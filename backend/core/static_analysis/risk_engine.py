"""
Static risk engine v2.

Design:
  extract_features(apk)  -> Features   (fast, no decompilation, cached by sha256)
  score_features(f)      -> report     (pure function, unit-testable)

Key properties:
  * Permissions are judged against (a) app category and (b) code evidence in DEX.
  * All sub-scores are CONTINUOUS (saturating curve 100*(1-exp(-x/K))), never bucketed.
  * 100 is reachable only with a confirmed malware signature (YARA severity >= 8).
  * A verified publisher (pinned signing cert) reduces permission/behavior sub-scores.
    A package-name match alone does NOT reduce the score.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import sys
import time
import zipfile
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:  # androguard is chatty
    from loguru import logger as _loguru
    _loguru.disable("androguard")
except Exception:
    pass

log = logging.getLogger("static.risk_engine")

ENGINE_VERSION = "2.0.0"
NS = "{http://schemas.android.com/apk/res/android}"
HERE = Path(__file__).resolve().parent
CACHE_DIR = Path(os.getenv("STATIC_CACHE_DIR", HERE / ".cache"))
TRUSTED_FILE = HERE / "data" / "trusted_publishers.json"
YARA_DIR = Path(os.getenv("YARA_RULES_DIR", HERE.parents[2] / "yara_rules"))
MAX_DEX_BYTES = 200 * 1024 * 1024

# --------------------------------------------------------------------------- #
# Knowledge base
# --------------------------------------------------------------------------- #
# permission -> (severity 0-10, evidence group)
PERMISSIONS: Dict[str, tuple] = {
    # normal / low
    "INTERNET": (0, None), "ACCESS_NETWORK_STATE": (0, None), "VIBRATE": (0, None),
    "ACCESS_WIFI_STATE": (1, None), "WAKE_LOCK": (1, None), "FOREGROUND_SERVICE": (1, None),
    "POST_NOTIFICATIONS": (1, None), "USE_BIOMETRIC": (1, None), "USE_FINGERPRINT": (1, None),
    "BLUETOOTH": (1, None), "SCHEDULE_EXACT_ALARM": (1, None), "NFC": (2, None),
    "BLUETOOTH_CONNECT": (2, None), "BLUETOOTH_SCAN": (2, None),
    "CHANGE_WIFI_STATE": (2, None), "CHANGE_NETWORK_STATE": (2, None),
    "RECEIVE_BOOT_COMPLETED": (2, "boot"),
    # sensitive / dangerous
    "READ_SMS": (8, "sms"), "RECEIVE_SMS": (8, "sms"), "SEND_SMS": (9, "sms"),
    "RECEIVE_MMS": (6, "sms"), "RECEIVE_WAP_PUSH": (5, "sms"),
    "READ_CALL_LOG": (8, "calllog"), "WRITE_CALL_LOG": (7, "calllog"),
    "PROCESS_OUTGOING_CALLS": (8, "calllog"), "CALL_PHONE": (5, "call"),
    "ANSWER_PHONE_CALLS": (6, "call"), "RECORD_AUDIO": (7, "audio"), "CAMERA": (5, "camera"),
    "ACCESS_FINE_LOCATION": (6, "location"), "ACCESS_COARSE_LOCATION": (4, "location"),
    "ACCESS_BACKGROUND_LOCATION": (8, "location"),
    "READ_CONTACTS": (6, "contacts"), "WRITE_CONTACTS": (6, "contacts"),
    "GET_ACCOUNTS": (4, "accounts"), "READ_PHONE_STATE": (4, "phone"),
    "READ_PHONE_NUMBERS": (5, "phone"), "READ_CALENDAR": (4, "calendar"),
    "WRITE_CALENDAR": (4, "calendar"), "READ_EXTERNAL_STORAGE": (3, "storage"),
    "WRITE_EXTERNAL_STORAGE": (3, "storage"), "READ_MEDIA_IMAGES": (3, "storage"),
    "READ_MEDIA_VIDEO": (3, "storage"), "READ_MEDIA_AUDIO": (3, "storage"),
    "MANAGE_EXTERNAL_STORAGE": (7, "storage"), "BODY_SENSORS": (5, "sensors"),
    "ACTIVITY_RECOGNITION": (3, "sensors"), "SYSTEM_ALERT_WINDOW": (8, "overlay"),
    "REQUEST_INSTALL_PACKAGES": (8, "install"), "INSTALL_PACKAGES": (9, "install"),
    "DELETE_PACKAGES": (7, None), "BIND_ACCESSIBILITY_SERVICE": (10, "accessibility"),
    "BIND_DEVICE_ADMIN": (10, "admin"), "BIND_NOTIFICATION_LISTENER_SERVICE": (8, "notiflistener"),
    "PACKAGE_USAGE_STATS": (6, "usage"), "QUERY_ALL_PACKAGES": (4, "pkgquery"),
    "GET_TASKS": (5, None), "READ_LOGS": (7, None), "DISABLE_KEYGUARD": (5, None),
    "KILL_BACKGROUND_PROCESSES": (4, None), "WRITE_SETTINGS": (4, None),
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": (4, None), "MOUNT_UNMOUNT_FILESYSTEMS": (6, None),
}
DEFAULT_UNKNOWN_SEVERITY = 1
DANGEROUS_MIN = 3

# evidence group -> byte needles found in DEX string pool when code really uses the capability
EVIDENCE: Dict[str, List[bytes]] = {
    "sms": [b"Landroid/telephony/SmsManager;", b"Landroid/telephony/SmsMessage;", b"content://sms",
            b"Landroid/provider/Telephony$Sms", b"SmsRetriever"],
    "location": [b"Landroid/location/LocationManager;", b"FusedLocationProviderClient",
                 b"Lcom/google/android/gms/location/", b"Lcom/google/android/gms/maps/",
                 b"Lcom/mapbox", b"Lcom/google/android/libraries/places"],
    "camera": [b"Landroid/hardware/camera2/", b"Landroidx/camera/", b"Landroid/hardware/Camera;",
               b"android.media.action.IMAGE_CAPTURE", b"Lcom/google/mlkit/vision/barcode",
               b"Lcom/journeyapps/barcodescanner", b"Lcom/google/zxing/"],
    "audio": [b"Landroid/media/AudioRecord;", b"Landroid/media/MediaRecorder;",
              b"Landroid/speech/SpeechRecognizer;"],
    "contacts": [b"ContactsContract", b"content://com.android.contacts"],
    "accounts": [b"Landroid/accounts/AccountManager;", b"Lcom/google/android/gms/auth/api/signin/"],
    "calllog": [b"Landroid/provider/CallLog"],
    "call": [b"android.intent.action.CALL"],
    "phone": [b"Landroid/telephony/TelephonyManager;"],
    "calendar": [b"CalendarContract"],
    "storage": [b"Landroid/os/Environment;", b"Landroid/provider/MediaStore", b"Landroidx/documentfile/"],
    "overlay": [b"TYPE_APPLICATION_OVERLAY", b"canDrawOverlays"],
    "install": [b"application/vnd.android.package-archive", b"Landroid/content/pm/PackageInstaller;"],
    "accessibility": [b"Landroid/accessibilityservice/AccessibilityService;"],
    "admin": [b"Landroid/app/admin/DevicePolicyManager;", b"Landroid/app/admin/DeviceAdminReceiver;"],
    "usage": [b"Landroid/app/usage/UsageStatsManager;"],
    "notiflistener": [b"Landroid/service/notification/NotificationListenerService;"],
    "sensors": [b"Landroid/hardware/SensorManager;", b"Lcom/google/android/gms/fitness/"],
    "boot": [b"android.intent.action.BOOT_COMPLETED"],
    "pkgquery": [b"getInstalledPackages", b"getInstalledApplications"],
}

# behavior -> (severity, needles(any), required_permission or None, description)
BEHAVIORS: Dict[str, tuple] = {
    "sms_send": (8, [b"sendTextMessage", b"sendMultipartTextMessage"], "SEND_SMS", "Sends SMS programmatically"),
    "sms_read": (6, [b"content://sms", b"Landroid/provider/Telephony$Sms"], "READ_SMS", "Reads SMS inbox"),
    "accessibility_service": (8, [b"Landroid/accessibilityservice/AccessibilityService;"], None, "Implements an AccessibilityService (classic banking-trojan vector)"),
    "device_admin": (8, [b"Landroid/app/admin/DeviceAdminReceiver;", b"lockNow", b"wipeData"], None, "Device-admin capabilities (lock/wipe)"),
    "overlay": (6, [b"TYPE_APPLICATION_OVERLAY", b"canDrawOverlays"], "SYSTEM_ALERT_WINDOW", "Draws over other apps"),
    "install_packages": (7, [b"application/vnd.android.package-archive", b"Landroid/content/pm/PackageInstaller;"], "REQUEST_INSTALL_PACKAGES", "Can install other APKs"),
    "dex_loader": (6, [b"Ldalvik/system/DexClassLoader;", b"Ldalvik/system/InMemoryDexClassLoader;"], None, "Loads code dynamically at runtime"),
    "telegram_exfil": (7, [b"api.telegram.org/bot"], None, "Telegram bot API endpoint (common exfil channel)"),
    "screen_capture": (4, [b"Landroid/media/projection/MediaProjection;"], None, "Screen capture API"),
    "notification_listener": (6, [b"Landroid/service/notification/NotificationListenerService;"], None, "Reads notifications (OTP interception vector)"),
    "usage_stats": (4, [b"Landroid/app/usage/UsageStatsManager;"], "PACKAGE_USAGE_STATS", "Reads app-usage data"),
    "su_binary": (2, [b"/system/xbin/su", b"/system/bin/su"], None, "Root-binary strings (also used by legit root detection)"),
    "insecure_tls": (4, [b"AllowAllHostnameVerifier", b"ALLOW_ALL_HOSTNAME_VERIFIER"], None, "Disables TLS hostname verification"),
    "weak_crypto": (2, [b"AES/ECB", b"DES/ECB", b"Ljavax/crypto/spec/DESKeySpec;"], None, "Weak crypto primitives"),
    "webview_js_bridge": (1.5, [b"addJavascriptInterface"], None, "WebView JavaScript bridge"),
}
DYNAMIC_BEHAVIORS = {"dex_loader"}
NETWORK_BEHAVIORS = {"insecure_tls", "telegram_exfil"}

SECRET_PATTERNS = {
    "aws_access_key": (re.compile(rb"AKIA[0-9A-Z]{16}"), 5.0),
    "private_key_block": (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 6.0),
    "slack_token": (re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}"), 4.0),
    "github_token": (re.compile(rb"ghp_[A-Za-z0-9]{36}"), 5.0),
    "stripe_live_key": (re.compile(rb"sk_live_[0-9a-zA-Z]{24,}"), 6.0),
}
IP_URL_RE = re.compile(rb"https?://(?:\d{1,3}\.){3}\d{1,3}")
IP_IGNORE = (b"127.0.0.1", b"10.0.2.2", b"0.0.0.0", b"192.168.", b"10.")

# ---- category profiles: what a legit app of this kind plausibly needs ------ #
def _p(s: str) -> Set[str]:
    return set(s.split())

PROFILES: Dict[str, Dict[str, Set[str]]] = {
    "delivery_shopping": {
        "expected": _p("ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION CAMERA POST_NOTIFICATIONS"),
        "conditional": _p("READ_SMS RECEIVE_SMS READ_PHONE_STATE READ_PHONE_NUMBERS READ_CONTACTS GET_ACCOUNTS CALL_PHONE READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE READ_MEDIA_IMAGES RECEIVE_BOOT_COMPLETED")},
    "finance": {
        "expected": _p("READ_PHONE_STATE CAMERA POST_NOTIFICATIONS READ_PHONE_NUMBERS"),
        "conditional": _p("READ_SMS RECEIVE_SMS SEND_SMS READ_CONTACTS ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION GET_ACCOUNTS READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE READ_MEDIA_IMAGES RECEIVE_BOOT_COMPLETED")},
    "messaging": {
        "expected": _p("READ_CONTACTS WRITE_CONTACTS CAMERA RECORD_AUDIO READ_PHONE_STATE POST_NOTIFICATIONS READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE READ_MEDIA_IMAGES READ_MEDIA_VIDEO READ_MEDIA_AUDIO"),
        "conditional": _p("READ_SMS RECEIVE_SMS SEND_SMS CALL_PHONE ANSWER_PHONE_CALLS READ_CALL_LOG ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION GET_ACCOUNTS RECEIVE_BOOT_COMPLETED")},
    "maps_transport": {
        "expected": _p("ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION POST_NOTIFICATIONS"),
        "conditional": _p("ACCESS_BACKGROUND_LOCATION CAMERA CALL_PHONE READ_PHONE_STATE READ_CONTACTS RECORD_AUDIO READ_SMS RECEIVE_SMS RECEIVE_BOOT_COMPLETED")},
    "social_media": {
        "expected": _p("CAMERA RECORD_AUDIO READ_CONTACTS ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION POST_NOTIFICATIONS READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE READ_MEDIA_IMAGES READ_MEDIA_VIDEO"),
        "conditional": _p("READ_PHONE_STATE GET_ACCOUNTS READ_CALENDAR RECEIVE_BOOT_COMPLETED")},
    "camera_media": {
        "expected": _p("CAMERA RECORD_AUDIO READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE READ_MEDIA_IMAGES READ_MEDIA_VIDEO READ_MEDIA_AUDIO POST_NOTIFICATIONS"),
        "conditional": _p("ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION READ_PHONE_STATE")},
    "game": {
        "expected": _p("POST_NOTIFICATIONS"),
        "conditional": _p("READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE READ_PHONE_STATE GET_ACCOUNTS RECEIVE_BOOT_COMPLETED")},
    "security_tool": {
        "expected": _p("POST_NOTIFICATIONS"),
        "conditional": _p("READ_PHONE_STATE QUERY_ALL_PACKAGES PACKAGE_USAGE_STATS SYSTEM_ALERT_WINDOW READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE RECEIVE_BOOT_COMPLETED")},
    "utility_simple": {"expected": _p("POST_NOTIFICATIONS CAMERA"), "conditional": set()},  # flashlight, calculator...
    "generic": {"expected": _p("POST_NOTIFICATIONS"), "conditional": set()},
}
KEYWORDS = [
    ("utility_simple", ("flashlight", "torch", "wallpaper", "cleaner", "booster", "ringtone", "calculator", "compass")),
    ("finance", ("bank", "wallet", "upi", "loan", "credit", "finance", "invest", "trading", "payment", "paytm", "phonepe")),
    ("delivery_shopping", ("grofer", "grocer", "blinkit", "zepto", "swiggy", "zomato", "shop", "mart", "cart", "delivery", "food", "market", "commerce", "instamart", "bigbasket")),
    ("messaging", ("messenger", "chat", "sms", "dialer", "whatsapp", "telegram")),
    ("maps_transport", ("maps", "navi", "taxi", "cab", "ride", "transit", "travel", "flight", "train", "uber", "ola")),
    ("social_media", ("social", "dating", "reels", "insta", "snap", "friends")),
    ("camera_media", ("camera", "photo", "gallery", "music", "player", "scanner", "video")),
    ("game", ("game", "puzzle", "racing", "ludo", "casino")),
    ("security_tool", ("vpn", "antivirus", "security", "applock")),
]

# (name, required perms, required behaviors, min suspect perms, bump 0-1, description)
COMBOS = [
    ("sms_stealer_read_send", {"READ_SMS", "SEND_SMS"}, set(), 1, 0.30, "Reads and sends SMS without being expected to"),
    ("sms_stealer_recv_send", {"RECEIVE_SMS", "SEND_SMS"}, set(), 1, 0.30, "Intercepts and sends SMS without being expected to"),
    ("overlay_plus_accessibility", {"SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"}, set(), 1, 0.40, "Overlay + Accessibility: banking-trojan pattern"),
    ("dropper", {"REQUEST_INSTALL_PACKAGES"}, {"dex_loader"}, 1, 0.30, "Installs packages and loads code dynamically"),
    ("device_admin_persistence", {"BIND_DEVICE_ADMIN", "RECEIVE_BOOT_COMPLETED"}, set(), 1, 0.30, "Device admin plus boot persistence"),
    ("stalkerware", {"RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "RECEIVE_BOOT_COMPLETED"}, set(), 3, 0.30, "Mic + camera + location + boot persistence"),
    ("data_harvester", {"READ_SMS", "READ_CALL_LOG", "READ_CONTACTS"}, set(), 2, 0.30, "SMS + call log + contacts harvesting"),
]

SCORE_WEIGHTS = {
    "permission_risk": 0.20, "overprivilege": 0.14, "sensitive_api": 0.17, "dynamic_code": 0.08,
    "component_exposure": 0.07, "network_security": 0.06, "hardcoded_secrets": 0.04,
    "obfuscation": 0.02, "signature_integrity": 0.10, "malware_signature": 0.12,
}
assert abs(sum(SCORE_WEIGHTS.values()) - 1.0) < 1e-9
TRUST_MULTIPLIER = 0.6  # applied to permission/behavior sub-scores for pinned-cert verified publishers


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Features:
    sha256: str = ""
    package: str = ""
    label: str = ""
    category: str = "generic"
    category_source: str = "default"
    size_bytes: int = 0
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    other_permissions: List[str] = field(default_factory=list)
    evidence_groups: Set[str] = field(default_factory=set)
    behaviors: Set[str] = field(default_factory=set)
    exposure_points: float = 0.0
    exposed_components: List[str] = field(default_factory=list)
    flags: Dict[str, bool] = field(default_factory=dict)
    signature: Dict[str, Any] = field(default_factory=dict)
    publisher_verified: bool = False
    publisher_mismatch: bool = False
    secrets: List[str] = field(default_factory=list)
    ip_urls: int = 0
    obfuscation_ratio: float = 0.0
    embedded_payloads: List[str] = field(default_factory=list)
    native_libs: int = 0
    yara_matches: List[Dict[str, Any]] = field(default_factory=list)
    timings: Dict[str, float] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _sat(x: float, k: float) -> float:
    """Saturating curve 0..100. Smooth, never jumps, approaches but never hits 100."""
    return 100.0 * (1.0 - math.exp(-max(x, 0.0) / k))


@lru_cache(maxsize=1)
def _trusted() -> Dict[str, Any]:
    try:
        return json.loads(TRUSTED_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def infer_category(package: str, label: str) -> tuple:
    t = _trusted().get(package)
    if t and t.get("category") in PROFILES:
        return t["category"], "trusted_publishers.json"
    tokens = [x for x in re.split(r"[^a-z0-9]+", f"{package} {label}".lower()) if x]
    for cat, stems in KEYWORDS:
        if any(tok.startswith(s) for tok in tokens for s in stems):
            return cat, "keyword"
    return "generic", "default"


def _load_apk(path: Path):
    try:
        from androguard.core.apk import APK  # androguard >= 4
    except ImportError:  # pragma: no cover
        from androguard.core.bytecodes.apk import APK
    return APK(str(path))


@lru_cache(maxsize=1)
def _compiled_rules(dir_str: str):
    try:
        import yara
    except ImportError:
        return None
    files = {}
    for p in Path(dir_str).glob("**/*"):
        if p.suffix.lower() in (".yar", ".yara"):
            try:
                yara.compile(filepath=str(p))  # drop broken rule files instead of failing the scan
                files[f"{p.parent.name}_{p.stem}"] = str(p)
            except Exception as exc:
                log.warning("Skipping broken YARA file %s: %s", p, exc)
    return yara.compile(filepaths=files) if files else None


def _run_yara(blob: bytes, warnings: List[str]) -> List[Dict[str, Any]]:
    try:
        rules = _compiled_rules(str(YARA_DIR))
        if rules is None:
            return []
        out = []
        for m in rules.match(data=blob, timeout=30):
            meta = dict(m.meta or {})
            try:
                sev = float(meta.get("severity", 6))
            except (TypeError, ValueError):
                sev = 6.0
            out.append({"rule": m.rule, "severity": sev, "family": meta.get("family"),
                        "description": meta.get("description", "")})
        return out
    except Exception as exc:
        warnings.append(f"yara failed: {exc}")
        return []


# --------------------------------------------------------------------------- #
# Feature extraction (fast: manifest + one pass over raw DEX bytes)
# --------------------------------------------------------------------------- #
def _manifest_features(apk, f: Features) -> Set[str]:
    """Return BIND_* permissions declared on components (accessibility, device admin...)."""
    bind_perms: Set[str] = set()
    xml = apk.get_android_manifest_xml()
    if xml is None:
        return bind_perms
    app = xml.find("application")
    if app is None:
        return bind_perms
    f.flags = {
        "debuggable": app.get(NS + "debuggable") == "true",
        "allow_backup": app.get(NS + "allowBackup") != "false",
        "cleartext_traffic": app.get(NS + "usesCleartextTraffic") == "true",
        "test_only": app.get(NS + "testOnly") == "true",
        "has_network_security_config": app.get(NS + "networkSecurityConfig") is not None,
    }
    pts = 0.0
    weights = {"service": 2.0, "receiver": 1.0, "provider": 3.0, "activity": 0.3, "activity-alias": 0.3}
    for tag, w in weights.items():
        for el in app.findall(tag):
            name = el.get(NS + "name") or "?"
            perm = el.get(NS + "permission") or ""
            if perm.startswith("android.permission.BIND_"):
                bind_perms.add(perm.rsplit(".", 1)[-1])
            filters = el.findall("intent-filter")
            exp = el.get(NS + "exported")
            exported = (exp == "true") if exp is not None else bool(filters)
            if not exported or perm:
                continue
            cats = {c.get(NS + "name") for fl in filters for c in fl.findall("category")}
            actions = {a.get(NS + "name") or "" for fl in filters for a in fl.findall("action")}
            if tag.startswith("activity") and cats & {"android.intent.category.LAUNCHER", "android.intent.category.BROWSABLE"}:
                continue
            if actions and all(a.startswith(("android.intent.action.", "com.google.firebase", "com.google.android.c2dm")) for a in actions):
                continue
            pts += w
            if len(f.exposed_components) < 25:
                f.exposed_components.append(f"{tag}:{name}")
    pts = min(pts, 12.0)
    if f.flags["debuggable"]:
        pts += 6
    if f.flags["test_only"]:
        pts += 3
    if f.flags["cleartext_traffic"]:
        pts += 2
    if f.flags["allow_backup"]:
        pts += 1.5
    if f.min_sdk and f.min_sdk < 23:
        pts += 1
    f.exposure_points = pts
    return bind_perms


def _signature_features(apk, f: Features) -> None:
    sig = {"v1": False, "v2": False, "v3": False, "debug": False, "unsigned": False, "sha256": []}
    for key, fn in (("v1", "is_signed_v1"), ("v2", "is_signed_v2"), ("v3", "is_signed_v3")):
        try:
            sig[key] = bool(getattr(apk, fn)())
        except Exception:
            pass
    try:
        certs = apk.get_certificates() or []
        for c in certs:
            fp = str(c.sha256_fingerprint).replace(" ", "").replace(":", "").lower()
            sig["sha256"].append(fp)
            subject = ""
            try:
                subject = c.subject.human_friendly
            except Exception:
                pass
            if "android debug" in subject.lower():
                sig["debug"] = True
        if not certs:
            sig["unsigned"] = True
    except Exception as exc:
        f.warnings.append(f"cert parse failed: {exc}")
        sig["unsigned"] = not (sig["v1"] or sig["v2"] or sig["v3"])
    f.signature = sig
    pinned = [x.lower() for x in (_trusted().get(f.package, {}).get("cert_sha256") or [])]
    if pinned:
        if set(sig["sha256"]) & set(pinned):
            f.publisher_verified = True
        else:
            f.publisher_mismatch = True  # same package name, different signer: impersonation/repackaging


def extract_features(apk_path: str) -> Features:
    path = Path(apk_path)
    t0 = time.perf_counter()
    f = Features(sha256=_sha256(path), size_bytes=path.stat().st_size)
    apk = _load_apk(path)
    f.package = apk.get_package() or ""
    try:
        f.min_sdk = int(apk.get_min_sdk_version() or 0)
        f.target_sdk = int(apk.get_target_sdk_version() or 0)
    except Exception:
        pass

    raw = list(apk.get_permissions() or [])
    perms = {p.rsplit(".", 1)[-1] for p in raw if p.startswith("android.permission.")}
    f.other_permissions = sorted(p for p in raw if not p.startswith("android.permission."))
    perms |= _manifest_features(apk, f)
    f.permissions = sorted(perms)

    _signature_features(apk, f)

    # label only if package-based classification is not decisive (resources.arsc parsing is slow)
    cat, src = infer_category(f.package, "")
    if cat == "generic":
        try:
            f.label = apk.get_app_name() or ""
        except Exception:
            f.label = ""
        cat, src = infer_category(f.package, f.label)
    else:
        f.label = _trusted().get(f.package, {}).get("label", "")
    f.category, f.category_source = cat, src
    f.timings["manifest_s"] = round(time.perf_counter() - t0, 3)

    t1 = time.perf_counter()
    dex_blobs: List[bytes] = []
    total = 0
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        for n in names:
            if re.fullmatch(r"classes\d*\.dex", n):
                data = zf.read(n)
                total += len(data)
                if total > MAX_DEX_BYTES:
                    f.warnings.append("DEX size cap reached; scan truncated")
                    break
                dex_blobs.append(data)
        f.native_libs = len({os.path.basename(n) for n in names if n.startswith("lib/") and n.endswith(".so")})
        checked = 0
        for n in names:
            if not n.startswith(("assets/", "res/raw/")) or n.endswith("/"):
                continue
            if n.lower().endswith((".dex", ".jar", ".apk")):
                f.embedded_payloads.append(n)
                continue
            checked += 1
            if checked > 500:
                break
            try:
                info = zf.getinfo(n)
                if 1024 <= info.file_size <= 30 * 1024 * 1024:
                    with zf.open(n) as fh:
                        head = fh.read(8)
                    if head.startswith(b"dex\n0") or head[:4] == b"PK\x03\x04":
                        f.embedded_payloads.append(n)
            except Exception:
                continue
    f.timings["unzip_s"] = round(time.perf_counter() - t1, 3)
    if not dex_blobs:
        f.warnings.append("no classes*.dex found (packed/corrupt APK?)")

    t2 = time.perf_counter()
    blob = b"\x00".join(dex_blobs)
    for group, needles in EVIDENCE.items():
        if any(n in blob for n in needles):
            f.evidence_groups.add(group)
    for key, (_sev, needles, _perm, _desc) in BEHAVIORS.items():
        if any(n in blob for n in needles):
            f.behaviors.add(key)
    for name, (rx, _w) in SECRET_PATTERNS.items():
        if rx.search(blob):
            f.secrets.append(name)
    f.ip_urls = sum(1 for m in set(IP_URL_RE.findall(blob)) if not any(ig in m for ig in IP_IGNORE))
    # obfuscation ratio on a bounded sample (R8 minification is NOT malicious; low weight)
    sample = b"".join(b[: 12 * 1024 * 1024] for b in dex_blobs[:3])
    total_cls = len(re.findall(rb"L[A-Za-z0-9_/$]{1,200};", sample))
    short_cls = len(re.findall(rb"L(?:[A-Za-z0-9]{1,2}/)+[A-Za-z0-9]{1,2};", sample))
    f.obfuscation_ratio = (short_cls / total_cls) if total_cls else 0.0
    f.timings["dex_scan_s"] = round(time.perf_counter() - t2, 3)

    t3 = time.perf_counter()
    f.yara_matches = _run_yara(blob, f.warnings) if blob else []
    f.timings["yara_s"] = round(time.perf_counter() - t3, 3)
    f.timings["total_s"] = round(time.perf_counter() - t0, 3)
    return f


# --------------------------------------------------------------------------- #
# Scoring (pure)
# --------------------------------------------------------------------------- #
def _verdict(expect: str, has_evidence: bool):
    """-> (verdict, factor, overprivilege_weight)"""
    if expect == "expected":
        return ("JUSTIFIED", 0.15, 0.0) if has_evidence else ("UNUSED_OVERREQUEST", 0.5, 0.4)
    if expect == "conditional":
        return ("PLAUSIBLE", 0.4, 0.0) if has_evidence else ("QUESTIONABLE", 0.7, 0.6)
    return ("USED_BUT_UNEXPECTED", 0.8, 0.5) if has_evidence else ("UNJUSTIFIED", 1.0, 1.0)


def _level(score: float) -> str:
    if score < 20:
        return "CLEAN"
    if score < 40:
        return "LOW"
    if score < 60:
        return "MEDIUM"
    if score < 80:
        return "HIGH"
    return "CRITICAL"


def score_features(f: Features) -> Dict[str, Any]:
    profile = PROFILES.get(f.category, PROFILES["generic"])
    findings: List[Dict[str, Any]] = []
    perm_pts = 0.0
    dang_sum = 0.0
    unjust_sum = 0.0
    dang_count = 0
    suspect: Set[str] = set()

    for p in f.permissions:
        sev, group = PERMISSIONS.get(p, (DEFAULT_UNKNOWN_SEVERITY, None))
        if sev < DANGEROUS_MIN:
            perm_pts += sev
            if sev >= 1:
                findings.append({"permission": p, "severity": sev, "verdict": "NORMAL", "points": float(sev),
                                 "reason": "Low-risk permission"})
            continue
        expect = "expected" if p in profile["expected"] else "conditional" if p in profile["conditional"] else "none"
        has_ev = bool(group and group in f.evidence_groups)
        verdict, factor, op_w = _verdict(expect, has_ev)
        pts = sev * factor
        perm_pts += pts
        dang_sum += sev
        dang_count += 1
        unjust_sum += sev * op_w
        if verdict in ("UNJUSTIFIED", "USED_BUT_UNEXPECTED", "QUESTIONABLE"):
            suspect.add(p)
        reason = {
            "JUSTIFIED": f"Expected for a '{f.category}' app and code uses the matching API",
            "UNUSED_OVERREQUEST": f"Expected for '{f.category}' but no code uses it (over-request)",
            "PLAUSIBLE": f"Sometimes needed by '{f.category}' apps and code uses the matching API",
            "QUESTIONABLE": f"Sometimes needed by '{f.category}' apps but no code evidence found",
            "USED_BUT_UNEXPECTED": f"Code uses it, but a '{f.category}' app normally does not need it",
            "UNJUSTIFIED": f"Not needed by a '{f.category}' app and no code uses it: flagged as risk",
        }[verdict]
        findings.append({"permission": p, "severity": sev, "expected_for_category": expect,
                         "code_evidence": has_ev, "verdict": verdict, "points": round(pts, 2), "reason": reason})

    perm_sub = _sat(perm_pts, 40.0)
    ratio = (unjust_sum / dang_sum) if dang_sum else 0.0
    overpriv_sub = 100.0 * ratio * min(1.0, dang_count / 4.0)

    behavior_findings, api_pts, dyn_pts, net_pts = [], 0.0, 0.0, 0.0
    declared = set(f.permissions)
    for key in sorted(f.behaviors):
        sev, _n, req, desc = BEHAVIORS[key]
        mult = 1.0 if (req is None or req in declared) else 0.5
        pts = sev * mult
        if key in DYNAMIC_BEHAVIORS:
            dyn_pts += pts
        elif key in NETWORK_BEHAVIORS:
            net_pts += pts
        if key not in DYNAMIC_BEHAVIORS:
            api_pts += pts
        behavior_findings.append({"behavior": key, "severity": sev, "points": round(pts, 2), "description": desc,
                                  "note": None if mult == 1.0 else f"{req} not declared, so weight halved"})
    dyn_pts += 4.0 * min(len(f.embedded_payloads), 3)
    api_sub = _sat(api_pts, 30.0)
    dyn_sub = _sat(dyn_pts, 12.0)

    net_pts += min(f.ip_urls, 5) * 0.8
    net_sub = _sat(net_pts, 8.0)
    secrets_pts = sum(SECRET_PATTERNS[s][1] for s in f.secrets if s in SECRET_PATTERNS)
    secrets_sub = _sat(secrets_pts, 8.0)
    exposure_sub = _sat(f.exposure_points, 12.0)
    obf_sub = 100.0 * max(0.0, min(1.0, (f.obfuscation_ratio - 0.15) / 0.6))

    sig = f.signature or {}
    if f.publisher_mismatch:
        sig_sub = 100.0
    elif f.publisher_verified:
        sig_sub = 0.0
    elif sig.get("unsigned"):
        sig_sub = 100.0
    elif sig.get("debug"):
        sig_sub = 60.0
    elif not (sig.get("v2") or sig.get("v3")):
        sig_sub = 25.0  # v1-only signing: janus-era weakness
    else:
        sig_sub = 0.0

    confirmed = any(m["severity"] >= 8 or m.get("family") for m in f.yara_matches)
    if f.yara_matches:
        max_sev = max(m["severity"] for m in f.yara_matches)
        mal_sub = min(100.0, max_sev * 10.0 + 5.0 * (len(f.yara_matches) - 1))
    else:
        mal_sub = 0.0

    if f.publisher_verified:
        perm_sub *= TRUST_MULTIPLIER
        overpriv_sub *= TRUST_MULTIPLIER
        api_sub *= TRUST_MULTIPLIER
        dyn_sub *= TRUST_MULTIPLIER

    scores = {
        "permission_risk": perm_sub, "overprivilege": overpriv_sub, "sensitive_api": api_sub,
        "dynamic_code": dyn_sub, "component_exposure": exposure_sub, "network_security": net_sub,
        "hardcoded_secrets": secrets_sub, "obfuscation": obf_sub, "signature_integrity": sig_sub,
        "malware_signature": mal_sub,
    }
    base = sum(SCORE_WEIGHTS[k] * v for k, v in scores.items()) / 100.0

    combo_hits, keep = [], 1.0
    for name, perms, behs, min_susp, bump, desc in COMBOS:
        if perms <= declared and behs <= f.behaviors and len(perms & suspect) >= min(min_susp, len(perms)):
            if f.publisher_verified:
                bump *= TRUST_MULTIPLIER
            combo_hits.append({"combo": name, "bump": bump, "description": desc})
            keep *= (1.0 - bump)
    mal_factor = 1.0 - 0.9 * (mal_sub / 100.0)
    overall = 100.0 * (1.0 - (1.0 - base) * keep * mal_factor)
    if f.publisher_mismatch:
        overall = max(overall, 75.0)  # impersonation of a pinned publisher
    overall = min(overall, 100.0 if confirmed else 97.0)

    ranked = sorted(((k, SCORE_WEIGHTS[k] * v) for k, v in scores.items()), key=lambda kv: -kv[1])
    top_reasons = [f"{k}: contributes {c:.1f} pts" for k, c in ranked[:4] if c > 0.5]
    flagged = [x for x in findings if x.get("verdict") in ("UNJUSTIFIED", "USED_BUT_UNEXPECTED", "QUESTIONABLE", "UNUSED_OVERREQUEST")]

    confidence = "high" if (f.publisher_verified or confirmed) else "low" if f.warnings and not f.evidence_groups else "medium"
    return {
        "engine_version": ENGINE_VERSION,
        "sha256": f.sha256, "package": f.package, "label": f.label,
        "category": f.category, "category_source": f.category_source,
        "overall": round(overall, 1), "level": _level(overall), "confidence": confidence,
        "publisher_verified": f.publisher_verified, "publisher_mismatch": f.publisher_mismatch,
        "scores": {k: round(v, 1) for k, v in scores.items()},
        "score_weights": SCORE_WEIGHTS,
        "permission_findings": sorted(findings, key=lambda x: -x["points"]),
        "flagged_permissions": [x["permission"] for x in flagged],
        "behavior_findings": behavior_findings,
        "toxic_combinations": combo_hits,
        "exposed_components": f.exposed_components,
        "manifest_flags": f.flags,
        "signature": f.signature,
        "embedded_payloads": f.embedded_payloads,
        "yara_matches": f.yara_matches,
        "secrets_found": f.secrets,
        "top_reasons": top_reasons,
        "warnings": f.warnings,
        "timings": f.timings,
        # legacy aliases so existing pipeline/UI keep working
        "risk_score": round(overall, 1), "threat_level": _level(overall), "score": round(overall, 1), "factors": top_reasons,
    }


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def analyze_static(apk_path: str, use_cache: bool = True) -> Dict[str, Any]:
    """Blocking. In async code call:  await asyncio.to_thread(analyze_static, path)"""
    path = Path(apk_path)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / f"{_sha256(path)}.{ENGINE_VERSION}.json"
    if use_cache and cache_file.exists():
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            data["cached"] = True
            return data
        except Exception:
            pass
    report = score_features(extract_features(str(path)))
    report["cached"] = False
    try:
        cache_file.write_text(json.dumps(report), encoding="utf-8")
    except Exception as exc:
        log.warning("cache write failed: %s", exc)
    return report


if __name__ == "__main__":  # python -m backend.core.static_analysis.risk_engine app.apk
    print(json.dumps(analyze_static(sys.argv[1], use_cache=False), indent=2))