"""Aggregator module unifying manifest analysis, code analysis, and signature checking into Static Results."""

import logging
from typing import Any, Dict, List

from backend.app.static_analysis.apk_loader import extract_apk
from backend.app.static_analysis.manifest_check import analyze_manifest
from backend.app.static_analysis.code_analysis import analyze_code
from backend.app.static_analysis.signature_check import run_yara_scan, check_virustotal

logger = logging.getLogger("aggregator")


def _compute_static_risk_indicators(
    manifest_data: Dict[str, Any],
    code_data: Dict[str, Any],
    yara_matches: List[Dict[str, Any]],
    vt_data: Dict[str, Any],
) -> List[str]:
    """
    Computes rule-based plain-English static risk indicator flags.

    :param manifest_data: Parsed manifest dictionary.
    :param code_data: Extracted code analysis dictionary.
    :param yara_matches: List of YARA rule matches.
    :param vt_data: VirusTotal check results.
    :return: List of risk indicator strings.
    """
    indicators: List[str] = []

    # 1. Manifest permission rules
    permissions = manifest_data.get("permissions", {})
    requested = set(permissions.get("requested", []))
    dangerous = set(permissions.get("dangerous", []))

    if any("SMS" in p for p in dangerous):
        indicators.append("Requests sensitive SMS permissions")

    if ("android.permission.SEND_SMS" in requested or "android.permission.RECEIVE_SMS" in requested) and (
        "android.intent.action.BOOT_COMPLETED" in requested
        or "android.permission.RECEIVE_BOOT_COMPLETED" in requested
        or "android.app.action.DEVICE_ADMIN_ENABLED" in requested
    ):
        indicators.append("Requests risky permission combination (SMS + Boot/Device Admin)")

    if "android.permission.SYSTEM_ALERT_WINDOW" in requested or "android.permission.BIND_ACCESSIBILITY_SERVICE" in requested:
        indicators.append("Requests sensitive System Overlay / Accessibility Service permission")

    # 2. Code analysis rules
    ip_addresses = code_data.get("ip_addresses", [])
    if ip_addresses:
        indicators.append(f"Contains hardcoded IPv4 address(es) ({len(ip_addresses)} found)")

    urls = code_data.get("urls", [])
    if urls:
        indicators.append(f"Contains embedded HTTP/HTTPS URL(s) ({len(urls)} found)")

    suspicious_apis = code_data.get("suspicious_apis", [])
    api_names = {item.get("api", "") for item in suspicious_apis}

    if "Runtime.exec" in api_names or "ProcessBuilder" in api_names:
        indicators.append("Uses command execution API (Runtime.exec / ProcessBuilder)")

    if "DexClassLoader" in api_names or "PathClassLoader" in api_names:
        indicators.append("Uses dynamic DEX code loading API (DexClassLoader)")

    if "Class.forName" in api_names or "getMethod" in api_names or "getDeclaredMethod" in api_names:
        indicators.append("Uses Java reflection API for dynamic invocation")

    if "Cipher.getInstance" in api_names:
        indicators.append("Uses Java Cryptography API (Cipher.getInstance)")

    # 3. YARA signature rules
    for match in yara_matches:
        rule_name = match.get("rule", "Unknown")
        indicators.append(f"Matched YARA rule: {rule_name}")

    # 4. VirusTotal rules
    if vt_data.get("status") == "completed":
        positives = vt_data.get("positives", 0)
        total = vt_data.get("total", 0)
        if positives > 0:
            indicators.append(f"VirusTotal flagged as malicious ({positives}/{total} security vendors)")

    # Deduplicate indicators preserving order
    return list(dict.fromkeys(indicators))


def run_static_analysis(apk_path: str) -> Dict[str, Any]:
    """
    Executes unified static analysis pipeline (manifest, bytecode scan, YARA signatures, VT lookup).

    :param apk_path: Path to the target APK file on disk.
    :return: Combined static results dictionary.
    """
    logger.info(f"Executing unified static analysis pipeline for: {apk_path}")

    # 1. Parse manifest once
    apk_obj = extract_apk(apk_path)
    manifest_data = analyze_manifest(apk_obj)
    package_name = manifest_data.get("package_name")

    # 2. Perform bytecode code scan
    code_data = analyze_code(apk_path)

    # 3. Perform signature checks
    yara_matches = run_yara_scan(apk_path)
    vt_data = check_virustotal(apk_path)

    # 4. Compute static risk indicators
    risk_indicators = _compute_static_risk_indicators(
        manifest_data=manifest_data,
        code_data=code_data,
        yara_matches=yara_matches,
        vt_data=vt_data,
    )

    return {
        "package_name": package_name,
        "manifest": manifest_data,
        "code_analysis": code_data,
        "signature_check": {
            "yara_matches": yara_matches,
            "virustotal": vt_data,
        },
        "static_risk_indicators": risk_indicators,
    }
