"""
APK Static Analyzer Module (Androguard 4.x)
Extracts manifest metadata, permissions, exported components,
and network indicators with transparent, heuristic risk profiling.
"""

import os
import re
import json
import sys
from typing import Dict, Any, List, Set
from androguard.core.apk import APK


SENSITIVE_PERMISSIONS_DB = {
    "android.permission.SEND_SMS": {
        "severity": "HIGH",
        "category": "SMS / Toll Fraud",
        "description": "Allows sending SMS without user confirmation, potentially incurring charges."
    },
    "android.permission.READ_SMS": {
        "severity": "HIGH",
        "category": "Privacy / 2FA Interception",
        "description": "Allows reading SMS messages, commonly abused to intercept 2FA tokens."
    },
    "android.permission.RECEIVE_SMS": {
        "severity": "HIGH",
        "category": "Privacy / 2FA Interception",
        "description": "Allows monitoring incoming SMS messages."
    },
    "android.permission.READ_CONTACTS": {
        "severity": "MEDIUM",
        "category": "Data Exfiltration",
        "description": "Allows harvesting address book entries."
    },
    "android.permission.READ_PHONE_STATE": {
        "severity": "MEDIUM",
        "category": "Device Fingerprinting",
        "description": "Allows reading IMEI, phone numbers, and cellular network status."
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "severity": "MEDIUM",
        "category": "Tracking",
        "description": "Allows accessing precise GPS location data."
    },
    "android.permission.RECORD_AUDIO": {
        "severity": "HIGH",
        "category": "Surveillance",
        "description": "Allows recording microphone audio."
    },
    "android.permission.CAMERA": {
        "severity": "MEDIUM",
        "category": "Surveillance",
        "description": "Allows taking photos and videos."
    },
    "android.permission.INTERNET": {
        "severity": "INFO",
        "category": "Network",
        "description": "Enables open network communication."
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "severity": "MEDIUM",
        "category": "Persistence",
        "description": "Allows automatically launching background services when device boots."
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "severity": "HIGH",
        "category": "Overlay / Phishing",
        "description": "Allows displaying floating overlay windows, commonly abused for credential phishing."
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "severity": "HIGH",
        "category": "Dropper / Downloader",
        "description": "Allows requesting installation of other APKs (dropper behavior)."
    }
}


class APKAnalyzer:
    def __init__(self, apk_path: str):
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")
        self.apk_path = os.path.abspath(apk_path)
        self.apk = APK(self.apk_path)

    def extract_metadata(self) -> Dict[str, Any]:
        """Extracts core manifest application information."""
        return {
            "file_name": os.path.basename(self.apk_path),
            "file_size_bytes": os.path.getsize(self.apk_path),
            "package_name": self.apk.get_package(),
            "app_name": self.apk.get_app_name() or self.apk.get_package(),
            "version_name": self.apk.get_androidversion_name() or "UNKNOWN",
            "version_code": self.apk.get_androidversion_code() or "UNKNOWN",
            "min_sdk": self.apk.get_min_sdk_version() or "UNKNOWN",
            "target_sdk": self.apk.get_target_sdk_version() or "UNKNOWN",
            "main_activity": self.apk.get_main_activity() or "UNKNOWN"
        }

    def extract_permissions(self) -> Dict[str, Any]:
        """Extracts and evaluates requested permissions against the risk database."""
        raw_perms = self.apk.get_permissions() or []
        declared_perms = self.apk.get_declared_permissions() or []

        sensitive_flags = []
        standard_perms = []
        risk_points = 0

        for perm in raw_perms:
            clean_perm = perm.strip()
            if clean_perm in SENSITIVE_PERMISSIONS_DB:
                rule = SENSITIVE_PERMISSIONS_DB[clean_perm]
                sev = rule["severity"]
                points = 15 if sev == "HIGH" else (8 if sev == "MEDIUM" else 2)
                risk_points += points
                sensitive_flags.append({
                    "permission": clean_perm,
                    "severity": sev,
                    "category": rule["category"],
                    "description": rule["description"]
                })
            else:
                standard_perms.append(clean_perm)

        return {
            "total_requested": len(raw_perms),
            "sensitive_count": len(sensitive_flags),
            "sensitive_permissions": sensitive_flags,
            "standard_permissions": standard_perms,
            "declared_permissions": declared_perms,
            "permission_risk_score": min(100, risk_points)
        }

    def extract_components(self) -> Dict[str, Any]:
        """Extracts Activities, Services, Receivers, and Exported components."""
        activities = self.apk.get_activities() or []
        services = self.apk.get_services() or []
        receivers = self.apk.get_receivers() or []
        providers = self.apk.get_providers() or []

        # Find exported components by inspecting manifest XML elements
        exported = []
        try:
            manifest_xml = self.apk.get_android_manifest_xml()
            if manifest_xml is not None:
                for elem in manifest_xml.iter():
                    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                    if tag in ["activity", "service", "receiver", "provider"]:
                        is_exported = False
                        name = None
                        for k, v in elem.attrib.items():
                            if k.endswith("name"):
                                name = v
                            if k.endswith("exported"):
                                is_exported = (v.lower() == "true")
                        # Components with intent-filters are exported by default on older SDKs unless explicit
                        has_intent_filter = any(child.tag.endswith("intent-filter") for child in elem)
                        if is_exported or (has_intent_filter and "exported" not in [k.split("}")[-1] for k in elem.attrib]):
                            if name:
                                exported.append({"type": tag, "name": name})
        except Exception:
            pass

        return {
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "exported_components": exported,
            "exported_count": len(exported)
        }

    def extract_network_indicators(self) -> Dict[str, Any]:
        """Extracts hardcoded URLs, IPs, and network-related strings from DEX/resources."""
        extracted_urls = set()
        extracted_ips = set()

        url_pattern = re.compile(r'https?://[a-zA-Z0-9\.\-_]+(?::\d+)?(?:/[^\s"\']*)?')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

        # Scan DEX files if available
        try:
            for dex in self.apk.get_all_dex():
                strings = re.findall(r'[\x20-\x7E]{6,}', dex.decode('latin1', errors='ignore'))
                for s in strings:
                    urls = url_pattern.findall(s)
                    for u in urls:
                        if not any(u.endswith(ext) for ext in [".dtd", ".xsd"]):
                            extracted_urls.add(u)
                    ips = ip_pattern.findall(s)
                    for ip in ips:
                        parts = [int(p) for p in ip.split(".")]
                        if all(0 <= p <= 255 for p in parts) and not ip.startswith("0.") and not ip.startswith("127."):
                            extracted_ips.add(ip)
        except Exception:
            pass

        return {
            "embedded_urls": sorted(list(extracted_urls))[:50],
            "embedded_ips": sorted(list(extracted_ips))[:50],
            "embedded_url_count": len(extracted_urls),
            "embedded_ip_count": len(extracted_ips)
        }

    def generate_report(self) -> Dict[str, Any]:
        """Compiles the complete static analysis report with transparent scoring."""
        metadata = self.extract_metadata()
        permissions = self.extract_permissions()
        components = self.extract_components()
        network_indicators = self.extract_network_indicators()

        # Transparent heuristic scoring
        # Note: A permission or exported component alone does not prove malware.
        perm_score = permissions["permission_risk_score"]
        exported_score = min(30, components["exported_count"] * 5)
        network_score = 15 if network_indicators["embedded_ip_count"] > 0 else (5 if network_indicators["embedded_url_count"] > 0 else 0)

        total_score = min(100, int(perm_score * 0.6 + exported_score * 0.2 + network_score * 0.2))
        
        risk_level = "LOW"
        if total_score > 60:
            risk_level = "HIGH"
        elif total_score > 30:
            risk_level = "MEDIUM"

        report = {
            "analysis_type": "STATIC_ANDROGUARD",
            "metadata": metadata,
            "permissions": permissions,
            "components": components,
            "network_indicators": network_indicators,
            "risk_assessment": {
                "heuristic_score": total_score,
                "risk_level": risk_level,
                "note": "Heuristic indicator score based on static indicators. Permissions alone do not confirm malicious intent."
            }
        }
        return report

    def save_json(self, output_file: str) -> str:
        """Saves analysis report to a JSON file."""
        report = self.generate_report()
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        return output_file


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python apk_analyzer.py <path_to_apk> [output_json]")
        sys.exit(1)

    apk_input = sys.argv[1]
    out_json = sys.argv[2] if len(sys.argv) > 2 else f"reports/static_{os.path.basename(apk_input)}.json"

    analyzer = APKAnalyzer(apk_input)
    saved = analyzer.save_json(out_json)
    print(f"Static analysis report saved to: {saved}")
