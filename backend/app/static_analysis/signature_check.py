"""Module for performing signature-based checks using local YARA rules and VirusTotal API."""

import hashlib
import logging
import os
import re
import requests
from typing import Any, Dict, List

try:
    import yara
except ImportError:
    yara = None

try:
    import plyara
except ImportError:
    plyara = None

logger = logging.getLogger("signature_check")


def _fallback_yara_scan(apk_path: str, rules_dir: str) -> List[Dict[str, Any]]:
    """
    Fallback YARA scanner when yara-python C extension is unavailable.
    Parses .yar rule files and matches strings against APK file bytes.
    """
    matches = []
    if not os.path.exists(apk_path):
        return matches

    try:
        with open(apk_path, "rb") as f:
            apk_bytes = f.read()
    except Exception as exc:
        logger.error(f"Failed to read APK bytes for fallback YARA scan: {exc}")
        return matches

    rule_files = []
    if os.path.isdir(rules_dir):
        for root, _, files in os.walk(rules_dir):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    rule_files.append(os.path.join(root, file))

    for r_file in rule_files:
        try:
            with open(r_file, "r", encoding="utf-8", errors="ignore") as rf:
                content = rf.read()

            rule_name_match = re.search(r"rule\s+([A-Za-z0-9_]+)", content)
            rule_name = rule_name_match.group(1) if rule_name_match else os.path.basename(r_file)

            meta = {}
            meta_block = re.search(r"meta:\s*([\s\S]*?)(?:strings:|condition:|\})", content)
            if meta_block:
                for line in meta_block.group(1).splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        meta[k.strip()] = v.strip().strip('"')

            strings_found = []
            string_block = re.search(r"strings:\s*([\s\S]*?)(?:condition:|\})", content)
            if string_block:
                for line in string_block.group(1).splitlines():
                    str_match = re.search(r"(\$[A-Za-z0-9_]+)\s*=\s*\"([^\"]+)\"", line)
                    if str_match:
                        s_name = str_match.group(1)
                        s_val = str_match.group(2)
                        # Check string match in raw bytes (utf-8 or utf-16le)
                        if s_val.encode("utf-8") in apk_bytes or s_val.encode("utf-16le") in apk_bytes:
                            strings_found.append({"identifier": s_name, "string": s_val})

            if strings_found:
                matches.append({
                    "rule": rule_name,
                    "tags": [],
                    "meta": meta,
                    "strings": strings_found
                })
        except Exception as err:
            logger.warning(f"Error parsing YARA rule file '{r_file}': {err}")

    return matches


def run_yara_scan(apk_path: str, rules_dir: str = "yara_rules") -> List[Dict[str, Any]]:
    """
    Compiles all .yar rules in rules_dir, scans the target APK file, and returns matched rules.

    :param apk_path: Path to the APK file on disk.
    :param rules_dir: Directory path containing .yar rule files.
    :return: List of matched rule dictionaries.
    """
    if not os.path.isabs(rules_dir):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        rules_dir = os.path.join(base_dir, rules_dir)

    if not os.path.exists(rules_dir):
        logger.warning(f"YARA rules directory '{rules_dir}' does not exist.")
        return []

    filepaths = {}
    for root, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(".yar") or file.endswith(".yara"):
                rule_name = os.path.splitext(file)[0]
                filepaths[rule_name] = os.path.join(root, file)

    if not filepaths:
        logger.warning(f"No .yar rule files found in '{rules_dir}'.")
        return []

    if yara is not None:
        try:
            compiled_rules = yara.compile(filepaths=filepaths)
            yara_matches = compiled_rules.match(apk_path)

            results = []
            for match in yara_matches:
                matched_strings = []
                for s in getattr(match, "strings", []):
                    if isinstance(s, tuple) and len(s) >= 3:
                        matched_strings.append({
                            "offset": s[0],
                            "identifier": s[1],
                            "string": s[2].decode("utf-8", errors="ignore") if isinstance(s[2], bytes) else str(s[2])
                        })
                    else:
                        matched_strings.append({"identifier": str(s)})

                results.append({
                    "rule": match.rule,
                    "tags": list(match.tags) if hasattr(match, "tags") else [],
                    "meta": dict(match.meta) if hasattr(match, "meta") else {},
                    "strings": matched_strings,
                })
            return results
        except Exception as exc:
            logger.error(f"Error executing yara-python scan: {exc}")
            return _fallback_yara_scan(apk_path, rules_dir)
    else:
        logger.info("yara-python not available, executing fallback YARA scanner.")
        return _fallback_yara_scan(apk_path, rules_dir)


def check_virustotal(apk_path: str) -> Dict[str, Any]:
    """
    Computes SHA256 hash of the APK file and queries VirusTotal v3 API if VT_API_KEY is present.

    :param apk_path: Path to the APK file.
    :return: Dict containing VirusTotal report details or skipped status.
    """
    if not os.path.exists(apk_path):
        return {"status": "error", "reason": f"File not found at path: {apk_path}"}

    sha256_hash = hashlib.sha256()
    try:
        with open(apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256_hash.update(chunk)
    except Exception as exc:
        return {"status": "error", "reason": f"Failed to compute file hash: {str(exc)}"}

    file_hash = sha256_hash.hexdigest()

    vt_api_key = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_api_key:
        return {
            "status": "skipped",
            "hash": file_hash,
            "reason": "VirusTotal API key (VT_API_KEY) is not configured in environment.",
        }

    vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": vt_api_key}

    try:
        response = requests.get(vt_url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            positives = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0

            return {
                "status": "completed",
                "hash": file_hash,
                "positives": positives,
                "total": total,
                "stats": stats,
                "scan_date": attributes.get("last_analysis_date"),
            }
        elif response.status_code == 404:
            return {
                "status": "not_found",
                "hash": file_hash,
                "reason": "File hash not found in VirusTotal database.",
            }
        else:
            return {
                "status": "skipped",
                "hash": file_hash,
                "reason": f"VirusTotal API returned HTTP {response.status_code}",
            }
    except Exception as req_err:
        logger.warning(f"VirusTotal API query failed: {req_err}")
        return {
            "status": "skipped",
            "hash": file_hash,
            "reason": f"VirusTotal query failed: {str(req_err)}",
        }
