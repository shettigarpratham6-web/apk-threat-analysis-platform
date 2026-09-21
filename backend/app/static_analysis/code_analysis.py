"""Module for performing static code analysis on decompiled APK DEX bytecode."""

import logging
import time
from typing import Any, Dict, List, Set

try:
    from androguard.misc import AnalyzeAPK
except ImportError:
    AnalyzeAPK = None

from backend.app.static_analysis.patterns import (
    IPV4_PATTERN,
    SUSPICIOUS_API_LIST,
    URL_PATTERN,
)

logger = logging.getLogger("code_analysis")


def analyze_code(apk_path: str) -> Dict[str, Any]:
    """
    Analyzes an APK file using Androguard to extract URLs, IPv4 addresses,
    and suspicious API invocations from DEX bytecode and call graphs.

    :param apk_path: Path to the target APK file on disk.
    :return: Dictionary containing 'urls', 'ip_addresses', and 'suspicious_apis'.
    """
    start_time = time.time()
    print(f"[PERFORMANCE LOG] Starting code analysis for: {apk_path}")
    logger.info(f"Starting code analysis for APK: {apk_path}")

    urls: Set[str] = set()
    ip_addresses: Set[str] = set()
    suspicious_apis: List[Dict[str, str]] = []
    seen_api_keys: Set[str] = set()

    try:
        if AnalyzeAPK is None:
            raise ImportError("Androguard AnalyzeAPK module is not available.")

        a, d, dx = AnalyzeAPK(apk_path)

        # 1. Extract string constants from DEX bytecode
        dex_list = d if isinstance(d, list) else ([d] if d else [])
        all_strings: Set[str] = set()

        for dex in dex_list:
            if not hasattr(dex, "get_strings"):
                continue

            raw_strings = dex.get_strings()
            for s in raw_strings:
                if not s:
                    continue
                s_str = s if isinstance(s, str) else str(s, errors="ignore")
                all_strings.add(s_str)

                # Match URLs
                found_urls = URL_PATTERN.findall(s_str)
                for url in found_urls:
                    cleaned_url = url.rstrip(".,);'\">]")
                    if len(cleaned_url) > 8:
                        urls.add(cleaned_url)

                # Match IPv4 addresses
                found_ips = IPV4_PATTERN.findall(s_str)
                for ip in found_ips:
                    octets = ip.split(".")
                    if len(octets) == 4 and all(0 <= int(o) <= 255 for o in octets):
                        # Filter out localhost and broadcast
                        if not (ip == "127.0.0.1" or ip == "0.0.0.0" or ip == "255.255.255.255"):
                            ip_addresses.add(ip)

        # 2. Extract suspicious API calls from Analysis (dx)
        if dx is not None:
            try:
                methods = dx.get_methods()
                for meth in methods:
                    c_name = getattr(meth, "class_name", "") or ""
                    m_name = getattr(meth, "name", "") or ""
                    full_sig = f"{c_name}->{m_name}"

                    matched_api = None
                    for api_target in SUSPICIOUS_API_LIST:
                        if api_target in full_sig or api_target in c_name or api_target in m_name:
                            matched_api = api_target
                            break

                    if matched_api:
                        xrefs = getattr(meth, "get_xref_from", lambda: [])()
                        if xrefs:
                            for xref in xrefs:
                                caller_class = getattr(xref[0], "name", getattr(xref[0], "class_name", str(xref[0])))
                                caller_method = getattr(xref[1], "name", str(xref[1]))

                                key = f"{matched_api}|{caller_class}|{caller_method}"
                                if key not in seen_api_keys:
                                    seen_api_keys.add(key)
                                    suspicious_apis.append({
                                        "api": matched_api,
                                        "class": str(caller_class),
                                        "method": str(caller_method),
                                    })
                        else:
                            key = f"{matched_api}|{c_name}|{m_name}"
                            if key not in seen_api_keys:
                                seen_api_keys.add(key)
                                suspicious_apis.append({
                                    "api": matched_api,
                                    "class": str(c_name),
                                    "method": str(m_name),
                                })
            except Exception as dx_err:
                logger.warning(f"Error during dx methods inspection: {dx_err}")

        # 3. String-fallback match for suspicious APIs in string constants
        for s_str in all_strings:
            for api_target in SUSPICIOUS_API_LIST:
                if api_target in s_str:
                    # Deriving class/method info from pattern or string
                    parts = api_target.rsplit(".", 1)
                    cls_name = parts[0] if len(parts) > 1 else "Unknown"
                    meth_name = parts[1] if len(parts) > 1 else parts[0]

                    key = f"{api_target}|{cls_name}|{meth_name}"
                    if key not in seen_api_keys:
                        seen_api_keys.add(key)
                        suspicious_apis.append({
                            "api": api_target,
                            "class": cls_name,
                            "method": meth_name,
                        })

    except Exception as exc:
        logger.error(f"Error during code analysis for '{apk_path}': {exc}", exc_info=True)

    elapsed_time = time.time() - start_time
    print(f"[PERFORMANCE LOG] Code analysis for '{apk_path}' completed in {elapsed_time:.3f} seconds.")
    logger.info(f"Code analysis completed in {elapsed_time:.3f} seconds.")

    return {
        "urls": sorted(list(urls)),
        "ip_addresses": sorted(list(ip_addresses)),
        "suspicious_apis": suspicious_apis,
    }
