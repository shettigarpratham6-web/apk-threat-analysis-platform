"""Module for aggregating multi-stage analysis results and generating correlated threat summaries."""

import json
import logging
import os
from typing import Any, Dict

from backend.app.correlation.risk_scoring import compute_risk_score

logger = logging.getLogger("correlation_aggregator")

RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "results"))


def correlate_apk(apk_id: str) -> Dict[str, Any]:
    """
    Loads saved JSON analysis artifacts for the given apk_id (_static, _dynamic, _c2, _servers),
    computes unified risk score, and generates concise summaries for final reporting.

    :param apk_id: Unique identifier for the APK analysis session.
    :return: Combined dictionary containing apk_id, summaries, and risk assessment.
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)

    static_file = os.path.join(RESULTS_DIR, f"{apk_id}_static.json")
    dynamic_file = os.path.join(RESULTS_DIR, f"{apk_id}_dynamic.json")
    c2_file = os.path.join(RESULTS_DIR, f"{apk_id}_c2.json")
    servers_file = os.path.join(RESULTS_DIR, f"{apk_id}_servers.json")

    static_data = {}
    if os.path.exists(static_file):
        try:
            with open(static_file, "r", encoding="utf-8") as f:
                static_data = json.load(f)
        except Exception as exc:
            logger.warning(f"Failed to read static results for '{apk_id}': {exc}")

    dynamic_data = {}
    if os.path.exists(dynamic_file):
        try:
            with open(dynamic_file, "r", encoding="utf-8") as f:
                dynamic_data = json.load(f)
        except Exception as exc:
            logger.warning(f"Failed to read dynamic results for '{apk_id}': {exc}")

    c2_data = {}
    if os.path.exists(c2_file):
        try:
            with open(c2_file, "r", encoding="utf-8") as f:
                c2_data = json.load(f)
        except Exception as exc:
            logger.warning(f"Failed to read C2 results for '{apk_id}': {exc}")

    servers_data = {}
    if os.path.exists(servers_file):
        try:
            with open(servers_file, "r", encoding="utf-8") as f:
                servers_data = json.load(f)
        except Exception as exc:
            logger.warning(f"Failed to read server reputation results for '{apk_id}': {exc}")

    # Resolve package name
    static_inner = static_data.get("static_analysis", static_data)
    manifest = static_inner.get("manifest", {})
    package_name = (
        manifest.get("package_name")
        or static_inner.get("package_name")
        or dynamic_data.get("package_name")
        or "unknown.package"
    )

    # 1. Static Analysis Summary
    code_analysis = static_inner.get("code_analysis", {})
    sig_check = static_inner.get("signature_check", {})
    requested_perms = manifest.get("requested_permissions", [])
    dang_perms = manifest.get("declared_dangerous_permissions", manifest.get("dangerous_permissions", []))
    yara_matches = sig_check.get("yara_matches", [])

    static_summary = {
        "package_name": package_name,
        "requested_permissions_count": len(requested_perms),
        "dangerous_permissions_count": len(dang_perms),
        "urls_count": len(code_analysis.get("urls", [])),
        "ip_addresses_count": len(code_analysis.get("ip_addresses", [])),
        "suspicious_apis_count": len(code_analysis.get("suspicious_apis", [])),
        "yara_matches_count": len(yara_matches),
    }

    # 2. Dynamic Analysis Summary
    dynamic_inner = dynamic_data.get("dynamic_analysis", dynamic_data)
    net_traffic = dynamic_inner.get("network_traffic", [])
    file_act = dynamic_inner.get("file_activity", [])
    api_calls = dynamic_inner.get("api_calls", [])

    dynamic_summary = {
        "network_entries_count": len(net_traffic),
        "file_activity_count": len(file_act),
        "api_calls_count": len(api_calls),
    }

    # 3. C2 Detection Summary
    c2_hosts = c2_data.get("suspected_c2_hosts", [])
    if not c2_hosts and "c2_detection" in c2_data and isinstance(c2_data["c2_detection"], dict):
        c2_hosts = c2_data["c2_detection"].get("suspected_c2_hosts", [])

    top_conf = "none"
    if c2_hosts:
        conf_levels = [h.get("confidence", "low").lower() for h in c2_hosts]
        if "high" in conf_levels:
            top_conf = "high"
        elif "medium" in conf_levels:
            top_conf = "medium"
        else:
            top_conf = "low"

    c2_summary = {
        "suspected_c2_hosts_count": len(c2_hosts),
        "top_confidence": top_conf,
    }

    # 4. Server Reputation Summary
    checked_servers = servers_data.get("checked", [])
    if not checked_servers and "server_reputation" in servers_data and isinstance(servers_data["server_reputation"], dict):
        checked_servers = servers_data["server_reputation"].get("checked", [])

    verdict_counts = {"clean": 0, "suspicious": 0, "malicious": 0, "unverified": 0}
    for s in checked_servers:
        v = str(s.get("verdict", "unverified")).lower()
        if v in verdict_counts:
            verdict_counts[v] += 1
        else:
            verdict_counts["unverified"] += 1

    server_summary = {
        "checked_servers_count": len(checked_servers),
        "verdicts_breakdown": verdict_counts,
    }

    # Compute risk assessment score & contributing factors
    risk_assessment = compute_risk_score(
        static_results=static_data,
        dynamic_results=dynamic_data,
        c2_results=c2_data,
        server_results=servers_data,
    )

    return {
        "apk_id": apk_id,
        "package_name": package_name,
        "static_summary": static_summary,
        "dynamic_summary": dynamic_summary,
        "c2_summary": c2_summary,
        "server_summary": server_summary,
        "risk_assessment": risk_assessment,
    }
