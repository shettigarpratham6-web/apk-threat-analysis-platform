"""Module for aggregating multi-stage analysis results, correlating static & dynamic evidence,
and generating unified LLM forensic threat summaries.
"""

import json
import logging
import os
from typing import Any, Dict, List

from backend.app.correlation.risk_scoring import compute_risk_score

try:
    from backend.app.static_analysis.llm_analyzer import generate_unified_threat_narrative
    _LLM_AVAILABLE = True
except Exception:
    _LLM_AVAILABLE = False
    generate_unified_threat_narrative = None

logger = logging.getLogger("correlation_aggregator")

RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "results"))


def correlate_apk(apk_id: str) -> Dict[str, Any]:
    """
    Loads saved JSON analysis artifacts for the given apk_id (_static, _dynamic, _c2, _servers),
    identifies confirmed multi-vector threats, computes unified risk score, and invokes the
    LLM reasoning layer with comprehensive static + dynamic evidence.

    :param apk_id: Unique identifier for the APK analysis session.
    :return: Combined dictionary containing apk_id, summaries, confirmed threats, risk assessment,
             and unified threat narrative.
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
    manifest = static_inner.get("manifest_analysis", static_inner.get("manifest", {}))
    metadata = manifest.get("metadata", {})
    package_name = (
        metadata.get("package_name")
        or manifest.get("package_name")
        or static_inner.get("package_name")
        or dynamic_data.get("package_name")
        or "unknown.package"
    )

    # 1. Static Analysis Summary
    code_analysis = static_inner.get("code_analysis", {})
    sig_check = static_inner.get("signature_check", {})
    manifest_perms = (
        manifest.get("permissions")
        or manifest.get("requested_permissions")
        or manifest.get("declared_dangerous_permissions")
        or []
    )
    dang_perms = [
        p.get("name") if isinstance(p, dict) else str(p)
        for p in manifest_perms
        if (isinstance(p, dict) and p.get("severity") in ("Critical", "High")) or "SMS" in str(p) or "RECORD" in str(p) or "BOOT" in str(p)
    ]
    if not dang_perms and manifest.get("declared_dangerous_permissions"):
        dang_perms = [str(p) for p in manifest.get("declared_dangerous_permissions", [])]

    yara_matches = static_inner.get("yara_matches", sig_check.get("yara_matches", []))

    static_summary = {
        "package_name": package_name,
        "requested_permissions_count": len(manifest_perms),
        "dangerous_permissions_count": len(dang_perms),
        "urls_count": len(code_analysis.get("urls", [])),
        "ip_addresses_count": len(code_analysis.get("ip_addresses", [])),
        "suspicious_apis_count": len(code_analysis.get("suspicious_apis", [])),
        "yara_matches_count": len(yara_matches),
    }

    # 2. Dynamic Analysis Summary & Runtime Events
    dynamic_inner = dynamic_data.get("dynamic_analysis", dynamic_data)
    frida_events_inner = dynamic_inner.get("frida_events", {}) if isinstance(dynamic_inner.get("frida_events"), dict) else {}
    net_traffic = dynamic_inner.get("network_traffic", [])
    file_act = dynamic_inner.get("file_activity") or frida_events_inner.get("file_activity", [])
    api_calls = dynamic_inner.get("api_calls") or frida_events_inner.get("api_calls", [])
    sms_interceptions = dynamic_inner.get("sms_interceptions") or frida_events_inner.get("sms_interceptions", [])
    process_executions = dynamic_inner.get("process_executions") or frida_events_inner.get("process_executions", [])
    dynamic_dex_loads = dynamic_inner.get("dynamic_dex_loads") or frida_events_inner.get("dynamic_dex_loads", [])
    logcat_summary = dynamic_inner.get("logcat_summary", {})

    dynamic_summary = {
        "network_entries_count": len(net_traffic),
        "file_activity_count": len(file_act),
        "api_calls_count": len(api_calls),
        "sms_intercepts_count": len(sms_interceptions),
        "process_executions_count": len(process_executions),
        "dynamic_dex_loads_count": len(dynamic_dex_loads),
    }

    # 3. C2 Detection Summary
    c2_hosts = c2_data.get("suspected_c2_hosts", [])
    if not c2_hosts and "c2_detection" in c2_data and isinstance(c2_data["c2_detection"], dict):
        c2_hosts = c2_data["c2_detection"].get("suspected_c2_hosts", [])

    c2_summary_obj = c2_data.get("c2_summary", {})
    has_beacon = c2_summary_obj.get("has_periodic_beacon", False)
    if not has_beacon:
        has_beacon = any("beacon" in str(h.get("reasons", [])).lower() for h in c2_hosts)

    dga_detections = c2_data.get("dga_detections", [])

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
        "has_periodic_beacon": has_beacon,
        "dga_domains_detected": len(dga_detections),
    }

    # 4. Server Reputation Summary
    checked_servers = servers_data.get("checked", [])
    if not checked_servers and "server_reputation" in servers_data and isinstance(servers_data["server_reputation"], dict):
        checked_servers = servers_data["server_reputation"].get("checked", [])

    verdict_counts = {"clean": 0, "suspicious": 0, "malicious": 0, "unverified": 0}
    malicious_ips = []
    for s in checked_servers:
        v = str(s.get("verdict", "unverified")).lower()
        if v in verdict_counts:
            verdict_counts[v] += 1
        else:
            verdict_counts["unverified"] += 1
        if v == "malicious":
            malicious_ips.append(s.get("host") or s.get("ip", "unknown"))

    server_summary = {
        "checked_servers_count": len(checked_servers),
        "verdicts_breakdown": verdict_counts,
        "malicious_hosts": malicious_ips,
    }

    # 5. MULTI-VECTOR CORRELATION (Matching Static Capability -> Dynamic Execution Reality)
    confirmed_threats: List[str] = []

    # Correlation A: SMS Fraud / Banking Trojan (Manifest permission + Runtime SMS transmission attempt)
    has_sms_perm = any("SEND_SMS" in p or "RECEIVE_SMS" in p for p in dang_perms)
    if has_sms_perm and sms_interceptions:
        confirmed_threats.append(
            f"Confirmed SMS Trojan: Declared SMS permissions statically and actively attempted outbound SMS transmission at runtime ({len(sms_interceptions)} pulse(s))"
        )
    elif sms_interceptions:
        confirmed_threats.append(
            f"Unprivileged SMS Interception: Intercepted {len(sms_interceptions)} SMS sending call(s) at runtime"
        )

    # Correlation B: Dropper / Dynamic Code Loading (Static classloader indicator + Runtime DexClassLoader)
    static_has_loader = any("DexClassLoader" in str(api) for api in code_analysis.get("suspicious_apis", []))
    if (static_has_loader or dang_perms) and dynamic_dex_loads:
        confirmed_threats.append(
            f"Confirmed Dynamic Dropper (Second-Stage Payload): Dynamically loaded external secondary payload ({len(dynamic_dex_loads)} DexClassLoader event(s))"
        )
    elif dynamic_dex_loads:
        confirmed_threats.append(
            f"Dynamic Code Execution / Dropper: Invoked DexClassLoader at runtime to load secondary bytecode"
        )

    # Correlation C: Command Execution / Root Shell (Static root commands + Runtime Runtime.exec)
    if process_executions:
        cmds = [e.get("details", {}).get("command") or e.get("command") or e.get("args", [""])[0] for e in process_executions[:3]]
        cmds_str = ", ".join(filter(None, cmds))
        confirmed_threats.append(
            f"Active Shell Execution: Executed system processes or root commands at runtime: [{cmds_str}]"
        )

    # Correlation D: Active C2 Communication (Static hardcoded domain + Dynamic connection/beacon)
    static_hosts = set(code_analysis.get("ip_addresses", []))
    for u in code_analysis.get("urls", []):
        static_hosts.add(str(u))

    matched_c2 = [
        h.get("host") for h in c2_hosts
        if any(h.get("host", "") in s or s in h.get("host", "") for s in static_hosts)
    ]
    if matched_c2 and has_beacon:
        confirmed_threats.append(
            f"Confirmed Active C2 Channel: Established periodic beaconing to hardcoded destination ({', '.join(matched_c2)})"
        )
    elif has_beacon:
        confirmed_threats.append(
            "Automated Periodic C2 Beaconing: Observed strict interval communication characteristic of botnet check-ins"
        )

    # Correlation E: Malicious Threat Infrastructure
    if malicious_ips:
        confirmed_threats.append(
            f"Confirmed Malicious Infrastructure: Active communication with server(s) flagged malicious by threat intelligence ({', '.join(malicious_ips)})"
        )

    # Correlation F: DGA Algorithm Egress
    if dga_detections and c2_hosts:
        dga_domains = [d.get("domain") for d in dga_detections[:2]]
        confirmed_threats.append(
            f"DGA-Driven Botnet Infrastructure: Dynamic communication with algorithmically generated domain(s) ({', '.join(dga_domains)})"
        )

    # 6. Compute Risk Assessment Score
    risk_assessment = compute_risk_score(
        static_results=static_data,
        dynamic_results=dynamic_data,
        c2_results=c2_data,
        server_results=servers_data,
        confirmed_threats=confirmed_threats,
    )

    # 7. Generate Unified Multi-Vector LLM Threat Narrative
    runtime_events = {
        "sms_interceptions": sms_interceptions,
        "process_executions": process_executions,
        "dynamic_dex_loads": dynamic_dex_loads,
        "file_activity_count": len(file_act),
        "logcat_summary": logcat_summary,
    }

    correlated_payload = {
        "apk_id": apk_id,
        "package_name": package_name,
        "confirmed_threats": confirmed_threats,
        "static_summary": static_summary,
        "dynamic_summary": dynamic_summary,
        "c2_summary": c2_summary,
        "server_summary": server_summary,
        "runtime_events": runtime_events,
        "risk_assessment": risk_assessment,
    }

    unified_narrative = ""
    if _LLM_AVAILABLE and generate_unified_threat_narrative is not None:
        try:
            logger.info(f"Generating unified multi-vector LLM threat narrative for {package_name}...")
            unified_narrative = generate_unified_threat_narrative(correlated_payload)
        except Exception as exc:
            logger.error(f"Error in unified threat narrative generation: {exc}")
            unified_narrative = f"[Executive threat narrative unavailable: {exc}]"

    correlated_payload["unified_threat_narrative"] = unified_narrative

    return correlated_payload
