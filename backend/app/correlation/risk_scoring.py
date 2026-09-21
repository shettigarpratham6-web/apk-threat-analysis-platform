"""Module for computing unified risk scores by correlating static, dynamic, C2, and server reputation results."""

import logging
from typing import Any, Dict, List

logger = logging.getLogger("risk_scoring")

# ==============================================================================
# RISK SCORING MODEL WEIGHTS & THRESHOLDS (DOCUMENTED FOR AUDIT & PRESENTATION)
# ==============================================================================
# 1. Dangerous Permissions: +10 points per declared dangerous permission, capped at +30.
# 2. YARA Rule Matches: +25 points per matched malware signature rule (no cap).
# 3. VirusTotal Detections: +30 points if VirusTotal report shows > 0 malicious engine detections.
# 4. Suspicious API Calls: +5 points per dangerous Dalvik API call detected in DEX code, capped at +20.
# 5. Suspected C2 Hosts: Weighted by confidence tier:
#      - Low Confidence C2 Host:    +10 points each
#      - Medium Confidence C2 Host: +20 points each
#      - High Confidence C2 Host:   +35 points each
# 6. External Server Reputation Verdicts:
#      - 'malicious' verdict:  +25 points each
#      - 'suspicious' verdict: +10 points each
#
# Score Range & Qualitative Risk Labels:
#   0  - 25  : Low Risk
#   26 - 50  : Medium Risk
#   51 - 75  : High Risk
#   76 - 100 : Critical Risk
# ==============================================================================


def compute_risk_score(
    static_results: Dict[str, Any] = None,
    dynamic_results: Dict[str, Any] = None,
    c2_results: Dict[str, Any] = None,
    server_results: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Computes a transparent, weighted risk score combining static analysis, dynamic behavior,
    C2 beaconing detection, and external server reputation lookup results.

    :param static_results: Dict containing manifest, code_analysis, signature_check.
    :param dynamic_results: Dict containing network_traffic, file_activity, api_calls.
    :param c2_results: Dict containing suspected_c2_hosts, raw_flagged_traffic.
    :param server_results: Dict containing checked server reputation list.
    :return: Dict containing risk_score, risk_label, score_breakdown, and contributing_factors.
    """
    if static_results is None:
        static_results = {}
    if dynamic_results is None:
        dynamic_results = {}
    if c2_results is None:
        c2_results = {}
    if server_results is None:
        server_results = {}

    # Extract nested sections safely
    static = static_results.get("static_analysis", static_results)
    manifest = static.get("manifest", {})
    code_analysis = static.get("code_analysis", {})
    sig_check = static.get("signature_check", {})

    c2_hosts = c2_results.get("suspected_c2_hosts", [])
    if not c2_hosts and "c2_detection" in c2_results and isinstance(c2_results["c2_detection"], dict):
        c2_hosts = c2_results["c2_detection"].get("suspected_c2_hosts", [])

    servers_checked = server_results.get("checked", [])
    if not servers_checked and "server_reputation" in server_results and isinstance(server_results["server_reputation"], dict):
        servers_checked = server_results["server_reputation"].get("checked", [])

    score_breakdown = {
        "dangerous_permissions_score": 0,
        "yara_matches_score": 0,
        "virustotal_score": 0,
        "suspicious_apis_score": 0,
        "c2_hosts_score": 0,
        "server_reputation_score": 0,
    }
    contributing_factors: List[str] = []

    # 1. Dangerous Permissions Score
    dang_perms = manifest.get("declared_dangerous_permissions", [])
    if not dang_perms and "dangerous_permissions" in manifest:
        dang_perms = manifest.get("dangerous_permissions", [])

    if dang_perms:
        perm_score = min(30, len(dang_perms) * 10)
        score_breakdown["dangerous_permissions_score"] = perm_score
        perm_names = ", ".join([p.rsplit(".", 1)[-1] for p in dang_perms[:3]])
        contributing_factors.append(
            f"Requested {len(dang_perms)} dangerous permission(s) ({perm_names})"
        )

    # 2. YARA Signature Rule Matches Score
    yara_matches = sig_check.get("yara_matches", [])
    if yara_matches:
        yara_score = len(yara_matches) * 25
        score_breakdown["yara_matches_score"] = yara_score
        rule_names = ", ".join([m.get("rule", "unknown") for m in yara_matches[:3]])
        contributing_factors.append(
            f"Matched {len(yara_matches)} YARA malware signature rule(s) ({rule_names})"
        )

    # 3. VirusTotal Detections Score
    vt_info = sig_check.get("virustotal", {})
    positives = vt_info.get("positives", 0)
    if positives > 0:
        score_breakdown["virustotal_score"] = 30
        contributing_factors.append(
            f"Flagged by VirusTotal with {positives} malicious detection(s)"
        )

    # 4. Suspicious API Calls Score
    susp_apis = code_analysis.get("suspicious_apis", [])
    if susp_apis:
        api_score = min(20, len(susp_apis) * 5)
        score_breakdown["suspicious_apis_score"] = api_score
        api_names = ", ".join([a.get("api", "unknown") if isinstance(a, dict) else str(a) for a in susp_apis[:3]])
        contributing_factors.append(
            f"Detected {len(susp_apis)} suspicious API call(s) in code ({api_names})"
        )

    # 5. Suspected C2 Hosts Score
    if c2_hosts:
        c2_score = 0
        high_cnt = 0
        med_cnt = 0
        low_cnt = 0
        for item in c2_hosts:
            conf = str(item.get("confidence", "low")).lower()
            if conf == "high":
                c2_score += 35
                high_cnt += 1
            elif conf == "medium":
                c2_score += 20
                med_cnt += 1
            else:
                c2_score += 10
                low_cnt += 1

        score_breakdown["c2_hosts_score"] = c2_score
        c2_summary_parts = []
        if high_cnt:
            c2_summary_parts.append(f"{high_cnt} high")
        if med_cnt:
            c2_summary_parts.append(f"{med_cnt} medium")
        if low_cnt:
            c2_summary_parts.append(f"{low_cnt} low")
        parts_str = ", ".join(c2_summary_parts)
        contributing_factors.append(
            f"Identified {len(c2_hosts)} suspected Command & Control (C2) host(s) ({parts_str} confidence)"
        )

    # 6. External Server Reputation Verdicts Score
    if servers_checked:
        rep_score = 0
        mal_cnt = 0
        susp_cnt = 0
        for s in servers_checked:
            v = str(s.get("verdict", "")).lower()
            if v == "malicious":
                rep_score += 25
                mal_cnt += 1
            elif v == "suspicious":
                rep_score += 10
                susp_cnt += 1

        if rep_score > 0:
            score_breakdown["server_reputation_score"] = rep_score
            rep_parts = []
            if mal_cnt:
                rep_parts.append(f"{mal_cnt} malicious")
            if susp_cnt:
                rep_parts.append(f"{susp_cnt} suspicious")
            contributing_factors.append(
                f"External reputation lookup flagged {', '.join(rep_parts)} server(s)"
            )

    # Calculate raw score sum and clamp to 0-100
    raw_score = sum(score_breakdown.values())
    risk_score = min(100, max(0, raw_score))

    # Map risk score to qualitative label
    if risk_score <= 25:
        risk_label = "Low Risk"
    elif risk_score <= 50:
        risk_label = "Medium Risk"
    elif risk_score <= 75:
        risk_label = "High Risk"
    else:
        risk_label = "Critical Risk"

    if not contributing_factors:
        contributing_factors.append("No significant static or dynamic threat indicators detected.")

    return {
        "risk_score": risk_score,
        "risk_label": risk_label,
        "score_breakdown": score_breakdown,
        "contributing_factors": contributing_factors,
    }
