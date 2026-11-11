"""Module for detecting Command & Control (C2) communication patterns in network traffic.

Includes multi-layered heuristics:
- Periodic beaconing interval detection (mean, variance, and standard deviation / jitter analysis)
- Domain Generation Algorithm (DGA) entropy and phonetic randomness detection
- Suspicious C2 URI endpoints (checkin, beacon, heartbeat, gate.php, poll, task, cmd)
- Dynamic DNS and non-standard egress port monitoring
- Static code indicator correlation (cross-referencing hardcoded URLs/IPs with runtime traffic)
"""

import math
import re
import logging
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("c2_detection")

# Regex pattern matching IPv4 addresses
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# Known suspicious / non-standard egress ports commonly leveraged by C2 backdoors
SUSPICIOUS_C2_PORTS: Set[int] = {
    1337, 4444, 5555, 6667, 7777, 8888, 9001, 9999, 13337, 31337, 8081, 8008, 8880
}

# Known free or dynamic DNS domains frequently abused for agile C2 infrastructure
DYNAMIC_DNS_DOMAINS: Set[str] = {
    "duckdns.org", "no-ip.org", "no-ip.com", "ngrok.io", "hopto.org",
    "zapto.org", "servehttp.com", "ddns.net", "bounceme.net", "freeddns.org",
    "myftp.biz", "myvnc.com", "sytes.net"
}

# Common benign/system Android domains to suppress false positive alerts
BENIGN_SYSTEM_DOMAINS: Set[str] = {
    "schemas.android.com", "android.com", "google.com", "googleapis.com",
    "gstatic.com", "googleusercontent.com", "gvt1.com", "gvt2.com", "ggpht.com",
    "w3.org", "localhost", "127.0.0.1", "10.0.2.2"
}

# Common C2 URI keywords and control endpoints
C2_URI_KEYWORDS: List[str] = [
    "gate.php", "beacon", "heartbeat", "checkin", "cmd", "task", "poll",
    "c2", "report", "bot", "connect.php", "update.php", "panel"
]


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy for a given string (bits per symbol)."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def is_dga_domain(domain: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Evaluates whether a domain name displays characteristics of an algorithmically
    generated domain (DGA) using Shannon entropy, consonant-to-vowel ratio,
    digit ratio, and length.
    """
    # Extract effective second-level domain name (strip TLD and subdomains)
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        # Use SLD
        target = parts[-2]
    else:
        target = parts[0]

    # Clean non-alphanumeric
    clean_target = re.sub(r"[^a-z0-9]", "", target)
    if len(clean_target) < 6:
        return False, {}

    entropy = calculate_entropy(clean_target)
    vowels = sum(1 for c in clean_target if c in "aeiou")
    consonants = sum(1 for c in clean_target if c in "bcdfghjklmnpqrstvwxyz")
    digits = sum(1 for c in clean_target if c.isdigit())
    length = len(clean_target)

    vowel_ratio = vowels / max(length, 1)
    consonant_ratio = consonants / max(length, 1)
    digit_ratio = digits / max(length, 1)

    # Heuristic thresholds:
    # High entropy (> 3.4), low vowel ratio (< 0.18), or high consonant clusters
    is_dga = False
    reasons = []

    if entropy >= 3.45 and length >= 8:
        is_dga = True
        reasons.append(f"High Shannon entropy ({entropy:.2f} bits/symbol)")

    if length >= 10 and vowel_ratio < 0.15:
        is_dga = True
        reasons.append(f"Abnormally low vowel ratio ({vowel_ratio:.2f})")

    if digit_ratio > 0.40 and length >= 8:
        is_dga = True
        reasons.append(f"High numeric density ({digit_ratio:.2f})")

    details = {
        "domain": domain,
        "evaluated_token": clean_target,
        "length": length,
        "entropy": round(entropy, 2),
        "vowel_ratio": round(vowel_ratio, 2),
        "consonant_ratio": round(consonant_ratio, 2),
        "digit_ratio": round(digit_ratio, 2),
        "reasons": reasons,
    }
    return is_dga, details


def detect_c2(
    network_traffic: List[Dict[str, Any]],
    code_analysis_urls_ips: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Applies multi-layered rule-based heuristics and behavioral analysis to dynamic network
    traffic and static code indicators to identify Command & Control (C2) communication.

    :param network_traffic: List of HTTP/HTTPS traffic flow dictionaries.
    :param code_analysis_urls_ips: Optional dict containing static 'urls' and 'ip_addresses'.
    :return: Dict containing 'suspected_c2_hosts', 'raw_flagged_traffic', 'dga_detections',
             and comprehensive 'c2_summary'.
    """
    if code_analysis_urls_ips is None:
        code_analysis_urls_ips = {}

    static_urls = set(code_analysis_urls_ips.get("urls", []))
    static_ips = set(code_analysis_urls_ips.get("ip_addresses", []))

    # Extract domain/IP host targets from static indicators
    static_hosts: Set[str] = set(static_ips)
    for u in static_urls:
        match = re.search(r"https?://([^/:]+)", str(u), re.IGNORECASE)
        if match:
            static_hosts.add(match.group(1).lower())
        else:
            cleaned = str(u).strip().lower()
            if cleaned:
                static_hosts.add(cleaned)

    # Filter out common benign/system hosts from static indicators
    static_hosts = {
        h for h in static_hosts
        if h not in BENIGN_SYSTEM_DOMAINS and not any(h.endswith("." + d) for d in BENIGN_SYSTEM_DOMAINS)
    }

    # Group traffic entries by host
    host_groups: Dict[str, List[Dict[str, Any]]] = {}
    for entry in network_traffic:
        raw_host = str(entry.get("host", "")).strip().lower()
        if raw_host:
            clean_host = raw_host.split(":")[0]
            if clean_host not in host_groups:
                host_groups[clean_host] = []
            host_groups[clean_host].append(entry)

    suspected_c2_hosts: List[Dict[str, Any]] = []
    raw_flagged_traffic: List[Dict[str, Any]] = []
    observed_static_hosts: Set[str] = set()
    dga_detections: List[Dict[str, Any]] = []

    # 1. Process active network traffic host groups
    for host, entries in host_groups.items():
        # Check if host is a known Android OS / benign domain
        is_os_domain = any(host == d or host.endswith("." + d) for d in BENIGN_SYSTEM_DOMAINS)
        if is_os_domain:
            continue

        reasons: List[str] = []
        indicators: List[Dict[str, Any]] = []
        host_score = 0

        # Heuristic A: Raw IP connection (excluding local / emulator subnets)
        if IPV4_REGEX.match(host):
            if not (host.startswith("127.") or host.startswith("10.0.2.") or host.startswith("192.168.") or host == "0.0.0.0"):
                r_desc = f"Direct egress to external raw IP address ({host}) bypassing public DNS resolution"
                reasons.append(r_desc)
                indicators.append({"type": "RAW_IP_EGRESS", "severity": "MEDIUM", "score": 20, "description": r_desc})
                host_score += 20

        # Heuristic B: Dynamic DNS provider usage
        is_ddns = any(host == ddns or host.endswith("." + ddns) for ddns in DYNAMIC_DNS_DOMAINS)
        if is_ddns:
            r_desc = f"Communication with dynamic DNS provider infrastructure ({host})"
            reasons.append(r_desc)
            indicators.append({"type": "DYNAMIC_DNS_USAGE", "severity": "HIGH", "score": 25, "description": r_desc})
            host_score += 25

        # Heuristic C: DGA Domain Analysis
        if not IPV4_REGEX.match(host):
            dga_flag, dga_meta = is_dga_domain(host)
            if dga_flag:
                r_desc = f"Domain matches Domain Generation Algorithm (DGA) pattern: {', '.join(dga_meta.get('reasons', []))}"
                reasons.append(r_desc)
                indicators.append({"type": "DGA_DOMAIN_ANOMALY", "severity": "HIGH", "score": 30, "description": r_desc})
                host_score += 30
                dga_detections.append(dga_meta)

        # Heuristic D: Non-standard C2 Egress Ports
        ports_observed = {entry.get("port") for entry in entries if entry.get("port")}
        suspicious_ports = ports_observed.intersection(SUSPICIOUS_C2_PORTS)
        non_standard_ports = {p for p in ports_observed if p not in (80, 443, None)}

        if suspicious_ports:
            ports_str = ", ".join(str(p) for p in sorted(list(suspicious_ports)))
            r_desc = f"Traffic observed outbound on high-risk C2 port(s): {ports_str}"
            reasons.append(r_desc)
            indicators.append({"type": "KNOWN_C2_PORT", "severity": "HIGH", "score": 25, "description": r_desc})
            host_score += 25
        elif non_standard_ports:
            ports_str = ", ".join(str(p) for p in sorted(list(non_standard_ports)))
            r_desc = f"Connections via non-standard egress port(s): {ports_str}"
            reasons.append(r_desc)
            indicators.append({"type": "NON_STANDARD_PORT", "severity": "MEDIUM", "score": 15, "description": r_desc})
            host_score += 15

        # Heuristic E: Beaconing pattern (low-jitter periodic connection intervals)
        timestamps = sorted([e.get("timestamp", 0) for e in entries if e.get("timestamp")])
        detected_interval = None
        std_dev = 0.0

        if len(timestamps) >= 3:
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
            avg_interval = sum(intervals) / len(intervals)
            if len(intervals) >= 2 and avg_interval > 0:
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                std_dev = math.sqrt(variance)
                jitter_ratio = std_dev / max(avg_interval, 0.001)

                # Strict beacon: regular intervals, low variance relative to mean
                if (std_dev <= 2.5 or jitter_ratio < 0.25) and (0.5 <= avg_interval <= 300):
                    detected_interval = round(avg_interval, 2)
                    r_desc = (
                        f"Automated C2 beaconing pattern detected (contacted {len(timestamps)} times, "
                        f"mean interval: {detected_interval}s, jitter/std-dev: {std_dev:.2f}s)"
                    )
                    reasons.append(r_desc)
                    indicators.append({"type": "C2_BEACONING_PATTERN", "severity": "HIGH", "score": 35, "description": r_desc})
                    host_score += 35
                elif jitter_ratio < 0.35:
                    detected_interval = round(avg_interval, 2)
                    r_desc = f"Suspected periodic beaconing interval (~{detected_interval}s, jitter: {std_dev:.2f}s)"
                    reasons.append(r_desc)
                    indicators.append({"type": "PERIODIC_REQUESTS", "severity": "MEDIUM", "score": 20, "description": r_desc})
                    host_score += 20

        elif len(timestamps) == 2:
            gap = timestamps[1] - timestamps[0]
            if 0.5 <= gap <= 60:
                detected_interval = round(gap, 2)
                r_desc = f"Repeated sequential requests with short gap ({detected_interval}s)"
                reasons.append(r_desc)
                indicators.append({"type": "SEQUENTIAL_POLL", "severity": "LOW", "score": 10, "description": r_desc})
                host_score += 10

        # Heuristic F: Suspicious C2 URI paths
        flagged_uris = []
        for e in entries:
            url_str = str(e.get("url") or e.get("path") or "").lower()
            for kw in C2_URI_KEYWORDS:
                if kw in url_str:
                    flagged_uris.append({"url": e.get("url") or e.get("path"), "matched_keyword": kw})
                    break

        if flagged_uris:
            r_desc = f"Observed {len(flagged_uris)} request(s) targeting C2 control terminology (e.g., {flagged_uris[0]['matched_keyword']})"
            reasons.append(r_desc)
            indicators.append({"type": "SUSPICIOUS_C2_URI", "severity": "HIGH", "score": 25, "description": r_desc})
            host_score += 25

        # Heuristic G: Small fixed-size POST payloads (beacon check-in)
        post_entries = [e for e in entries if str(e.get("method")).upper() == "POST"]
        if post_entries:
            small_posts = [e for e in post_entries if 0 < (e.get("request_size") or 0) < 512]
            if len(small_posts) == len(post_entries) and len(post_entries) >= 2:
                r_desc = f"Repeated small POST payloads ({len(small_posts)} check-in pulses < 512 bytes)"
                reasons.append(r_desc)
                indicators.append({"type": "SMALL_POST_CHECKIN", "severity": "MEDIUM", "score": 15, "description": r_desc})
                host_score += 15

        # Heuristic H: Static code analysis correlation
        matched_static = [s_host for s_host in static_hosts if host == s_host or host in s_host or s_host in host]
        if matched_static:
            r_desc = f"Host matches hardcoded C2 indicator extracted from static DEX bytecode ({', '.join(matched_static)})"
            reasons.append(r_desc)
            indicators.append({"type": "STATIC_INDICATOR_MATCH", "severity": "HIGH", "score": 30, "description": r_desc})
            host_score += 30
            for m in matched_static:
                observed_static_hosts.add(m)

        if reasons:
            confidence = "low"
            if host_score >= 50 or any(i.get("severity") == "HIGH" for i in indicators):
                confidence = "high"
            elif host_score >= 25 or len(reasons) >= 2:
                confidence = "medium"

            evidence = {
                "requests_count": len(entries),
                "methods": sorted(list({str(e.get("method", "GET")).upper() for e in entries if e.get("method")})),
                "ports": sorted(list({e.get("port") for e in entries if e.get("port")})),
                "sample_urls": [e.get("url") for e in entries[:4] if e.get("url")],
                "sample_paths": list({e.get("path") for e in entries[:5] if e.get("path")}),
                "beacon_interval_seconds": detected_interval,
                "jitter_std_dev": round(std_dev, 2) if std_dev else 0.0,
                "total_bytes_transferred": sum((e.get("request_size") or 0) + (e.get("response_size") or 0) for e in entries),
                "detailed_indicators": indicators,
            }

            suspected_c2_hosts.append({
                "host": host,
                "reasons": reasons,
                "confidence": confidence,
                "evidence": evidence,
                "heuristic_score": min(host_score, 100),
            })
            raw_flagged_traffic.extend(entries)

    # 2. Process hardcoded-but-unused static C2 indicators (dormant/obfuscated C2 domains)
    unobserved_static = static_hosts - observed_static_hosts
    for host in unobserved_static:
        reasons = ["Hardcoded domain/IP in static code analysis was not resolved via active traffic"]
        dormant_score = 15

        if IPV4_REGEX.match(host) and not (host.startswith("127.") or host.startswith("10.0.2.") or host.startswith("192.168.")):
            reasons.append(f"Hardcoded raw IP address ({host}) found in static code")
            dormant_score += 15

        is_ddns = any(host == ddns or host.endswith("." + ddns) for ddns in DYNAMIC_DNS_DOMAINS)
        if is_ddns:
            reasons.append(f"Hardcoded domain uses Dynamic DNS infrastructure ({host})")
            dormant_score += 20

        dga_flag, dga_meta = is_dga_domain(host)
        if dga_flag:
            reasons.append("Hardcoded domain displays DGA entropy characteristics")
            dormant_score += 20
            dga_detections.append(dga_meta)

        confidence = "low"
        if dormant_score >= 40:
            confidence = "medium"

        suspected_c2_hosts.append({
            "host": host,
            "reasons": reasons,
            "confidence": confidence,
            "evidence": {
                "requests_count": 0,
                "status": "Dormant / Static-Only",
                "source": "Decompiled Bytecode Asset",
            },
            "heuristic_score": min(dormant_score, 100),
        })

    # Sort suspected C2 hosts by confidence level
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    suspected_c2_hosts.sort(key=lambda x: confidence_order.get(x["confidence"], 3))

    # Overall C2 score synthesis
    max_score = max([h.get("heuristic_score", 0) for h in suspected_c2_hosts], default=0)
    has_beacon = any(
        any("beacon" in str(r).lower() for r in h.get("reasons", []))
        for h in suspected_c2_hosts
    )

    if max_score >= 60:
        c2_verdict = "HIGH"
    elif max_score >= 30:
        c2_verdict = "MEDIUM"
    elif suspected_c2_hosts:
        c2_verdict = "LOW"
    else:
        c2_verdict = "CLEAN"

    c2_summary = {
        "overall_c2_score": max_score,
        "c2_risk_level": c2_verdict,
        "is_suspicious": max_score >= 30,
        "has_periodic_beacon": has_beacon,
        "dga_domains_detected": len(dga_detections),
        "suspected_hosts_count": len(suspected_c2_hosts),
        "assessment": f"Evaluated {len(network_traffic)} flows. Flagged {len(suspected_c2_hosts)} suspected C2 destination(s) ({c2_verdict} RISK)."
    }

    return {
        "suspected_c2_hosts": suspected_c2_hosts,
        "raw_flagged_traffic": raw_flagged_traffic,
        "dga_detections": dga_detections,
        "c2_summary": c2_summary,
    }
