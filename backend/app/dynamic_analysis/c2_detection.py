"""Module for detecting Command & Control (C2) communication patterns in network traffic."""

import math
import re
import logging
from typing import Any, Dict, List, Set

logger = logging.getLogger("c2_detection")

# Regex pattern matching IPv4 addresses
IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")


def detect_c2(
    network_traffic: List[Dict[str, Any]],
    code_analysis_urls_ips: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Applies rule-based heuristics to dynamic network traffic and static code indicators to detect C2 communication.

    :param network_traffic: List of HTTP/HTTPS traffic flow dictionaries.
    :param code_analysis_urls_ips: Optional dict containing static 'urls' and 'ip_addresses'.
    :return: Dict containing 'suspected_c2_hosts' and 'raw_flagged_traffic'.
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
    benign_defaults = {"schemas.android.com", "android.com", "google.com", "w3.org", "localhost", "127.0.0.1", "10.0.2.2"}
    static_hosts = {h for h in static_hosts if h not in benign_defaults and not h.endswith(".google.com")}

    # Group traffic entries by host
    host_groups: Dict[str, List[Dict[str, Any]]] = {}
    for entry in network_traffic:
        host = str(entry.get("host", "")).strip().lower()
        if host:
            if host not in host_groups:
                host_groups[host] = []
            host_groups[host].append(entry)

    suspected_c2_hosts: List[Dict[str, Any]] = []
    raw_flagged_traffic: List[Dict[str, Any]] = []
    observed_static_hosts: Set[str] = set()

    # 1. Process active network traffic host groups
    for host, entries in host_groups.items():
        reasons: List[str] = []

        # Heuristic A: Raw IP connection (excluding standard local/emulator subnets)
        if IPV4_REGEX.match(host):
            if not (host.startswith("127.") or host.startswith("10.0.2.") or host == "0.0.0.0"):
                reasons.append(f"Connection directly to raw IP address ({host}) instead of domain name")

        # Heuristic B: Non-standard ports (other than 80 and 443)
        non_std_ports = {
            entry.get("port")
            for entry in entries
            if entry.get("port") and entry.get("port") not in (80, 443)
        }
        if non_std_ports:
            ports_str = ", ".join(str(p) for p in sorted(list(non_std_ports)))
            reasons.append(f"Connections via non-standard port(s): {ports_str}")

        # Heuristic C: Beaconing pattern (regular time intervals between requests)
        timestamps = sorted([e.get("timestamp", 0) for e in entries if e.get("timestamp")])
        if len(timestamps) >= 3:
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
            avg_interval = sum(intervals) / len(intervals)
            if len(intervals) >= 2 and avg_interval > 0:
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                std_dev = math.sqrt(variance)
                if (std_dev / max(avg_interval, 0.001) < 0.35) and (0.5 <= avg_interval <= 300):
                    reasons.append(f"Beaconing pattern detected (regular request interval ~{avg_interval:.1f}s)")
        elif len(timestamps) == 2:
            gap = timestamps[1] - timestamps[0]
            if 0.5 <= gap <= 60:
                reasons.append(f"Repeated sequential requests with short gap ({gap:.1f}s)")

        # Heuristic D: Small fixed-size POST payloads (beacon check-in)
        post_entries = [e for e in entries if str(e.get("method")).upper() == "POST"]
        if post_entries:
            small_posts = [e for e in post_entries if 0 < e.get("request_size", 0) < 512]
            if len(small_posts) == len(post_entries) and len(post_entries) >= 1:
                reasons.append(f"Repeated small POST payloads ({len(small_posts)} check-ins < 512 bytes)")

        # Heuristic E: Static code analysis correlation
        matched_static = [s_host for s_host in static_hosts if host == s_host or host in s_host or s_host in host]
        if matched_static:
            reasons.append("Host matches hardcoded C2 indicator extracted from static code analysis")
            for m in matched_static:
                observed_static_hosts.add(m)

        if reasons:
            score = len(reasons)
            confidence = "low"
            if score == 2:
                confidence = "medium"
            elif score >= 3:
                confidence = "high"

            suspected_c2_hosts.append({
                "host": host,
                "reasons": reasons,
                "confidence": confidence,
            })
            raw_flagged_traffic.extend(entries)

    # 2. Process hardcoded-but-unused static C2 indicators (dormant/obfuscated C2 domains)
    unobserved_static = static_hosts - observed_static_hosts
    for host in unobserved_static:
        # Check if unobserved static host is raw IP or suspicious domain
        reasons = ["Hardcoded domain/IP in static code analysis was not resolved via active traffic"]
        if IPV4_REGEX.match(host) and not (host.startswith("127.") or host.startswith("10.0.2.")):
            reasons.append(f"Hardcoded raw IP address ({host}) found in static code")

        score = len(reasons)
        confidence = "low"
        if score == 2:
            confidence = "medium"
        elif score >= 3:
            confidence = "high"

        suspected_c2_hosts.append({
            "host": host,
            "reasons": reasons,
            "confidence": confidence,
        })

    # Sort suspected C2 hosts by confidence level
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    suspected_c2_hosts.sort(key=lambda x: confidence_order.get(x["confidence"], 3))

    return {
        "suspected_c2_hosts": suspected_c2_hosts,
        "raw_flagged_traffic": raw_flagged_traffic,
    }

