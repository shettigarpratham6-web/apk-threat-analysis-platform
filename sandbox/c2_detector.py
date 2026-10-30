"""
Command-and-Control (C2) Pattern Detection Engine
Heuristic scoring and traffic pattern analysis for identifying beaconing,
frequency anomalies, raw IP communications, and non-standard egress points.
"""

import re
from typing import Dict, Any, List
from collections import defaultdict


SUSPICIOUS_PORTS = {1337, 4444, 5555, 6667, 7777, 8888, 9001, 9999, 13337, 31337}
ANDROID_SYSTEM_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "android.com",
    "googleusercontent.com", "gvt1.com", "gvt2.com", "ggpht.com"
}
C2_URI_KEYWORDS = ["beacon", "checkin", "heartbeat", "gate.php", "cmd", "task", "poll", "c2", "report"]


class C2Detector:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.raw_ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

    def analyze_network_data(self, network_summary: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes structured flow summary for C2 behavioral indicators.
        Returns a transparent heuristic score and itemized evidence.
        """
        indicators = []
        score = 0
        flows = network_summary.get("flows", [])
        intervals = network_summary.get("connection_intervals", {})
        dest_frequencies = network_summary.get("destination_frequencies", {})

        # Rule 1: Beaconing Interval Detection (Periodic requests with low jitter)
        for host, data in intervals.items():
            count = data["connection_count"]
            avg_int = data["avg_interval_seconds"]
            std_dev = data["std_deviation_seconds"]

            # Filter out known Android OS background domains
            clean_host = host.split(":")[0].lower()
            is_os_domain = any(clean_host == d or clean_host.endswith("." + d) for d in ANDROID_SYSTEM_DOMAINS)
            if is_os_domain:
                continue

            # If connected >= 3 times and std dev is low relative to mean, flag beaconing
            if count >= 3 and (std_dev <= 2.5 or (avg_int > 0 and std_dev / avg_int < 0.25)):
                rule_score = 35
                score += rule_score
                indicators.append({
                    "indicator": "C2_BEACONING_PATTERN",
                    "severity": "HIGH",
                    "score_weight": rule_score,
                    "target": host,
                    "evidence": {
                        "connection_count": count,
                        "average_interval_seconds": avg_int,
                        "std_deviation_seconds": std_dev,
                        "sample_intervals": data["intervals_seconds"][:5]
                    },
                    "description": f"Target contacted {count} times with strict periodic timing (avg: {avg_int}s, jitter/std_dev: {std_dev}s), characteristic of automated C2 beaconing."
                })

        # Rule 2: High Frequency Polling
        for host, count in dest_frequencies.items():
            clean_host = host.split(":")[0].lower()
            is_os_domain = any(clean_host == d or clean_host.endswith("." + d) for d in ANDROID_SYSTEM_DOMAINS)
            if is_os_domain:
                continue
            if count >= 8:
                rule_score = 20
                score += rule_score
                indicators.append({
                    "indicator": "HIGH_FREQUENCY_POLLING",
                    "severity": "MEDIUM",
                    "score_weight": rule_score,
                    "target": host,
                    "evidence": {"request_count": count},
                    "description": f"Destination received {count} requests within the analysis session without standard web asset patterns."
                })

        # Rule 3: Direct Raw IP Communication (No DNS resolution / FQDN)
        raw_ip_hosts = set()
        for f in flows:
            host = f.get("host", "").split(":")[0]
            if self.raw_ip_pattern.match(host) and not host.startswith("10.") and not host.startswith("127."):
                raw_ip_hosts.add(host)

        for ip in raw_ip_hosts:
            rule_score = 20
            score += rule_score
            indicators.append({
                "indicator": "RAW_IP_EGRESS",
                "severity": "MEDIUM",
                "score_weight": rule_score,
                "target": ip,
                "description": f"Direct socket or HTTP connection to raw external IP ({ip}) bypassing public domain name resolution."
            })

        # Rule 4: Non-Standard Port Communication
        suspicious_port_flows = defaultdict(list)
        for f in flows:
            port = f.get("port")
            if port in SUSPICIOUS_PORTS:
                suspicious_port_flows[port].append(f.get("url"))

        for port, sample_urls in suspicious_port_flows.items():
            rule_score = 15
            score += rule_score
            indicators.append({
                "indicator": "NON_STANDARD_EGRESS_PORT",
                "severity": "MEDIUM",
                "score_weight": rule_score,
                "target": f":{port}",
                "evidence": {"port": port, "sample_requests": sample_urls[:3]},
                "description": f"Traffic observed outbound on non-standard port {port}, commonly associated with backdoors and reverse shells."
            })

        # Rule 5: Suspicious C2 URI Patterns
        flagged_uris = []
        for f in flows:
            clean_host = f.get("host", "").split(":")[0].lower()
            is_os_domain = any(clean_host == d or clean_host.endswith("." + d) for d in ANDROID_SYSTEM_DOMAINS)
            if is_os_domain:
                continue
            path = f.get("path", "").lower()
            for kw in C2_URI_KEYWORDS:
                if kw in path:
                    flagged_uris.append({"url": f.get("url"), "matched_keyword": kw})
                    break

        if flagged_uris:
            rule_score = 25
            score += rule_score
            indicators.append({
                "indicator": "SUSPICIOUS_C2_URI_ENDPOINT",
                "severity": "HIGH",
                "score_weight": rule_score,
                "evidence": {"matched_endpoints": flagged_uris[:5]},
                "description": f"Observed {len(flagged_uris)} HTTP request(s) targeting endpoints containing C2 or polling terminology (e.g., checkin, beacon, poll)."
            })

        # Calculate final clamped score
        clamped_score = min(100, max(0, score))
        if clamped_score >= 61:
            risk_level = "HIGH"
        elif clamped_score >= 31:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "c2_heuristic_score": clamped_score,
            "risk_level": risk_level,
            "indicators_found": len(indicators),
            "indicators": indicators,
            "summary": {
                "is_suspicious": clamped_score >= 31,
                "has_periodic_beacon": any(i["indicator"] == "C2_BEACONING_PATTERN" for i in indicators),
                "assessment": f"Calculated risk score of {clamped_score}/100 ({risk_level} RISK). "
                              f"{len(indicators)} behavioral anomalies detected."
            }
        }
