"""
Network Flow Analyzer for Android Sandbox
Parses mitmproxy .flow captures, extracts connection metadata,
and computes frequency and periodicity metrics.
"""

import os
import json
from typing import Dict, Any, List
from collections import defaultdict
from mitmproxy import io
from mitmproxy.http import HTTPFlow


class NetworkAnalyzer:
    def __init__(self, flow_path: str):
        self.flow_path = flow_path

    def parse_flows(self) -> List[Dict[str, Any]]:
        """Parses raw mitmproxy binary stream into structured flow records."""
        if not os.path.exists(self.flow_path):
            return []

        parsed_flows = []
        with open(self.flow_path, "rb") as f:
            reader = io.FlowReader(f)
            for flow in reader.stream():
                if isinstance(flow, HTTPFlow):
                    req = flow.request
                    resp = flow.response

                    entry = {
                        "timestamp": req.timestamp_start,
                        "method": req.method,
                        "scheme": req.scheme,
                        "host": req.pretty_host,
                        "port": req.port,
                        "path": req.path,
                        "url": req.url,
                        "status_code": resp.status_code if resp else None,
                        "request_content_length": len(req.content) if req.content else 0,
                        "response_content_length": len(resp.content) if resp and resp.content else 0,
                        "content_type": resp.headers.get("content-type", "") if resp else "",
                        "tls_established": flow.client_conn.tls_established if flow.client_conn else False,
                        "sni": flow.client_conn.sni if flow.client_conn else None,
                        "client_ip": flow.client_conn.peername[0] if flow.client_conn and flow.client_conn.peername else "UNKNOWN"
                    }
                    parsed_flows.append(entry)

        return parsed_flows

    def analyze(self) -> Dict[str, Any]:
        """Calculates communication metrics, frequency distributions, and unique destination sets."""
        flows = self.parse_flows()

        host_counts = defaultdict(int)
        host_timestamps = defaultdict(list)
        protocol_counts = {"http": 0, "https": 0}

        for f in flows:
            host = f["host"]
            host_counts[host] += 1
            if f["timestamp"]:
                host_timestamps[host].append(f["timestamp"])
            scheme = f["scheme"].lower()
            if scheme in protocol_counts:
                protocol_counts[scheme] += 1
            else:
                protocol_counts[scheme] = 1

        # Calculate time intervals for destinations contacted >= 3 times
        destination_intervals = {}
        for host, timestamps in host_timestamps.items():
            if len(timestamps) >= 3:
                sorted_ts = sorted(timestamps)
                deltas = [round(sorted_ts[i] - sorted_ts[i - 1], 2) for i in range(1, len(sorted_ts))]
                avg_delta = sum(deltas) / len(deltas) if deltas else 0
                variance = sum((d - avg_delta) ** 2 for d in deltas) / len(deltas) if deltas else 0
                std_dev = variance ** 0.5
                destination_intervals[host] = {
                    "connection_count": len(timestamps),
                    "intervals_seconds": deltas,
                    "avg_interval_seconds": round(avg_delta, 2),
                    "std_deviation_seconds": round(std_dev, 2)
                }

        unique_hosts = sorted(list(host_counts.keys()))

        return {
            "total_connections": len(flows),
            "unique_destinations": unique_hosts,
            "unique_destination_count": len(unique_hosts),
            "protocol_breakdown": protocol_counts,
            "destination_frequencies": dict(host_counts),
            "connection_intervals": destination_intervals,
            "flows": flows
        }

    def save_summary_json(self, output_path: str) -> str:
        summary = self.analyze()
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        return output_path


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "logs/traffic/traffic.flow"
    analyzer = NetworkAnalyzer(path)
    res = analyzer.analyze()
    print(f"Total Captured Connections: {res['total_connections']}")
    print(f"Unique Destinations ({res['unique_destination_count']}): {res['unique_destinations'][:10]}")
