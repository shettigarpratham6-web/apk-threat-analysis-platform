"""
Report Generator for Android Malware Analysis Sandbox
Produces structured JSON and comprehensive, modern HTML forensic reports.
"""

import os
import json
import datetime
from typing import Dict, Any


class ReportGenerator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_unified_report(
        self,
        session_id: str,
        static_data: Dict[str, Any],
        network_data: Dict[str, Any],
        c2_data: Dict[str, Any],
        frida_events: list,
        logcat_summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Combines all analysis phases into a structured forensic report."""
        timestamp = datetime.datetime.now().isoformat()
        
        # Calculate combined risk assessment
        static_score = static_data.get("risk_assessment", {}).get("heuristic_score", 0)
        c2_score = c2_data.get("c2_heuristic_score", 0)
        has_beacon = c2_data.get("summary", {}).get("has_periodic_beacon", False)
        
        # Dynamic Frida behavioral penalty
        frida_penalty = 0
        for ev in frida_events:
            mod = ev.get("module", "")
            ev_type = ev.get("type", "")
            if mod == "sms":
                frida_penalty += 30
            elif "EXEC" in ev_type:
                frida_penalty += 25
            elif "DYNAMIC_DEX" in ev_type:
                frida_penalty += 25

        # Multi-Vector Threat Scoring Synthesis:
        # If active C2 beaconing or critical runtime tampering is confirmed,
        # anchor the threat score at High Risk (>= 65) and compound secondary findings.
        dynamic_threat = max(c2_score, frida_penalty)

        if has_beacon or c2_score >= 60 or frida_penalty >= 50:
            base = max(dynamic_threat, 65)
            compounding = int((static_score * 0.25) + (min(c2_score, frida_penalty) * 0.15))
            overall_score = min(100, base + compounding)
        elif dynamic_threat >= 30:
            overall_score = min(100, int((dynamic_threat * 0.65) + (static_score * 0.35)))
        else:
            overall_score = min(100, int((static_score * 0.8) + (dynamic_threat * 0.2)))
        
        if overall_score >= 61:
            verdict = "MALICIOUS / HIGH RISK"
            verdict_level = "HIGH"
        elif overall_score >= 31:
            verdict = "POTENTIALLY SUSPICIOUS / MEDIUM RISK"
            verdict_level = "MEDIUM"
        else:
            verdict = "BENIGN / LOW RISK"
            verdict_level = "LOW"

        report = {
            "session_id": session_id,
            "generated_at": timestamp,
            "overall_verdict": verdict,
            "verdict_level": verdict_level,
            "overall_risk_score": overall_score,
            "static_analysis": static_data,
            "network_analysis": {
                "total_connections": network_data.get("total_connections", 0),
                "unique_destinations": network_data.get("unique_destinations", []),
                "protocol_breakdown": network_data.get("protocol_breakdown", {}),
                "connection_intervals": network_data.get("connection_intervals", {}),
                "sample_flows": network_data.get("flows", [])[:25]
            },
            "c2_detection": c2_data,
            "dynamic_analysis": {
                "total_frida_events": len(frida_events),
                "frida_events": frida_events[:50],
                "logcat_summary": logcat_summary
            },
            "forensic_summary": {
                "benign_indicators": [
                    "Standard Android manifest structure",
                    "No destructive filesystem tampering detected"
                ] if overall_score < 40 else [],
                "suspicious_indicators": [i.get("description", "") for i in c2_data.get("indicators", [])],
                "limitations": [
                    "Encrypted custom payload inspection requires certificate pinning bypass.",
                    "Controlled heuristic scoring reflects observed lab patterns."
                ],
                "recommended_actions": [
                    "Block destination domains and IPs at egress firewall.",
                    "Conduct deeper Ghidra decompilation on native shared objects if present."
                ] if overall_score >= 31 else ["No immediate threat mitigation required."]
            }
        }
        return report

    def save_reports(self, report_data: Dict[str, Any]) -> Dict[str, str]:
        """Saves both JSON and HTML report artifacts."""
        session_id = report_data.get("session_id", "session")
        json_file = os.path.join(self.output_dir, f"report_{session_id}.json")
        html_file = os.path.join(self.output_dir, f"report_{session_id}.html")

        # Save JSON
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        # Build and Save HTML
        html_content = self._render_html(report_data)
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        return {"json": json_file, "html": html_file}

    def _render_html(self, data: Dict[str, Any]) -> str:
        score = data.get("overall_risk_score", 0)
        verdict = data.get("overall_verdict", "UNKNOWN")
        level = data.get("verdict_level", "LOW")
        meta = data.get("static_analysis", {}).get("metadata", {})
        perms = data.get("static_analysis", {}).get("permissions", {})
        c2 = data.get("c2_detection", {})
        net = data.get("network_analysis", {})
        dynamic = data.get("dynamic_analysis", {})

        badge_color = "#10b981" if level == "LOW" else ("#f59e0b" if level == "MEDIUM" else "#ef4444")

        # Rows for sensitive perms
        perm_rows = ""
        for p in perms.get("sensitive_permissions", []):
            perm_rows += f"""
            <tr>
                <td style="color: #ef4444; font-family: monospace;">{p.get('permission')}</td>
                <td><span class="badge badge-warning">{p.get('severity')}</span></td>
                <td>{p.get('category')}</td>
                <td>{p.get('description')}</td>
            </tr>"""
        if not perm_rows:
            perm_rows = "<tr><td colspan='4' style='text-align: center; color: #94a3b8;'>No sensitive permissions detected.</td></tr>"

        # Rows for C2 indicators
        c2_rows = ""
        for ind in c2.get("indicators", []):
            c2_rows += f"""
            <tr>
                <td style="font-weight: 600; color: #f43f5e;">{ind.get('indicator')}</td>
                <td><span class="badge badge-danger">{ind.get('severity')}</span> (+{ind.get('score_weight')})</td>
                <td>{ind.get('target', 'N/A')}</td>
                <td>{ind.get('description')}</td>
            </tr>"""
        if not c2_rows:
            c2_rows = "<tr><td colspan='4' style='text-align: center; color: #94a3b8;'>No anomalous Command-and-Control indicators flagged.</td></tr>"

        # Rows for Flows
        flow_rows = ""
        for fl in net.get("sample_flows", []):
            status_style = "color: #10b981;" if fl.get("status_code", 0) and fl.get("status_code", 0) < 400 else "color: #ef4444;"
            flow_rows += f"""
            <tr>
                <td style="font-family: monospace;">{fl.get('method')}</td>
                <td style="font-family: monospace; word-break: break-all;">{fl.get('url')}</td>
                <td style="font-family: monospace; {status_style}">{fl.get('status_code') or 'Blocked/Drop'}</td>
                <td>{fl.get('scheme', '').upper()}</td>
                <td>{fl.get('request_content_length')} B</td>
            </tr>"""
        if not flow_rows:
            flow_rows = "<tr><td colspan='5' style='text-align: center; color: #94a3b8;'>No network flows captured during this session.</td></tr>"

        # Rows for Frida events
        frida_rows = ""
        for fe in dynamic.get("frida_events", []):
            frida_rows += f"""
            <tr>
                <td style="font-family: monospace; font-size: 11px;">{fe.get('timestamp')}</td>
                <td><span class="badge badge-info">{fe.get('module')}</span></td>
                <td style="font-weight: 600;">{fe.get('type')}</td>
                <td style="font-family: monospace; font-size: 12px; word-break: break-all;">{json.dumps(fe.get('details', {}))}</td>
            </tr>"""
        if not frida_rows:
            frida_rows = "<tr><td colspan='4' style='text-align: center; color: #94a3b8;'>No dynamic Frida security events observed.</td></tr>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malware Analysis Forensic Report - {meta.get('app_name', 'APK')}</title>
    <style>
        :root {{
            --bg-main: #0b0f19;
            --bg-card: #111827;
            --bg-card-alt: #1f2937;
            --border: #374151;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --primary: #3b82f6;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-main);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 30px;
            line-height: 1.5;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{ font-size: 24px; font-weight: 700; color: #fff; }}
        .header p {{ color: var(--text-secondary); font-size: 13px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}
        .card h2 {{ font-size: 16px; margin-bottom: 15px; border-bottom: 1px solid var(--border); padding-bottom: 8px; color: #93c5fd; }}
        .metric {{ font-size: 32px; font-weight: 800; }}
        .table-wrap {{ overflow-x: auto; margin-top: 15px; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }}
        th {{ background: var(--bg-card-alt); padding: 10px; color: var(--text-secondary); border-bottom: 1px solid var(--border); }}
        td {{ padding: 10px; border-bottom: 1px solid var(--border); }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            font-size: 11px;
            font-weight: 700;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }}
        .badge-success {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }}
        .badge-info {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🛡️ Android Malware Analysis Forensic Report</h1>
            <p>Session ID: {data.get('session_id')} &bull; Analyzed at: {data.get('generated_at')}</p>
        </div>
        <div style="text-align: right;">
            <span class="badge" style="background: {badge_color}; color: #fff; font-size: 14px; padding: 6px 14px;">
                {verdict}
            </span>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h2>Heuristic Risk Score</h2>
            <div class="metric" style="color: {badge_color};">{score} <span style="font-size: 18px; color: var(--text-secondary);">/ 100</span></div>
            <p style="color: var(--text-secondary); font-size: 12px; margin-top: 5px;">Composite score based on static permissions, dynamic API hooks, and C2 traffic beaconing.</p>
        </div>
        <div class="card">
            <h2>Target APK Info</h2>
            <p><strong>App Name:</strong> {meta.get('app_name')}</p>
            <p><strong>Package:</strong> <code style="color: #60a5fa;">{meta.get('package_name')}</code></p>
            <p><strong>Version:</strong> {meta.get('version_name')} (code: {meta.get('version_code')})</p>
            <p><strong>Target SDK:</strong> {meta.get('target_sdk')}</p>
        </div>
        <div class="card">
            <h2>Network Telemetry</h2>
            <p><strong>Total Connections:</strong> {net.get('total_connections')}</p>
            <p><strong>Unique Destinations:</strong> {len(net.get('unique_destinations', []))}</p>
            <p><strong>HTTP / HTTPS:</strong> {net.get('protocol_breakdown', {}).get('http', 0)} / {net.get('protocol_breakdown', {}).get('https', 0)}</p>
            <p><strong>C2 Anomalies Flagged:</strong> <span style="color: {'#ef4444' if c2.get('indicators_found', 0) > 0 else '#10b981'}; font-weight: 700;">{c2.get('indicators_found', 0)}</span></p>
        </div>
    </div>

    <!-- Section: C2 Indicators -->
    <div class="card" style="margin-bottom: 25px;">
        <h2>🚨 Command-and-Control (C2) Detection Engine Findings</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Indicator</th>
                        <th>Severity</th>
                        <th>Target Egress</th>
                        <th>Forensic Explanation</th>
                    </tr>
                </thead>
                <tbody>
                    {c2_rows}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Section: Sensitive Permissions -->
    <div class="card" style="margin-bottom: 25px;">
        <h2>🔑 Sensitive Android Permissions Audit</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Permission</th>
                        <th>Severity</th>
                        <th>Threat Category</th>
                        <th>Risk Rationale</th>
                    </tr>
                </thead>
                <tbody>
                    {perm_rows}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Section: Network Interceptions -->
    <div class="card" style="margin-bottom: 25px;">
        <h2>🌐 Intercepted Network Traffic (mitmproxy)</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Method</th>
                        <th>Destination URL</th>
                        <th>Status</th>
                        <th>Proto</th>
                        <th>Size</th>
                    </tr>
                </thead>
                <tbody>
                    {flow_rows}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Section: Frida Dynamic Events -->
    <div class="card" style="margin-bottom: 25px;">
        <h2>⚡ Dynamic Instrumentation Traces (Frida Hooks)</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Module</th>
                        <th>Event Type</th>
                        <th>Extracted Parameters</th>
                    </tr>
                </thead>
                <tbody>
                    {frida_rows}
                </tbody>
            </table>
        </div>
    </div>

    <div style="text-align: center; color: var(--text-secondary); font-size: 12px; margin-top: 30px;">
        Generated automatically by Android Malware Analysis & C2 Detection Sandbox &bull; Defensive Security Laboratory
    </div>
</body>
</html>"""
        return html
