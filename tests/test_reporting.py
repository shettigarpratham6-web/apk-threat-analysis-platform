"""Unit and integration tests for forensic report generation and reporting endpoints."""

import json
import os
from fastapi.testclient import TestClient

from backend.main import app
from backend.app.reporting.report_generator import generate_report

client = TestClient(app)


def test_generate_report_pdf_and_html():
    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "results"))
    os.makedirs(results_dir, exist_ok=True)

    test_apk_id = "test_report_eval_7777"
    correlation_file = os.path.join(results_dir, f"{test_apk_id}_correlation.json")
    html_file = os.path.join(results_dir, f"{test_apk_id}_report.html")
    pdf_file = os.path.join(results_dir, f"{test_apk_id}_report.pdf")

    # Mock correlation artifact
    correlation_data = {
        "apk_id": test_apk_id,
        "package_name": "com.test.forensicapp",
        "risk_assessment": {
            "risk_score": 85,
            "risk_label": "Critical Risk",
            "score_breakdown": {"dangerous_permissions_score": 30, "c2_hosts_score": 35},
            "contributing_factors": [
                "Requested 3 dangerous permissions (SEND_SMS, READ_CONTACTS)",
                "Identified 1 high-confidence C2 host (198.51.100.45)"
            ]
        },
        "static_summary": {"package_name": "com.test.forensicapp"},
        "dynamic_summary": {"network_entries_count": 5},
        "c2_summary": {"suspected_c2_hosts_count": 1},
        "server_summary": {"checked_servers_count": 1}
    }

    with open(correlation_file, "w", encoding="utf-8") as cf:
        json.dump(correlation_data, cf)

    try:
        pdf_path = generate_report(test_apk_id)

        assert os.path.exists(html_file), "HTML report artifact must exist"
        assert os.path.exists(pdf_file), "PDF report artifact must exist"
        assert pdf_path == pdf_file

        with open(html_file, "r", encoding="utf-8") as hf:
            html_content = hf.read()
            assert "com.test.forensicapp" in html_content
            assert "Critical Risk" in html_content
            assert "85 / 100" in html_content
    finally:
        for p in [correlation_file, html_file, pdf_file]:
            if os.path.exists(p):
                os.remove(p)


def test_xss_prevention_in_html_report():
    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "results"))
    os.makedirs(results_dir, exist_ok=True)

    test_apk_id = "77777777-7777-7777-7777-777777777777"
    correlation_file = os.path.join(results_dir, f"{test_apk_id}_correlation.json")
    html_file = os.path.join(results_dir, f"{test_apk_id}_report.html")
    pdf_file = os.path.join(results_dir, f"{test_apk_id}_report.pdf")

    xss_payload = "<script>alert(1)</script>"
    correlation_data = {
        "apk_id": test_apk_id,
        "package_name": xss_payload,
        "manifest_analysis": {
            "metadata": {"package_name": xss_payload}
        },
        "risk_assessment": {
            "risk_score": 50,
            "risk_label": "Medium Risk",
            "contributing_factors": [f"Suspicious activity in {xss_payload}"]
        }
    }

    with open(correlation_file, "w", encoding="utf-8") as cf:
        json.dump(correlation_data, cf)

    try:
        generate_report(test_apk_id)
        assert os.path.exists(html_file)

        with open(html_file, "r", encoding="utf-8") as hf:
            rendered = hf.read()

        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
        assert "<script>alert(1)</script>" not in rendered

        view_res = client.get(f"/api/report/{test_apk_id}/view")
        assert view_res.status_code == 200
        assert "default-src 'none'" in view_res.headers.get("content-security-policy", "")
        assert view_res.headers.get("x-content-type-options") == "nosniff"
    finally:
        for p in [correlation_file, html_file, pdf_file]:
            if os.path.exists(p):
                os.remove(p)



def test_reporting_api_endpoints():
    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "results"))
    os.makedirs(results_dir, exist_ok=True)

    test_apk_id = "66666666-6666-6666-6666-666666666666"
    correlation_file = os.path.join(results_dir, f"{test_apk_id}_correlation.json")
    html_file = os.path.join(results_dir, f"{test_apk_id}_report.html")
    pdf_file = os.path.join(results_dir, f"{test_apk_id}_report.pdf")

    correlation_data = {
        "apk_id": test_apk_id,
        "package_name": "com.test.routeapp",
        "risk_assessment": {
            "risk_score": 40,
            "risk_label": "Medium Risk",
            "contributing_factors": ["Detected 2 suspicious API calls"]
        }
    }

    with open(correlation_file, "w", encoding="utf-8") as cf:
        json.dump(correlation_data, cf)

    try:
        # 1. POST /api/report/generate
        gen_res = client.post("/api/report/generate", data={"apk_id": test_apk_id})
        assert gen_res.status_code == 200
        gen_data = gen_res.json()
        assert gen_data["apk_id"] == test_apk_id

        # 2. GET /api/report/{apk_id}/view
        view_res = client.get(f"/api/report/{test_apk_id}/view")
        assert view_res.status_code == 200
        assert "text/html" in view_res.headers.get("content-type", "")
        assert "com.test.routeapp" in view_res.text

        # 3. GET /api/report/{apk_id}/download
        dl_res = client.get(f"/api/report/{test_apk_id}/download")
        assert dl_res.status_code == 200
        assert "application/pdf" in dl_res.headers.get("content-type", "")
    finally:
        for p in [correlation_file, html_file, pdf_file]:
            if os.path.exists(p):
                os.remove(p)

