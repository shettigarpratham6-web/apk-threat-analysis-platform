import os
import json
import pytest
from dashboard import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_dashboard_index(client):
    rv = client.get("/")
    assert rv.status_code == 200
    assert b"Android Malware Analysis & C2 Detection Sandbox" in rv.data

def test_api_status(client):
    rv = client.get("/api/status")
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert "emulator" in data
    assert "is_online" in data
    assert "frida_version" in data
    assert "proxy_port" in data

def test_reports_routing(client):
    # Test serving an existing report
    import glob
    reports = glob.glob("reports/report_session_*.html")
    if reports:
        fname = os.path.basename(reports[0])
        rv = client.get(f"/reports/{fname}")
        assert rv.status_code == 200
        assert b"Malware Analysis Forensic Report" in rv.data
