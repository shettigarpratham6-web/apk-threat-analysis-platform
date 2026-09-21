"""Unit and integration tests for dynamic analysis sandbox endpoints, ApkRunner, FridaMonitor, NetworkMonitor, and monitor route."""

import json
import os
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from backend.main import app
from backend.app.dynamic_analysis.sandbox_manager import SandboxManager
from backend.app.dynamic_analysis.apk_runner import ApkRunner
from backend.app.dynamic_analysis.network_monitor import NetworkMonitor
from backend.app.dynamic_analysis.frida_monitor import FridaMonitor

client = TestClient(app)


def test_sandbox_manager_config():
    manager = SandboxManager()
    assert manager.avd_name is not None
    assert manager.snapshot_name is not None


def test_apk_runner_package_extraction():
    sample_apk = "datasets/benign/sample.apk"
    assert os.path.exists(sample_apk), "sample.apk must exist in datasets/benign/"

    runner = ApkRunner()
    pkg_name = runner.get_package_name(sample_apk)
    assert pkg_name == "com.example.threattest"


def test_network_monitor_parse_log(tmp_path):
    log_file = tmp_path / "test_traffic.jsonl"
    entry1 = {"timestamp": 123, "method": "GET", "host": "example.com", "path": "/", "status_code": 200}
    entry2 = {"timestamp": 124, "method": "POST", "host": "c2.org", "path": "/api", "status_code": 404}
    log_file.write_text(json.dumps(entry1) + "\n" + json.dumps(entry2) + "\n")

    monitor = NetworkMonitor()
    entries = monitor.parse_log(str(log_file))
    assert len(entries) == 2
    assert entries[0]["host"] == "example.com"
    assert entries[1]["host"] == "c2.org"


def test_frida_monitor_event_categorization():
    monitor = FridaMonitor()
    monitor._on_message(
        {"type": "send", "payload": {"category": "file_activity", "api": "FileOutputStream", "args": ["/sdcard/stolen.txt"]}},
        None
    )
    monitor._on_message(
        {"type": "send", "payload": {"category": "api_calls", "api": "sendTextMessage", "args": ["+123456789", "leak"]}},
        None
    )

    events = monitor.get_events()
    assert len(events["file_activity"]) == 1
    assert len(events["api_calls"]) == 1
    assert events["file_activity"][0]["api"] == "FileOutputStream"
    assert events["api_calls"][0]["api"] == "sendTextMessage"


def test_start_sandbox_mocked():
    with patch("backend.app.routes.dynamic_analysis.sandbox.start_emulator") as mock_start, \
         patch("backend.app.routes.dynamic_analysis.sandbox.wait_until_ready") as mock_wait:
        mock_start.return_value = None
        mock_wait.return_value = True

        response = client.post("/api/dynamic-analysis/sandbox/start")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"


def test_stop_sandbox_mocked():
    with patch("backend.app.routes.dynamic_analysis.sandbox.stop_emulator") as mock_stop:
        mock_stop.return_value = None

        response = client.post("/api/dynamic-analysis/sandbox/stop")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "stopped"


def test_run_apk_safely_mocked():
    sample_apk = "datasets/benign/sample.apk"
    with patch("backend.app.routes.dynamic_analysis.sandbox.run_full_dynamic_prep") as mock_prep:
        mock_prep.return_value = {
            "package_name": "com.example.threattest",
            "status": "running"
        }

        with open(sample_apk, "rb") as f:
            response = client.post(
                "/api/dynamic-analysis/run",
                files={"file": ("sample.apk", f, "application/vnd.android.package-archive")}
            )

        assert response.status_code == 200
        data = response.json()
        assert data["package_name"] == "com.example.threattest"
        assert data["status"] == "running"
        assert "apk_id" in data


def test_monitor_endpoint_mocked():
    with patch("backend.app.routes.dynamic_analysis.sandbox.monitor_behavior") as mock_monitor:
        mock_monitor.return_value = {
            "network_traffic": [
                {"timestamp": 100, "method": "GET", "url": "http://api.threat-c2.com/connect", "status_code": 200}
            ],
            "file_activity": [
                {"category": "file_activity", "api": "FileOutputStream", "args": ["/sdcard/log.txt"]}
            ],
            "api_calls": [
                {"category": "api_calls", "api": "SmsManager.sendTextMessage", "args": ["+15550001", "test"]}
            ]
        }

        response = client.post(
            "/api/dynamic-analysis/monitor",
            data={
                "apk_id": "test_uuid_12345",
                "package_name": "com.example.threattest",
                "duration": 1
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["apk_id"] == "test_uuid_12345"
        assert data["package_name"] == "com.example.threattest"

        dynamic = data["dynamic_analysis"]
        assert len(dynamic["network_traffic"]) == 1
        assert len(dynamic["file_activity"]) == 1
        assert len(dynamic["api_calls"]) == 1

        # Verify result JSON file persistence in backend/results/test_uuid_12345_dynamic.json
        results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "results"))
        persisted_file = os.path.join(results_dir, "test_uuid_12345_dynamic.json")
        assert os.path.exists(persisted_file), f"Result JSON file {persisted_file} must exist!"


def test_detect_c2_heuristics():
    from backend.app.dynamic_analysis.c2_detection import detect_c2

    # Craft dynamic traffic to match 3+ heuristics (high confidence):
    # 1. Raw IP address (198.51.100.45)
    # 2. Non-standard port (8080)
    # 3. Regular beaconing interval (every 10s: t=100, 110, 120, 130)
    # 4. Small POST payloads (128 bytes)
    mock_traffic = [
        {"timestamp": 100.0, "method": "POST", "host": "198.51.100.45", "port": 8080, "path": "/checkin", "request_size": 128},
        {"timestamp": 110.0, "method": "POST", "host": "198.51.100.45", "port": 8080, "path": "/checkin", "request_size": 128},
        {"timestamp": 120.0, "method": "POST", "host": "198.51.100.45", "port": 8080, "path": "/checkin", "request_size": 128},
        {"timestamp": 130.0, "method": "POST", "host": "198.51.100.45", "port": 8080, "path": "/checkin", "request_size": 128},
    ]

    mock_static = {
        "urls": ["http://198.51.100.45:8080/checkin"],
        "ip_addresses": ["198.51.100.45"]
    }

    results = detect_c2(mock_traffic, mock_static)
    assert "suspected_c2_hosts" in results
    assert len(results["suspected_c2_hosts"]) >= 1

    c2_host = results["suspected_c2_hosts"][0]
    assert c2_host["host"] == "198.51.100.45"
    assert c2_host["confidence"] == "high"
    assert len(c2_host["reasons"]) >= 3


def test_sandbox_run_c2_detection():
    manager = SandboxManager()
    dynamic_data = {
        "network_traffic": [
            {"timestamp": 10, "method": "GET", "host": "203.0.113.5", "port": 9000, "request_size": 50},
            {"timestamp": 15, "method": "GET", "host": "203.0.113.5", "port": 9000, "request_size": 50},
        ]
    }
    static_data = {
        "code_analysis": {
            "urls": ["http://203.0.113.5:9000/cmd"],
            "ip_addresses": ["203.0.113.5"]
        }
    }

    res = manager.run_c2_detection(dynamic_data, static_data)
    assert "suspected_c2_hosts" in res
    assert len(res["suspected_c2_hosts"]) >= 1


def test_c2_detect_endpoint(tmp_path):
    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "results"))
    os.makedirs(results_dir, exist_ok=True)

    test_apk_id = "test_c2_eval_9999"
    dynamic_path = os.path.join(results_dir, f"{test_apk_id}_dynamic.json")
    static_path = os.path.join(results_dir, f"{test_apk_id}_static.json")

    dynamic_content = {
        "apk_id": test_apk_id,
        "dynamic_analysis": {
            "network_traffic": [
                {"timestamp": 100, "method": "POST", "host": "192.0.2.1", "port": 4444, "request_size": 64},
                {"timestamp": 110, "method": "POST", "host": "192.0.2.1", "port": 4444, "request_size": 64},
                {"timestamp": 120, "method": "POST", "host": "192.0.2.1", "port": 4444, "request_size": 64},
            ]
        }
    }

    with open(dynamic_path, "w", encoding="utf-8") as df:
        json.dump(dynamic_content, df)

    try:
        response = client.post(
            "/api/dynamic-analysis/c2-detect",
            data={"apk_id": test_apk_id}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["apk_id"] == test_apk_id
        assert "suspected_c2_hosts" in data
        assert len(data["suspected_c2_hosts"]) >= 1
        assert data["suspected_c2_hosts"][0]["host"] == "192.0.2.1"
        assert data["suspected_c2_hosts"][0]["confidence"] in ("medium", "high")

        # Verify backend/results/<apk_id>_c2.json output
        c2_saved_path = os.path.join(results_dir, f"{test_apk_id}_c2.json")
        assert os.path.exists(c2_saved_path)
    finally:
        for p in [dynamic_path, static_path, os.path.join(results_dir, f"{test_apk_id}_c2.json")]:
            if os.path.exists(p):
                os.remove(p)


def test_server_reputation_checks():
    from backend.app.dynamic_analysis.server_reputation import (
        check_ip_reputation,
        check_domain_reputation,
        check_all,
    )

    # 1. Private IP should be skipped and marked clean
    priv_res = check_ip_reputation("127.0.0.1")
    assert priv_res["verdict"] == "clean"
    assert priv_res["status"] == "skipped"

    # 2. Public IP without API key should be marked unverified
    pub_res = check_ip_reputation("8.8.8.8")
    assert pub_res["verdict"] == "unverified"

    # 3. Domain without API key should be marked unverified
    dom_res = check_domain_reputation("suspicious-domain.com")
    assert dom_res["verdict"] == "unverified"

    # 4. check_all on mixed hosts
    all_res = check_all([
        {"host": "127.0.0.1"},
        {"host": "8.8.8.8"},
        {"host": "bad-c2-server.net"}
    ])
    assert "checked" in all_res
    assert len(all_res["checked"]) == 3
    verdicts = [item["verdict"] for item in all_res["checked"]]
    assert "clean" in verdicts
    assert "unverified" in verdicts



def test_check_servers_endpoint():
    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "results"))
    os.makedirs(results_dir, exist_ok=True)

    test_apk_id = "test_servers_eval_8888"
    c2_path = os.path.join(results_dir, f"{test_apk_id}_c2.json")
    servers_path = os.path.join(results_dir, f"{test_apk_id}_servers.json")

    c2_content = {
        "apk_id": test_apk_id,
        "suspected_c2_hosts": [
            {"host": "10.0.2.15", "reasons": ["Internal"], "confidence": "low"},
            {"host": "203.0.113.50", "reasons": ["Raw IP"], "confidence": "low"},
            {"host": "evil-tracker.org", "reasons": ["Non-standard port"], "confidence": "medium"},
        ]
    }

    with open(c2_path, "w", encoding="utf-8") as cf:
        json.dump(c2_content, cf)

    try:
        response = client.post(
            "/api/dynamic-analysis/check-servers",
            data={"apk_id": test_apk_id}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["apk_id"] == test_apk_id
        assert "checked" in data
        assert len(data["checked"]) == 3

        hosts_checked = [item["host"] for item in data["checked"]]
        assert "10.0.2.15" in hosts_checked
        assert "203.0.113.50" in hosts_checked
        assert "evil-tracker.org" in hosts_checked

        # Verify backend/results/<apk_id>_servers.json output
        assert os.path.exists(servers_path)
    finally:
        for p in [c2_path, servers_path]:
            if os.path.exists(p):
                os.remove(p)


