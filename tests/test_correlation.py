"""Unit and integration tests for correlation and risk scoring module."""

import json
import os
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.app.correlation.risk_scoring import compute_risk_score
from backend.app.correlation.aggregator import correlate_apk

client = TestClient(app)


def test_compute_risk_score_calculation():
    mock_static = {
        "manifest": {
            "declared_dangerous_permissions": [
                "android.permission.SEND_SMS",
                "android.permission.READ_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.RECORD_AUDIO",
            ]
        },
        "code_analysis": {
            "suspicious_apis": [
                {"api": "Runtime.exec"},
                {"api": "Cipher.getInstance"},
            ]
        },
        "signature_check": {
            "yara_matches": [
                {"rule": "generic_android_malware"},
            ],
            "virustotal": {
                "positives": 5,
            }
        }
    }

    mock_c2 = {
        "suspected_c2_hosts": [
            {"host": "198.51.100.45", "confidence": "high"},
            {"host": "bad-domain.net", "confidence": "medium"},
        ]
    }

    mock_servers = {
        "checked": [
            {"host": "198.51.100.45", "verdict": "malicious"},
            {"host": "bad-domain.net", "verdict": "suspicious"},
        ]
    }

    res = compute_risk_score(mock_static, {}, mock_c2, mock_servers)

    assert "risk_score" in res
    assert "risk_label" in res
    assert "score_breakdown" in res
    assert "contributing_factors" in res

    # 30 (perms capped) + 25 (yara) + 30 (vt) + 10 (apis) + 55 (c2: 35+20) + 35 (servers: 25+10) = 185 -> clamped to 100
    assert res["risk_score"] == 100
    assert res["risk_label"] == "Critical Risk"
    assert len(res["contributing_factors"]) >= 5


def test_correlate_apk_graceful_missing_files():
    # Calling correlate_apk with non-existent ID should return clean/low risk gracefully
    res = correlate_apk("non_existent_apk_id_9999")
    assert res["apk_id"] == "non_existent_apk_id_9999"
    assert "risk_assessment" in res
    assert res["risk_assessment"]["risk_score"] == 0
    assert res["risk_assessment"]["risk_label"] == "Low Risk"


def test_correlation_analyze_endpoint():
    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "results"))
    os.makedirs(results_dir, exist_ok=True)

    test_apk_id = "test_correlation_9999"
    static_file = os.path.join(results_dir, f"{test_apk_id}_static.json")
    dynamic_file = os.path.join(results_dir, f"{test_apk_id}_dynamic.json")
    c2_file = os.path.join(results_dir, f"{test_apk_id}_c2.json")
    servers_file = os.path.join(results_dir, f"{test_apk_id}_servers.json")
    correlation_file = os.path.join(results_dir, f"{test_apk_id}_correlation.json")

    # Create dummy stage output files
    with open(static_file, "w", encoding="utf-8") as f:
        json.dump({"apk_id": test_apk_id, "manifest": {"package_name": "com.test.threat", "declared_dangerous_permissions": ["SEND_SMS"]}}, f)

    with open(c2_file, "w", encoding="utf-8") as f:
        json.dump({"apk_id": test_apk_id, "suspected_c2_hosts": [{"host": "192.0.2.1", "confidence": "high"}]}, f)

    try:
        response = client.post(
            "/api/correlation/analyze",
            data={"apk_id": test_apk_id}
        )

        assert response.status_code == 200
        data = response.json()

        assert data["apk_id"] == test_apk_id
        assert data["package_name"] == "com.test.threat"
        assert "risk_assessment" in data
        assert data["risk_assessment"]["risk_score"] > 0
        assert len(data["risk_assessment"]["contributing_factors"]) >= 1

        assert os.path.exists(correlation_file)
    finally:
        for p in [static_file, dynamic_file, c2_file, servers_file, correlation_file]:
            if os.path.exists(p):
                os.remove(p)


def test_confirmed_threats_multi_vector_correlation():
    # Test correlation engine combining static permissions and dynamic Frida SMS/exec activity
    mock_static = {
        "manifest": {
            "declared_dangerous_permissions": ["android.permission.SEND_SMS"],
        },
        "code_analysis": {
            "suspicious_apis": [{"api": "Runtime.exec"}],
        },
        "signature_check": {
            "yara_matches": [],
            "virustotal": {"positives": 0}
        }
    }

    mock_dynamic = {
        "frida_events": {
            "sms_interceptions": [{"destination": "1234", "message": "spy"}],
            "process_executions": [{"command": "su -c ls"}],
            "dynamic_dex_loads": [{"dexPath": "/tmp/dropped.apk"}],
        }
    }

    mock_c2 = {
        "suspected_c2_hosts": [
            {"host": "evil-c2.cc", "confidence": "high", "reasons": ["Beaconing"]}
        ],
        "dga_detections": [
            {"domain": "evil-c2.cc", "entropy": 3.8}
        ]
    }

    mock_servers = {
        "checked": [
            {"host": "evil-c2.cc", "verdict": "malicious"}
        ]
    }

    # Test scoring with confirmed_threats parameter
    res = compute_risk_score(
        mock_static,
        mock_dynamic,
        mock_c2,
        mock_servers,
        confirmed_threats=["Confirmed SMS Trojan", "Active Shell Execution"]
    )
    assert res["risk_score"] >= 80
    assert "score_breakdown" in res
    assert "correlated_threats_score" in res["score_breakdown"]
    assert res["score_breakdown"]["correlated_threats_score"] == 30

    # Test confirmed threats in correlate_apk via aggregator logic
    from backend.app.correlation.aggregator import correlate_apk

    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "results"))
    os.makedirs(results_dir, exist_ok=True)
    test_id = "test_confirmed_multi_vector"

    s_file = os.path.join(results_dir, f"{test_id}_static.json")
    d_file = os.path.join(results_dir, f"{test_id}_dynamic.json")
    c_file = os.path.join(results_dir, f"{test_id}_c2.json")
    srv_file = os.path.join(results_dir, f"{test_id}_servers.json")

    with open(s_file, "w") as f:
        json.dump(mock_static, f)
    with open(d_file, "w") as f:
        json.dump(mock_dynamic, f)
    with open(c_file, "w") as f:
        json.dump(mock_c2, f)
    with open(srv_file, "w") as f:
        json.dump(mock_servers, f)

    try:
        corr = correlate_apk(test_id)
        assert "confirmed_threats" in corr
        assert any("SMS Trojan" in t for t in corr["confirmed_threats"])
        assert any("Shell Execution" in t for t in corr["confirmed_threats"])
        assert any("Dynamic Dropper" in t for t in corr["confirmed_threats"])
        assert any("DGA" in t for t in corr["confirmed_threats"])
        assert "unified_threat_narrative" in corr
    finally:
        for p in [s_file, d_file, c_file, srv_file, os.path.join(results_dir, f"{test_id}_correlation.json")]:
            if os.path.exists(p):
                os.remove(p)

