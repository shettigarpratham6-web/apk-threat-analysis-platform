"""Unit and integration tests for static analysis endpoints and correlation engine."""

import os
import sys
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.app.static_analysis.aggregator import calculate_risk
from backend.app.static_analysis.apk_loader import extract_apk

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_extract_apk_nonexistent_file():
    with pytest.raises(ValueError, match="not found"):
        extract_apk("non_existent_file.apk")


def test_extract_apk_invalid_file(tmp_path):
    invalid_file = tmp_path / "corrupted.apk"
    invalid_file.write_bytes(b"not a real zip or apk content")

    with pytest.raises(ValueError):
        extract_apk(str(invalid_file))


def test_upload_endpoint_invalid_file_extension():
    response = client.post(
        "/api/static-analysis/upload",
        files={"file": ("test.txt", b"dummy content", "text/plain")}
    )
    assert response.status_code == 400
    assert "Invalid file format" in response.json()["detail"]


def test_risk_correlation_engine_critical():
    manifest = {
        "permissions": [
            {"name": "android.permission.SYSTEM_ALERT_WINDOW", "severity": "Critical"}
        ],
        "security_flags": {"debuggable": True}
    }
    code = {
        "suspicious_apis": [{"api": "DexClassLoader", "severity": "High"}],
        "malware_indicators": [{"why_flagged": "/system/bin/sh", "severity": "Critical"}]
    }
    resources = {"secrets": [{"type": "AWS Key"}]}
    natives = {"suspicious_libraries": [{"name": "libpacked.so"}]}
    yara = [{"rule_name": "BankBot", "severity": "High"}]

    risk = calculate_risk(manifest, code, resources, natives, yara)
    
    assert risk["score"] >= 80
    assert risk["level"] == "Critical"
    assert "App is debuggable (android:debuggable=true)" in risk["factors"]
    assert len(risk["recommendations"]) > 0


def test_risk_correlation_engine_safe():
    manifest = {"permissions": [], "security_flags": {}}
    code = {}
    resources = {}
    natives = {}
    yara = []

    risk = calculate_risk(manifest, code, resources, natives, yara)
    
    assert risk["score"] == 0
    assert risk["level"] == "Safe"
    assert len(risk["factors"]) == 0


@patch("backend.app.routes.static_analysis.extract_apk_securely")
@patch("backend.app.routes.static_analysis.hash_file")
@patch("shutil.copyfileobj")
@patch("os.path.getsize")
def test_analyze_api_file_too_large(mock_getsize, mock_copy, mock_hash, mock_extract):
    mock_getsize.return_value = 200 * 1024 * 1024 + 1
    
    with patch("os.remove"):
        response = client.post(
            "/api/static-analysis/analyze",
            files={"file": ("malware.apk", b"dummy content", "application/vnd.android.package-archive")}
        )
        assert response.status_code == 413
        assert "exceeds the 200MB limit" in response.json()["detail"]


@patch("backend.app.routes.static_analysis.extract_apk_securely")
@patch("backend.app.routes.static_analysis.hash_file")
@patch("backend.app.routes.static_analysis.analyze_manifest")
@patch("backend.app.routes.static_analysis.analyze_code")
@patch("backend.app.routes.static_analysis.analyze_resources")
@patch("backend.app.routes.static_analysis.analyze_native_libs")
@patch("backend.app.routes.static_analysis.run_yara_scan")
@patch("shutil.copyfileobj")
@patch("os.path.getsize")
def test_analyze_api_success_schema(mock_getsize, mock_copy, mock_yara, mock_native, mock_resource, mock_code, mock_manifest, mock_hash, mock_extract):
    mock_getsize.return_value = 1024 * 1024
    mock_hash.return_value = {"sha256": "fake256", "md5": "fake_md5"}
    
    mock_manifest.return_value = {"metadata": {"package_name": "com.test.app"}}
    mock_code.return_value = {"suspicious_apis": []}
    mock_resource.return_value = {"secrets": []}
    mock_native.return_value = {"architectures": ["arm64-v8a"]}
    mock_yara.return_value = []
    
    with patch("builtins.open", MagicMock()):
        response = client.post(
            "/api/static-analysis/analyze",
            files={"file": ("clean_app.apk", b"PK...", "application/vnd.android.package-archive")}
        )
        
    assert response.status_code == 200
    data = response.json()
    assert "apk_id" in data
    assert "metadata" in data
    assert "manifest_analysis" in data
    assert "risk_analysis" in data
    assert "ml_classification" in data
    
    # Verify Risk Analysis structure
    assert data["risk_analysis"]["level"] == "Safe"
    assert data["risk_analysis"]["score"] == 0
