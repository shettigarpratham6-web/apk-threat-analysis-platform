"""Unit and integration tests for static analysis manifest, code scan, signature check, and unified analyze endpoints."""

import os
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.app.static_analysis.apk_loader import extract_apk
from backend.app.static_analysis.manifest_check import analyze_manifest
from backend.app.static_analysis.code_analysis import analyze_code
from backend.app.static_analysis.signature_check import run_yara_scan, check_virustotal
from backend.app.static_analysis.aggregator import run_static_analysis

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_extract_apk_nonexistent_file():
    with pytest.raises(ValueError, match="file not found"):
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


def test_upload_endpoint_corrupted_apk():
    response = client.post(
        "/api/static-analysis/upload",
        files={"file": ("corrupted.apk", b"corrupted apk content", "application/vnd.android.package-archive")}
    )
    assert response.status_code == 422


def test_upload_sample_apk():
    sample_apk_path = "datasets/benign/sample.apk"
    assert os.path.exists(sample_apk_path), "sample.apk must exist in datasets/benign/"

    with open(sample_apk_path, "rb") as f:
        response = client.post(
            "/api/static-analysis/upload",
            files={"file": ("sample.apk", f, "application/vnd.android.package-archive")}
        )

    assert response.status_code == 200
    data = response.json()

    assert data["package_name"] == "com.example.threattest"
    assert data["main_activity"] == "com.example.threattest.MainActivity"
    assert "android.permission.INTERNET" in data["permissions"]["requested"]
    assert "android.permission.READ_CONTACTS" in data["permissions"]["dangerous"]


def test_code_scan_sample_apk():
    sample_apk_path = "datasets/benign/sample.apk"
    assert os.path.exists(sample_apk_path), "sample.apk must exist in datasets/benign/"

    with open(sample_apk_path, "rb") as f:
        response = client.post(
            "/api/static-analysis/code-scan",
            files={"file": ("sample.apk", f, "application/vnd.android.package-archive")}
        )

    assert response.status_code == 200
    data = response.json()

    assert "urls" in data
    assert "ip_addresses" in data
    assert "suspicious_apis" in data


def test_signature_check_sample_apk():
    sample_apk_path = "datasets/benign/sample.apk"
    assert os.path.exists(sample_apk_path), "sample.apk must exist in datasets/benign/"

    with open(sample_apk_path, "rb") as f:
        response = client.post(
            "/api/static-analysis/signature-check",
            files={"file": ("sample.apk", f, "application/vnd.android.package-archive")}
        )

    assert response.status_code == 200
    data = response.json()

    assert "yara_matches" in data
    assert "virustotal" in data


def test_unified_analyze_sample_apk():
    sample_apk_path = "datasets/benign/sample.apk"
    assert os.path.exists(sample_apk_path), "sample.apk must exist in datasets/benign/"

    with open(sample_apk_path, "rb") as f:
        response = client.post(
            "/api/static-analysis/analyze",
            files={"file": ("sample.apk", f, "application/vnd.android.package-archive")}
        )

    assert response.status_code == 200
    payload = response.json()

    assert "apk_id" in payload
    apk_id = payload["apk_id"]
    static_analysis = payload["static_analysis"]

    # Verify top-level structure
    assert static_analysis["package_name"] == "com.example.threattest"
    assert "manifest" in static_analysis
    assert "code_analysis" in static_analysis
    assert "signature_check" in static_analysis
    assert "static_risk_indicators" in static_analysis

    # Verify sub-results
    assert len(static_analysis["static_risk_indicators"]) > 0
    assert any("YARA" in ind or "IPv4" in ind or "URL" in ind for ind in static_analysis["static_risk_indicators"])

    # Verify JSON result file persistence in backend/results/<apk_id>_static.json
    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "results"))
    persisted_file = os.path.join(results_dir, f"{apk_id}_static.json")
    assert os.path.exists(persisted_file), f"Result JSON file {persisted_file} must exist!"
