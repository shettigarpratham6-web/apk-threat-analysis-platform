"""Unit and integration tests for dynamic analysis sandbox endpoints and SandboxManager."""

import os
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from backend.main import app
from backend.app.dynamic_analysis.sandbox_manager import SandboxManager

client = TestClient(app)


def test_sandbox_manager_config():
    manager = SandboxManager()
    assert manager.avd_name is not None
    assert manager.snapshot_name is not None


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


def test_start_sandbox_timeout_error():
    with patch("backend.app.routes.dynamic_analysis.sandbox.start_emulator") as mock_start, \
         patch("backend.app.routes.dynamic_analysis.sandbox.wait_until_ready") as mock_wait:
        mock_start.return_value = None
        mock_wait.side_effect = TimeoutError("Emulator readiness timed out.")

        response = client.post("/api/dynamic-analysis/sandbox/start")
        assert response.status_code == 504
        assert "timed out" in response.json()["detail"]
