import os
import pytest
from sandbox.apk_analyzer import SENSITIVE_PERMISSIONS_DB, APKAnalyzer

def test_sensitive_permissions_db():
    assert "android.permission.SEND_SMS" in SENSITIVE_PERMISSIONS_DB
    assert SENSITIVE_PERMISSIONS_DB["android.permission.SEND_SMS"]["severity"] == "HIGH"
    assert "android.permission.INTERNET" in SENSITIVE_PERMISSIONS_DB
    assert "android.permission.RECEIVE_BOOT_COMPLETED" in SENSITIVE_PERMISSIONS_DB

def test_missing_apk_raises_filenotfound():
    with pytest.raises(FileNotFoundError):
        APKAnalyzer("non_existent_file.apk")
