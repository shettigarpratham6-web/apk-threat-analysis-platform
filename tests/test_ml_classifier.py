"""
Unit and integration tests for the Random Forest Static Malware Classifier.
"""

import json
import os
import pytest
from backend.core.static_analysis.ml_classifier import (
    StaticMalwareClassifier,
    get_static_malware_classifier,
    classify_static_features,
)


def test_classifier_artifacts_exist():
    """Verify all expected ML artifacts have been generated and saved."""
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    model_path = os.path.join(base_dir, "ml", "models", "static_malware_random_forest.pkl")
    features_path = os.path.join(base_dir, "ml", "models", "static_feature_names.json")
    importance_path = os.path.join(base_dir, "ml", "models", "feature_importance.json")
    metrics_path = os.path.join(base_dir, "ml", "models", "evaluation_metrics.json")

    assert os.path.exists(model_path), f"Model artifact not found at {model_path}"
    assert os.path.exists(features_path), f"Features artifact not found at {features_path}"
    assert os.path.exists(importance_path), f"Feature importance not found at {importance_path}"
    assert os.path.exists(metrics_path), f"Evaluation metrics not found at {metrics_path}"


def test_classifier_loaded():
    """Verify that the classifier singleton loads model and feature list."""
    clf = get_static_malware_classifier()
    assert clf.is_ready() is True
    assert len(clf.feature_names) == 215
    assert "SEND_SMS" in clf.feature_names
    assert "READ_PHONE_STATE" in clf.feature_names
    assert "android.os.Binder" in clf.feature_names


def test_predict_clean_vector():
    """A sample with zero dangerous features should be classified as benign."""
    clf = get_static_malware_classifier()
    clean_vector = {feat: 0 for feat in clf.feature_names}
    res = clf.predict(clean_vector)

    assert "prediction" in res
    assert "malware_probability" in res
    assert "benign_probability" in res
    assert res["prediction"] == "benign"
    assert res["benign_probability"] > 0.5
    assert res["malware_probability"] < 0.5
    assert abs((res["malware_probability"] + res["benign_probability"]) - 1.0) < 0.01


def test_predict_malicious_vector():
    """A sample with multiple high-risk malware indicators should be classified as malware."""
    clf = get_static_malware_classifier()
    mal_vector = {feat: 0 for feat in clf.feature_names}
    mal_features = [
        "SEND_SMS",
        "READ_PHONE_STATE",
        "transact",
        "attachInterface",
        "android.os.Binder",
        "TelephonyManager.getDeviceId",
        "TelephonyManager.getSubscriberId",
        "Ljava.lang.Class.getCanonicalName",
    ]
    for feat in mal_features:
        if feat in mal_vector:
            mal_vector[feat] = 1

    res = clf.predict(mal_vector)
    assert res["prediction"] == "malware"
    assert res["malware_probability"] > 0.5


def test_extract_feature_vector_from_static_analysis():
    """Verify feature vector mapping from existing static analysis output dicts."""
    clf = get_static_malware_classifier()
    manifest_results = {
        "permissions": [
            {"name": "android.permission.SEND_SMS", "severity": "Critical"},
            {"name": "android.permission.INTERNET", "severity": "Normal"},
            {"name": "android.permission.READ_PHONE_STATE", "severity": "High"},
        ],
        "components": {
            "receivers": [
                {
                    "name": "BootReceiver",
                    "intent_filters": ["android.intent.action.BOOT_COMPLETED"],
                }
            ]
        },
    }
    code_results = {
        "suspicious_apis": [
            {"api": "DexClassLoader", "severity": "High"},
            {"api": "Runtime.exec", "severity": "Medium"},
        ],
        "malware_indicators": [
            {"why_flagged": "Shell command execution: /system/bin/sh"}
        ],
    }

    feature_vector = clf.extract_feature_vector_from_static_analysis(
        manifest_results=manifest_results,
        code_results=code_results,
    )

    assert len(feature_vector) == 215
    assert feature_vector["SEND_SMS"] == 1
    assert feature_vector["INTERNET"] == 1
    assert feature_vector["READ_PHONE_STATE"] == 1
    assert feature_vector["android.intent.action.BOOT_COMPLETED"] == 1
    assert feature_vector["DexClassLoader"] == 1
    assert feature_vector["Runtime.exec"] == 1
    assert feature_vector["/system/bin"] == 1


def test_convenience_function():
    """Test classify_static_features wrapper."""
    clf = get_static_malware_classifier()
    zero_vec = [0] * len(clf.feature_names)
    res = classify_static_features(zero_vec)
    assert res["prediction"] == "benign"
    assert "malware_probability" in res
