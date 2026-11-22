from backend.core.static_analysis.risk_engine import Features, score_features

SIGNED = {"v1": True, "v2": True, "v3": True, "debug": False, "unsigned": False, "sha256": ["aa"]}
FLAGS = {"debuggable": False, "allow_backup": True, "cleartext_traffic": False, "test_only": False}


def _grocery(evidence, perms=None):
    return Features(
        package="com.grofers.customerapp", label="Blinkit", category="delivery_shopping",
        permissions=perms or ["INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_FINE_LOCATION",
                              "ACCESS_COARSE_LOCATION", "CAMERA", "POST_NOTIFICATIONS", "READ_CONTACTS",
                              "READ_PHONE_STATE", "READ_SMS", "WAKE_LOCK", "VIBRATE"],
        evidence_groups=evidence, signature=SIGNED, flags=FLAGS, exposure_points=1.5, min_sdk=24)


def test_trusted_grocery_app_is_not_high_risk():
    r = score_features(_grocery({"location", "camera", "contacts", "phone", "sms"}))
    assert r["overall"] < 25 and r["level"] in ("CLEAN", "LOW")


def test_grocery_without_code_evidence_still_not_critical():
    r = score_features(_grocery(set()))
    assert r["overall"] < 35


def test_unneeded_permissions_are_flagged_for_flashlight_app():
    f = Features(package="com.x.flashlight", category="utility_simple",
                 permissions=["CAMERA", "READ_SMS", "READ_CONTACTS", "ACCESS_FINE_LOCATION", "INTERNET"],
                 signature=SIGNED, flags=FLAGS)
    r = score_features(f)
    flagged = set(r["flagged_permissions"])
    assert {"READ_SMS", "READ_CONTACTS", "ACCESS_FINE_LOCATION"} <= flagged
    assert 20 <= r["overall"] <= 70


def test_banking_trojan_pattern_is_high_but_not_100_without_yara():
    f = Features(
        package="com.fake.flashlight", category="utility_simple",
        permissions=["SEND_SMS", "READ_SMS", "RECEIVE_SMS", "READ_CALL_LOG", "BIND_ACCESSIBILITY_SERVICE",
                     "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "INTERNET", "RECEIVE_BOOT_COMPLETED"],
        evidence_groups={"sms", "accessibility", "overlay", "install"},
        behaviors={"sms_send", "accessibility_service", "overlay", "dex_loader", "telegram_exfil"},
        signature=SIGNED, flags=FLAGS)
    r = score_features(f)
    assert 60 <= r["overall"] <= 97
    assert r["toxic_combinations"]


def test_confirmed_yara_hit_can_reach_critical():
    f = Features(package="x.y", signature=SIGNED, flags=FLAGS,
                 yara_matches=[{"rule": "R", "severity": 9, "family": "Anubis"}])
    assert score_features(f)["overall"] >= 80


def test_scores_are_continuous_and_all_ten_present():
    r = score_features(_grocery({"location"}))
    assert len(r["scores"]) == 10
    vals = set(round(v, 1) for v in r["scores"].values())
    assert len(vals) > 3  # not bucketed


def test_pinned_cert_mismatch_flags_impersonation():
    f = _grocery({"location"})
    f.publisher_mismatch = True
    assert score_features(f)["overall"] >= 75


def test_verified_publisher_lowers_score():
    a = _grocery(set()); b = _grocery(set()); b.publisher_verified = True
    assert score_features(b)["overall"] < score_features(a)["overall"]