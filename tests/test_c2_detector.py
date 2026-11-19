import pytest
from sandbox.c2_detector import C2Detector

def test_c2_detector_clean():
    detector = C2Detector()
    mock_summary = {
        "flows": [
            {"host": "example.com", "port": 80, "path": "/", "url": "http://example.com/"}
        ],
        "connection_intervals": {},
        "destination_frequencies": {"example.com": 1}
    }
    result = detector.analyze_network_data(mock_summary)
    assert result["c2_heuristic_score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["summary"]["is_suspicious"] is False

def test_c2_detector_beaconing():
    detector = C2Detector()
    mock_summary = {
        "flows": [
            {"host": "malicious-c2.test", "port": 8888, "path": "/api/beacon", "url": "http://malicious-c2.test:8888/api/beacon"},
            {"host": "malicious-c2.test", "port": 8888, "path": "/api/beacon", "url": "http://malicious-c2.test:8888/api/beacon"},
            {"host": "malicious-c2.test", "port": 8888, "path": "/api/beacon", "url": "http://malicious-c2.test:8888/api/beacon"},
            {"host": "malicious-c2.test", "port": 8888, "path": "/api/beacon", "url": "http://malicious-c2.test:8888/api/beacon"}
        ],
        "connection_intervals": {
            "malicious-c2.test": {
                "connection_count": 4,
                "intervals_seconds": [5.01, 4.99, 5.02],
                "avg_interval_seconds": 5.01,
                "std_deviation_seconds": 0.01
            }
        },
        "destination_frequencies": {"malicious-c2.test": 4}
    }
    result = detector.analyze_network_data(mock_summary)
    assert result["c2_heuristic_score"] >= 60
    assert result["risk_level"] == "HIGH"
    assert result["summary"]["has_periodic_beacon"] is True
