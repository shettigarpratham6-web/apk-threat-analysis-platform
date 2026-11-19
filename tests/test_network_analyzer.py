import os
import pytest
from sandbox.network_analyzer import NetworkAnalyzer

def test_network_analyzer_missing_file():
    analyzer = NetworkAnalyzer("non_existent_flow.flow")
    summary = analyzer.analyze()
    assert summary["total_connections"] == 0
    assert summary["unique_destination_count"] == 0

def test_network_analyzer_real_capture():
    sample_flow = "logs/traffic/traffic.flow"
    if os.path.exists(sample_flow) and os.path.getsize(sample_flow) > 0:
        analyzer = NetworkAnalyzer(sample_flow)
        summary = analyzer.analyze()
        assert summary["total_connections"] > 0
        assert "protocol_breakdown" in summary
