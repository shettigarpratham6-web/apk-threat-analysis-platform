"""
Static Analysis ML Classifier Adapter.
Aliases backend.core.static_analysis.ml_classifier.
"""

from backend.core.static_analysis.ml_classifier import (
    StaticMalwareClassifier,
    get_static_malware_classifier,
    classify_static_features,
)

__all__ = [
    "StaticMalwareClassifier",
    "get_static_malware_classifier",
    "classify_static_features",
]
