"""Re-export of CodeBERTSimilarityAnalyzer for backend.core.static_analysis."""
from backend.app.static_analysis.codebert_analyzer import (
    CodeBERTSimilarityAnalyzer,
    get_codebert_analyzer,
    REFERENCE_PATTERNS,
)

__all__ = [
    "CodeBERTSimilarityAnalyzer",
    "get_codebert_analyzer",
    "REFERENCE_PATTERNS",
]
