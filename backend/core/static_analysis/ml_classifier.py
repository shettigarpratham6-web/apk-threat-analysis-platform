"""
Random Forest Static Malware Classifier Module.

Loads the pre-trained RandomForest model (trained on the Drebin static APK feature benchmark)
and accepts the extracted static feature vector from the existing static analysis pipeline.
"""

import json
import os
from typing import Any, Dict, List, Optional, Union

import joblib
import numpy as np
import pandas as pd
from loguru import logger

# Paths to model artifacts
DEFAULT_MODEL_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml", "models", "static_malware_random_forest.pkl")
)
DEFAULT_FEATURES_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml", "models", "static_feature_names.json")
)


class StaticMalwareClassifier:
    """
    Random Forest Classifier for static APK threat assessment.
    Evaluates 215 static features (permissions, API calls, intent actions, system commands).
    """

    def __init__(self, model_path: Optional[str] = None, features_path: Optional[str] = None):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.features_path = features_path or DEFAULT_FEATURES_PATH
        self.model = None
        self.feature_names: List[str] = []
        self._load_model_and_features()

    def _load_model_and_features(self) -> None:
        """Loads the serialized Random Forest model and exact feature names list."""
        if not os.path.exists(self.model_path):
            logger.warning(f"Static Malware model not found at: {self.model_path}")
            return
        if not os.path.exists(self.features_path):
            logger.warning(f"Static feature names not found at: {self.features_path}")
            return

        try:
            self.model = joblib.load(self.model_path)
            with open(self.features_path, "r", encoding="utf-8") as f:
                self.feature_names = json.load(f)
            logger.info(
                f"Successfully loaded StaticMalwareClassifier model with {len(self.feature_names)} features."
            )
        except Exception as exc:
            logger.error(f"Failed to load StaticMalwareClassifier: {exc}")
            self.model = None

    def is_ready(self) -> bool:
        """Returns True if the model and feature names are loaded."""
        return self.model is not None and len(self.feature_names) > 0

    def extract_feature_vector_from_static_analysis(
        self,
        manifest_results: Optional[Dict[str, Any]] = None,
        code_results: Optional[Dict[str, Any]] = None,
        native_results: Optional[Dict[str, Any]] = None,
        raw_features: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, int]:
        """
        Converts existing static analysis outputs into the exact 215-element
        binary feature vector required by the Random Forest classifier.
        Does not recreate or alter any existing feature extraction logic.
        """
        if raw_features and isinstance(raw_features, dict):
            # Already provided a dictionary of features
            return {
                feat: int(raw_features.get(feat, 0))
                for feat in self.feature_names
            }

        manifest = manifest_results or {}
        code = code_results or {}

        # 1. Gather all extracted permissions
        extracted_perms = set()
        for p in manifest.get("permissions", []):
            if isinstance(p, dict):
                p_name = p.get("name", "")
            else:
                p_name = str(p)
            extracted_perms.add(p_name)
            # Add short name (e.g. 'SEND_SMS' from 'android.permission.SEND_SMS')
            if "." in p_name:
                extracted_perms.add(p_name.rsplit(".", 1)[-1])

        # 2. Gather extracted intent filters / actions
        extracted_intents = set()
        components = manifest.get("components", {})
        if isinstance(components, dict):
            for comp_list in components.values():
                if isinstance(comp_list, list):
                    for comp in comp_list:
                        if isinstance(comp, dict):
                            for action in comp.get("intent_filters", []):
                                extracted_intents.add(action)

        # 3. Gather extracted suspicious APIs and malware indicators from code analysis
        extracted_apis = set()
        for api_item in code.get("suspicious_apis", []):
            if isinstance(api_item, dict):
                api_name = api_item.get("api", "")
            else:
                api_name = str(api_item)
            extracted_apis.add(api_name)

        extracted_indicators = set()
        for ind_item in code.get("malware_indicators", []):
            if isinstance(ind_item, dict):
                why = ind_item.get("why_flagged", "")
                snippet = ind_item.get("snippet", "")
            else:
                why = str(ind_item)
                snippet = ""
            extracted_indicators.add(why)
            extracted_indicators.add(snippet)

        # 4. Map each model feature to 1 if present in findings, else 0
        feature_vector: Dict[str, int] = {}
        for feat in self.feature_names:
            val = 0
            # Direct permission match
            if feat in extracted_perms or f"android.permission.{feat}" in extracted_perms:
                val = 1
            # Direct intent action match
            elif feat in extracted_intents or f"android.intent.action.{feat}" in extracted_intents:
                val = 1
            # Suspicious API match
            elif feat in extracted_apis or any(feat in api for api in extracted_apis):
                val = 1
            # Malware indicator / system command / path match
            elif any(feat in ind for ind in extracted_indicators):
                val = 1
            feature_vector[feat] = val

        return feature_vector

    def predict(
        self,
        feature_vector: Union[Dict[str, Any], List[int], np.ndarray, pd.DataFrame],
    ) -> Dict[str, Any]:
        """
        Runs Random Forest inference on the static feature vector.

        :param feature_vector: Dictionary mapping feature names -> 0/1,
                               or list/array aligned with self.feature_names.
        :return: Standard classification result payload:
            {
                "prediction": "malware" | "benign",
                "malware_probability": 0.91,
                "benign_probability": 0.09
            }
        """
        if not self.is_ready():
            self._load_model_and_features()
            if not self.is_ready():
                logger.error("StaticMalwareClassifier model is unavailable.")
                return {
                    "prediction": "unknown",
                    "malware_probability": 0.0,
                    "benign_probability": 0.0,
                    "error": "Model not loaded or model artifact missing.",
                }

        # Convert input into 2D DataFrame with exact feature names and ordering
        if isinstance(feature_vector, dict):
            vector_df = pd.DataFrame(
                [[int(feature_vector.get(f, 0)) for f in self.feature_names]],
                columns=self.feature_names,
            )
        elif isinstance(feature_vector, (list, tuple)):
            if len(feature_vector) != len(self.feature_names):
                raise ValueError(
                    f"Expected {len(self.feature_names)} features, got {len(feature_vector)}"
                )
            vector_df = pd.DataFrame([feature_vector], columns=self.feature_names)
        elif isinstance(feature_vector, pd.DataFrame):
            if set(self.feature_names).issubset(set(feature_vector.columns)):
                vector_df = feature_vector[self.feature_names].copy()
            else:
                vector_df = pd.DataFrame(feature_vector.values, columns=self.feature_names)
        elif isinstance(feature_vector, np.ndarray):
            arr = feature_vector if feature_vector.ndim == 2 else np.expand_dims(feature_vector, 0)
            if arr.shape[1] != len(self.feature_names):
                raise ValueError(
                    f"Expected {len(self.feature_names)} features, got {arr.shape[1]}"
                )
            vector_df = pd.DataFrame(arr, columns=self.feature_names)
        else:
            raise TypeError(f"Unsupported feature vector type: {type(feature_vector)}")

        # Predict probability using feature DataFrame
        probs = self.model.predict_proba(vector_df)[0]
        benign_prob = float(probs[0])
        malware_prob = float(probs[1]) if len(probs) > 1 else (1.0 - benign_prob)

        prediction_label = "malware" if malware_prob >= 0.5 else "benign"

        # Count active features present in sample
        active_features = [
            feat for feat in self.feature_names if vector_df.iloc[0][feat] == 1
        ]

        return {
            "prediction": prediction_label,
            "malware_probability": round(malware_prob, 4),
            "benign_probability": round(benign_prob, 4),
            "features_evaluated": len(self.feature_names),
            "active_features_count": len(active_features),
            "active_features": active_features[:15],
        }


# Singleton instance for high performance in FastAPI
_classifier_instance: Optional[StaticMalwareClassifier] = None


def get_static_malware_classifier() -> StaticMalwareClassifier:
    """Returns the singleton instance of StaticMalwareClassifier."""
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = StaticMalwareClassifier()
    return _classifier_instance


def classify_static_features(
    feature_vector_or_dict: Union[Dict[str, Any], List[int], np.ndarray],
) -> Dict[str, Any]:
    """
    Convenience function to classify an already-extracted static feature vector.
    """
    clf = get_static_malware_classifier()
    return clf.predict(feature_vector_or_dict)
