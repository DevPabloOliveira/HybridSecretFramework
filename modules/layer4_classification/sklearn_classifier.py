"""Scikit-Learn/XGBoost model adapter for the classification layer."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from modules.core.models import ClassificationResult, FeatureVector
from modules.layer4_classification.feature_encoding import DEFAULT_FEATURE_ORDER, FeatureEncoder
from modules.layer4_classification.threshold_policy import ThresholdPolicy
from modules.layer1_retrieval.signatures import DEFAULT_SIGNATURES


class SklearnSecretClassifier:
    """Load a supervised model artifact and classify feature vectors.

    The model is expected to expose either predict_proba or decision_function.
    This adapter keeps the production pipeline ready for Scikit-Learn/XGBoost
    without making the repository depend on a trained artifact.
    """

    model_name = "sklearn-supervised-adapter"

    def __init__(
        self,
        model_path: str,
        feature_order: list[str] | None = None,
        threshold_policy: ThresholdPolicy | None = None,
    ) -> None:
        self.model_path = Path(model_path)
        self.threshold_policy = threshold_policy or ThresholdPolicy()
        artifact = self._load_artifact()
        if isinstance(artifact, dict) and "model" in artifact:
            self.model = artifact["model"]
            self.feature_order = feature_order or artifact.get("feature_order") or list(DEFAULT_FEATURE_ORDER)
            self.model_name = artifact.get("model_name", self.model_name)
        else:
            self.model = artifact
            self.feature_order = feature_order or list(DEFAULT_FEATURE_ORDER)
        self.encoder = FeatureEncoder(self.feature_order)

    def classify(self, features: FeatureVector) -> ClassificationResult:
        row = [self.encoder.encode(features.features)]
        confidence = self._predict_probability(row)
        approval_threshold = self._approval_threshold(features)
        approved = confidence >= approval_threshold
        return ClassificationResult(
            label="REAL_SECRET" if approved else "FALSE_POSITIVE",
            confidence=confidence,
            approved=approved,
            model_name=self.model_name,
            reasons=[
                f"supervised model probability from {self.model_name}",
                f"approval threshold={approval_threshold:.2f}",
            ],
            raw_score=confidence,
        )

    def _load_artifact(self) -> Any:
        try:
            import joblib
        except Exception as exc:
            raise RuntimeError("joblib is required to load a supervised classifier.") from exc
        return joblib.load(self.model_path)

    def _predict_probability(self, row: list[list[float]]) -> float:
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(row)
            return float(probabilities[0][1])
        if hasattr(self.model, "decision_function"):
            decision = float(self.model.decision_function(row)[0])
            return 1.0 / (1.0 + pow(2.718281828, -decision))
        prediction = self.model.predict(row)
        return 0.99 if int(prediction[0]) == 1 else 0.01

    def _approval_threshold(self, features: FeatureVector) -> float:
        provider = str(features.features.get("provider", ""))
        context = str(features.features.get("context_window", "")).lower()
        file_path = str(features.features.get("file_path", features.candidate.file_path)).lower()

        is_generic = provider.startswith("Generic") or provider == "UUID-like Secret"
        provider_specific = any(signature.provider == provider for signature in DEFAULT_SIGNATURES) and not is_generic
        is_doc = bool(features.features.get("is_documentation_or_test_path"))
        has_placeholder = bool(features.features.get("has_placeholder_signal")) or bool(features.features.get("has_template_language"))
        has_hash_noise = bool(features.features.get("has_hash_or_identifier_term"))
        variable_is_sensitive = bool(features.features.get("variable_is_sensitive"))
        has_assignment = bool(features.features.get("is_assignment_context"))
        has_secret_terms = bool(features.features.get("has_secret_term_nearby"))
        has_asset_reference = bool(features.features.get("has_asset_reference"))
        is_reconx_dump = "reconx/keys.md" in file_path
        is_operational_uuid = provider == "UUID-like Secret" and any(
            term in context for term in ("connector_id", "job_id", "policy_id", "screenshot", ".png")
        )

        threshold = self.threshold_policy.approve_threshold
        if provider_specific:
            return threshold
        if is_operational_uuid:
            return 0.995
        if is_generic and has_placeholder:
            return 0.995
        if is_generic and has_hash_noise:
            return 0.995
        if is_generic and is_reconx_dump:
            return 0.995
        if is_generic and is_doc:
            return 0.995
        if is_generic and has_assignment and (variable_is_sensitive or has_secret_terms or has_asset_reference):
            return 0.90
        if is_generic and (variable_is_sensitive or has_secret_terms) and has_asset_reference:
            return 0.94
        if is_generic:
            return 0.995
        return threshold
