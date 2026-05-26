"""Reproducible baseline classifier until a supervised model is trained."""

from __future__ import annotations

from modules.core.models import ClassificationResult, FeatureVector
from modules.layer4_classification.threshold_policy import ThresholdPolicy


class HeuristicBaselineClassifier:
    """Score feature vectors using transparent weights.

    This is a scientific baseline, not the final ML model. It keeps the layer
    contract stable while labeled data and Scikit-Learn/XGBoost artifacts are
    prepared, as recommended by QP1 and QP3 in the mapping.
    """

    model_name = "heuristic-baseline-v1"

    def __init__(self, threshold_policy: ThresholdPolicy | None = None) -> None:
        self.threshold_policy = threshold_policy or ThresholdPolicy()

    def classify(self, feature_vector: FeatureVector) -> ClassificationResult:
        features = feature_vector.features
        reasons: list[str] = []
        score = self._base_score(str(features.get("signature_confidence", "LOW")))

        score = self._add(score, 0.10, bool(features.get("variable_is_sensitive")), reasons, "sensitive variable name")
        score = self._add(score, 0.10, bool(features.get("call_is_auth_related")), reasons, "auth/client call context")
        score = self._add(score, 0.08, bool(features.get("is_assignment_context")), reasons, "assignment/config binding")
        score = self._add(score, 0.08, bool(features.get("has_secret_term_nearby")), reasons, "nearby secret terminology")
        score = self._add(score, 0.04, float(features.get("entropy") or 0) >= 4.0, reasons, "high entropy")
        score = self._add(score, 0.08, bool(features.get("has_downstream_usage")), reasons, "data-flow usage")
        score = self._add(score, 0.08, bool(features.get("has_asset_reference")), reasons, "secret-asset association")

        score = self._subtract(score, 0.30, bool(features.get("has_placeholder_signal")), reasons, "placeholder/example context")
        score = self._subtract(score, 0.24, bool(features.get("has_template_language")), reasons, "template instructions")
        score = self._subtract(score, 0.18, bool(features.get("is_documentation_or_test_path")), reasons, "documentation/test path")
        score = self._subtract(
            score,
            0.18,
            bool(features.get("is_weak_documentation_context")),
            reasons,
            "weak documentation context",
        )
        score = self._subtract(score, 0.20, bool(features.get("has_hash_or_identifier_term")), reasons, "hash/id context")
        score = self._subtract(score, 0.10, bool(features.get("is_uuid_like")), reasons, "uuid-like structure")

        if str(features.get("provider", "")).startswith("Generic") and bool(features.get("is_hex")):
            score -= 0.10
            reasons.append("generic hexadecimal candidate")

        if self._is_doc_template_secret(features):
            score -= 0.28
            reasons.append("documentation template without usage or asset evidence")

        confidence = max(0.0, min(0.99, score))
        approved = self.threshold_policy.approve_candidate(confidence)
        label = "REAL_SECRET" if approved else "FALSE_POSITIVE"

        return ClassificationResult(
            label=label,
            confidence=confidence,
            approved=approved,
            model_name=self.model_name,
            reasons=reasons,
            raw_score=score,
        )

    @staticmethod
    def _base_score(signature_confidence: str) -> float:
        return {
            "CRITICAL": 0.66,
            "HIGH": 0.55,
            "MEDIUM": 0.36,
            "LOW": 0.22,
        }.get(signature_confidence.upper(), 0.25)

    @staticmethod
    def _add(score: float, weight: float, condition: bool, reasons: list[str], reason: str) -> float:
        if condition:
            reasons.append(reason)
            return score + weight
        return score

    @staticmethod
    def _subtract(score: float, weight: float, condition: bool, reasons: list[str], reason: str) -> float:
        if condition:
            reasons.append(reason)
            return score - weight
        return score

    @staticmethod
    def _is_doc_template_secret(features) -> bool:
        return (
            bool(features.get("has_template_language") or features.get("has_placeholder_signal"))
            and bool(features.get("is_template_file") or features.get("is_documentation_or_test_path"))
            and not bool(features.get("has_asset_reference"))
            and not bool(features.get("has_downstream_usage"))
        )
