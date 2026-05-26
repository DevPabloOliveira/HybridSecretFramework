"""Stable feature encoding for supervised classifiers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


DEFAULT_FEATURE_ORDER = [
    "length",
    "entropy",
    "digit_ratio",
    "alpha_ratio",
    "symbol_ratio",
    "is_hex",
    "is_uuid_like",
    "signature_confidence_score",
    "provider_is_generic",
    "provider_is_critical_type",
    "has_ast_context",
    "has_variable_name",
    "variable_is_sensitive",
    "call_is_auth_related",
    "is_assignment_context",
    "has_downstream_usage",
    "downstream_call_count",
    "has_secret_term_nearby",
    "secret_term_proximity_score",
    "has_asset_reference",
    "asset_reference_count",
    "has_database_asset",
    "has_url_asset",
    "has_host_asset",
    "has_hash_or_identifier_term",
    "has_placeholder_signal",
    "has_template_language",
    "is_template_file",
    "is_documentation_or_test_path",
    "is_weak_documentation_context",
    "language_is_python",
    "language_is_config",
    "language_is_documentation",
    "parse_error_present",
]


SIGNATURE_CONFIDENCE_WEIGHTS = {
    "CRITICAL": 1.0,
    "HIGH": 0.75,
    "MEDIUM": 0.5,
    "LOW": 0.25,
}

CRITICAL_PROVIDER_TERMS = (
    "aws",
    "google",
    "github",
    "gitlab",
    "stripe",
    "openai",
    "slack",
    "pypi",
)


class FeatureEncoder:
    """Convert extracted feature dictionaries into numeric model vectors."""

    def __init__(self, feature_order: list[str] | None = None) -> None:
        self.feature_order = feature_order or list(DEFAULT_FEATURE_ORDER)

    def encode(self, features: Mapping[str, Any]) -> list[float]:
        """Encode features using the configured schema."""

        return [self._encode_one(name, features) for name in self.feature_order]

    def _encode_one(self, name: str, features: Mapping[str, Any]) -> float:
        if name == "signature_confidence_score":
            return SIGNATURE_CONFIDENCE_WEIGHTS.get(str(features.get("signature_confidence", "")).upper(), 0.0)
        if name == "provider_is_generic":
            return self._bool(str(features.get("provider", "")).lower().startswith("generic"))
        if name == "provider_is_critical_type":
            provider = str(features.get("provider", "")).lower()
            return self._bool(any(term in provider for term in CRITICAL_PROVIDER_TERMS))
        if name == "secret_term_proximity_score":
            distance = features.get("nearest_secret_term_distance")
            if distance in (None, ""):
                return 0.0
            return max(0.0, 1.0 - min(float(distance), 120.0) / 120.0)
        if name == "language_is_python":
            return self._bool(str(features.get("language", "")).lower() == "python")
        if name == "language_is_config":
            return self._bool(str(features.get("language", "")).lower() == "config")
        if name == "language_is_documentation":
            return self._bool(str(features.get("language", "")).lower() == "documentation")
        if name == "parse_error_present":
            return self._bool(bool(features.get("parse_error")))

        return self._numeric(features.get(name))

    @staticmethod
    def _numeric(value: Any) -> float:
        if value in (None, ""):
            return 0.0
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip().lower()
        if text in {"true", "yes", "y", "1", "real_secret"}:
            return 1.0
        if text in {"false", "no", "n", "0", "false_positive"}:
            return 0.0
        try:
            return float(text)
        except ValueError:
            return 0.0

    @staticmethod
    def _bool(value: bool) -> float:
        return 1.0 if value else 0.0
