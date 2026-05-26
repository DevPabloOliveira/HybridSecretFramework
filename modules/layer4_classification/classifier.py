"""Classifier interfaces for the ML decision layer."""

from __future__ import annotations

from typing import Protocol

from modules.core.models import ClassificationResult, FeatureVector


class SecretClassifier(Protocol):
    """Contract implemented by heuristic, Scikit-Learn, or XGBoost classifiers."""

    def classify(self, features: FeatureVector) -> ClassificationResult:
        """Classify a candidate as real secret or false positive."""
