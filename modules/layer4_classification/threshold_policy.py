"""Classification and validation thresholds."""

from __future__ import annotations


class ThresholdPolicy:
    """Centralize confidence gates used by classification and validation."""

    def __init__(self, approve_threshold: float = 0.62, validation_threshold: float = 0.82) -> None:
        self.approve_threshold = approve_threshold
        self.validation_threshold = validation_threshold

    def approve_candidate(self, confidence: float) -> bool:
        return confidence >= self.approve_threshold

    def allow_active_validation(self, confidence: float) -> bool:
        return confidence >= self.validation_threshold
