"""Risk scoring for explainable findings."""

from __future__ import annotations

from modules.core.models import FeatureVector


CRITICAL_TYPES = (
    "AWS",
    "Google",
    "GitHub",
    "GitLab",
    "Stripe",
    "OpenAI",
    "Slack",
    "PyPI",
)


def calculate_risk_score(features: FeatureVector, confidence: float) -> tuple[float, str]:
    """Calculate operational risk from confidence and contextual evidence."""

    provider = features.candidate.provider
    score = confidence

    if any(provider.startswith(prefix) for prefix in CRITICAL_TYPES):
        score += 0.10
    if bool(features.features.get("call_is_auth_related")):
        score += 0.08
    if bool(features.features.get("variable_is_sensitive")):
        score += 0.06
    if bool(features.features.get("has_downstream_usage")):
        score += 0.08
    if bool(features.features.get("has_asset_reference")):
        score += 0.08
    if bool(features.features.get("has_database_asset")):
        score += 0.04
    if bool(features.features.get("is_documentation_or_test_path")):
        score -= 0.10

    score = max(0.0, min(1.0, score))
    if score >= 0.85:
        level = "CRITICAL"
    elif score >= 0.72:
        level = "HIGH"
    elif score >= 0.55:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level
