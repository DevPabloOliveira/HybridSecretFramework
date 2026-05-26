"""Finding explanation builder."""

from __future__ import annotations

from modules.core.models import ClassificationResult, FeatureVector


def build_evidence(features: FeatureVector, decision: ClassificationResult) -> list[str]:
    """Merge model reasons and contextual evidence into analyst-facing text."""

    evidence: list[str] = []
    evidence.extend(features.evidence)
    evidence.extend(f"Classifier reason: {reason}." for reason in decision.reasons)

    context_window = features.features.get("context_window")
    if isinstance(context_window, str) and context_window:
        evidence.append(f"Context: {context_window}")

    return _dedupe(evidence)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result
