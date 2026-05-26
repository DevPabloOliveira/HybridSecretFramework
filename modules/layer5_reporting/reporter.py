"""Final report assembly for approved findings."""

from __future__ import annotations

from modules.core.masking import mask_secret
from modules.core.models import ClassificationResult, FeatureVector, PrioritizedFinding, SecretCandidate
from modules.layer5_reporting.explanation import build_evidence
from modules.layer5_reporting.risk import calculate_risk_score


class FindingReporter:
    """Build explainable prioritized findings."""

    def build(
        self,
        candidate: SecretCandidate,
        features: FeatureVector,
        decision: ClassificationResult,
    ) -> PrioritizedFinding:
        risk_score, risk_level = calculate_risk_score(features, decision.confidence)
        return PrioritizedFinding(
            raw_value=candidate.value,
            masked_value=mask_secret(candidate.value),
            secret_type=candidate.provider,
            repository=candidate.repository,
            file_path=candidate.file_path,
            url=candidate.url,
            line_number=candidate.line_number,
            ast_node=features.ast_context.ast_node_type,
            variable_name=features.ast_context.variable_name,
            usage_calls=features.ast_context.downstream_calls,
            asset_references=(
                str(features.features.get("asset_references") or "").split(" | ")
                if features.features.get("asset_references")
                else []
            ),
            confidence=decision.confidence,
            risk_score=risk_score,
            risk_level=risk_level,
            evidence=build_evidence(features, decision),
            model_name=decision.model_name,
        )
