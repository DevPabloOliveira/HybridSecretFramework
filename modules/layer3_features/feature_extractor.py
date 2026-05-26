"""High-level feature extraction layer."""

from __future__ import annotations

from modules.core.models import AstContext, FeatureVector, SecretCandidate
from modules.layer3_features.asset_features import extract_asset_features
from modules.layer3_features.contextual_features import extract_contextual_features
from modules.layer3_features.statistical_features import extract_statistical_features
from modules.layer3_features.syntactic_features import extract_syntactic_features


class FeatureExtractor:
    """Compose syntactic, contextual, and statistical features."""

    def extract(
        self,
        content: str,
        candidate: SecretCandidate,
        ast_context: AstContext,
    ) -> FeatureVector:
        """Build a feature vector for supervised or baseline classification."""

        features = extract_statistical_features(candidate)
        syntactic, syntactic_evidence = extract_syntactic_features(ast_context)
        contextual, contextual_evidence = extract_contextual_features(content, candidate)
        assets, asset_evidence = extract_asset_features(content, candidate, ast_context)

        features.update(syntactic)
        features.update(contextual)
        features.update(assets)
        features.update(
            {
                "provider": candidate.provider,
                "signature_confidence": candidate.signature_confidence,
                "file_path": candidate.file_path,
                "language": ast_context.language,
            }
        )

        evidence = syntactic_evidence + contextual_evidence + asset_evidence
        return FeatureVector(
            candidate=candidate,
            ast_context=ast_context,
            features=features,
            evidence=evidence,
        )
