"""Shared data contracts for the hybrid secret detection pipeline.

The pipeline mirrors the five-layer architecture proposed in the systematic
mapping: retrieval, parsing, feature extraction, classification, and
prioritization/explainability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


FeatureValue = bool | int | float | str | None


@dataclass(slots=True)
class SourceFile:
    """Downloaded source artifact selected by the GitHub recovery layer."""

    repository: str
    path: str
    url: str
    raw_url: str
    content: str
    pattern_source: str | None = None


@dataclass(slots=True)
class SecretCandidate:
    """Raw candidate recovered by Regex and entropy-oriented heuristics."""

    repository: str
    file_path: str
    url: str
    raw_url: str
    value: str
    provider: str
    signature_confidence: str
    start_index: int
    end_index: int
    line_number: int
    column_number: int
    entropy: float
    pattern_source: str | None = None


@dataclass(slots=True)
class AstContext:
    """Syntactic context associated with a candidate in a source file."""

    language: str
    parser_name: str
    ast_node_type: str | None = None
    parent_node_type: str | None = None
    variable_name: str | None = None
    enclosing_function: str | None = None
    call_name: str | None = None
    downstream_calls: list[str] = field(default_factory=list)
    asset_references: list[str] = field(default_factory=list)
    asset_kinds: list[str] = field(default_factory=list)
    usage_context: str | None = None
    parse_error: str | None = None
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FeatureVector:
    """Structured features used by the classification layer."""

    candidate: SecretCandidate
    ast_context: AstContext
    features: dict[str, FeatureValue]
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ClassificationResult:
    """Decision returned by a classifier implementation."""

    label: str
    confidence: float
    approved: bool
    model_name: str
    reasons: list[str] = field(default_factory=list)
    raw_score: float | None = None


@dataclass(slots=True)
class CandidateAnalysis:
    """Full per-candidate record before final report filtering."""

    candidate: SecretCandidate
    ast_context: AstContext
    feature_vector: FeatureVector
    classification: ClassificationResult

    def to_feature_row(self, include_raw: bool = False) -> dict[str, Any]:
        """Serialize features for labeling, training, or evaluation."""

        row: dict[str, Any] = {
            "Repository": self.candidate.repository,
            "File": self.candidate.file_path,
            "URL": self.candidate.url,
            "Line": self.candidate.line_number,
            "Masked Value": _mask_for_feature_row(self.candidate.value),
            "Secret Type": self.candidate.provider,
            "AST Node": self.ast_context.ast_node_type or "",
            "Associated Variable": self.ast_context.variable_name or "",
            "Classifier Label": self.classification.label,
            "Classifier Confidence": round(self.classification.confidence, 4),
        }
        row.update(self.feature_vector.features)
        if include_raw:
            row["Raw Value"] = self.candidate.value
        return row


@dataclass(slots=True)
class PrioritizedFinding:
    """Final explainable finding emitted by the reporting layer."""

    raw_value: str
    masked_value: str
    secret_type: str
    repository: str
    file_path: str
    url: str
    line_number: int
    ast_node: str | None
    variable_name: str | None
    usage_calls: list[str]
    asset_references: list[str]
    confidence: float
    risk_score: float
    risk_level: str
    evidence: list[str]
    model_name: str
    validation_details: str | None = None

    def to_report_row(self, include_raw: bool = False) -> dict[str, Any]:
        """Serialize the finding for CSV output.

        The default report intentionally masks the secret value, matching the
        explainability layer requested by the paper-derived architecture.
        """

        row: dict[str, Any] = {
            "Repository": self.repository,
            "File": self.file_path,
            "URL": self.url,
            "Line": self.line_number,
            "Masked Value": self.masked_value,
            "Secret Type": self.secret_type,
            "AST Node": self.ast_node or "",
            "Associated Variable": self.variable_name or "",
            "Usage Calls": " | ".join(self.usage_calls),
            "Asset References": " | ".join(self.asset_references),
            "Confidence": round(self.confidence, 4),
            "Risk Score": round(self.risk_score, 4),
            "Risk Level": self.risk_level,
            "Model": self.model_name,
            "Contextual Evidence": " | ".join(self.evidence),
            "Validation Details": self.validation_details or "",
        }
        if include_raw:
            row["Raw Value"] = self.raw_value
        return row


def _mask_for_feature_row(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}********{value[-4:]}"
