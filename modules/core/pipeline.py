"""Orchestration for the five-layer hybrid secret detection pipeline."""

from __future__ import annotations

from modules.core.models import CandidateAnalysis, PrioritizedFinding
from modules.layer1_retrieval.candidate_retriever import CandidateRetriever
from modules.layer1_retrieval.content_fetcher import AsyncContentFetcher
from modules.layer2_parsing.parser_registry import ParserRegistry
from modules.layer3_features.feature_extractor import FeatureExtractor
from modules.layer4_classification.classifier import SecretClassifier
from modules.layer4_classification.heuristic_baseline import HeuristicBaselineClassifier
from modules.layer5_reporting.reporter import FindingReporter


class HybridSecretPipeline:
    """Run retrieval, AST parsing, feature extraction, ML gate, and reporting."""

    def __init__(
        self,
        concurrency: int = 20,
        classifier: SecretClassifier | None = None,
    ) -> None:
        self.fetcher = AsyncContentFetcher(concurrency=concurrency)
        self.retriever = CandidateRetriever()
        self.parser_registry = ParserRegistry()
        self.feature_extractor = FeatureExtractor()
        self.classifier = classifier or HeuristicBaselineClassifier()
        self.reporter = FindingReporter()

    async def run(self, scan_items: list[dict[str, str]]) -> list[PrioritizedFinding]:
        """Execute the complete academic five-layer pipeline."""

        analyses = await self.analyze(scan_items)
        findings = [
            self.reporter.build(analysis.candidate, analysis.feature_vector, analysis.classification)
            for analysis in analyses
            if analysis.classification.approved
        ]
        findings.sort(key=lambda item: (item.risk_score, item.confidence), reverse=True)
        return findings

    async def analyze(self, scan_items: list[dict[str, str]]) -> list[CandidateAnalysis]:
        """Return full feature/classification records for all recovered candidates."""

        source_files = await self.fetcher.fetch_many(scan_items)
        analyses: list[CandidateAnalysis] = []
        seen: set[tuple[str, str, str, int]] = set()

        for source_file in source_files:
            candidates = self.retriever.retrieve(source_file)
            for candidate in candidates:
                identity = (
                    candidate.repository,
                    candidate.file_path,
                    candidate.value,
                    candidate.line_number,
                )
                if identity in seen:
                    continue
                seen.add(identity)

                ast_context = self.parser_registry.analyze(
                    source_file.path,
                    source_file.content,
                    candidate,
                )
                features = self.feature_extractor.extract(
                    source_file.content,
                    candidate,
                    ast_context,
                )
                decision = self.classifier.classify(features)
                analyses.append(
                    CandidateAnalysis(
                        candidate=candidate,
                        ast_context=ast_context,
                        feature_vector=features,
                        classification=decision,
                    )
                )

        return analyses
