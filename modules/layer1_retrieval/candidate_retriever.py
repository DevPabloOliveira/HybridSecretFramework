"""Candidate recovery layer built on broad Regex signatures and entropy."""

from __future__ import annotations

from modules.core.models import SecretCandidate, SourceFile
from modules.layer1_retrieval.entropy import shannon_entropy
from modules.layer1_retrieval.signatures import DEFAULT_SIGNATURES, SecretSignature


class CandidateRetriever:
    """Recover possible secrets while preserving high recall."""

    def __init__(self, signatures: tuple[SecretSignature, ...] = DEFAULT_SIGNATURES) -> None:
        self.signatures = signatures

    def retrieve(self, source_file: SourceFile) -> list[SecretCandidate]:
        """Return candidates found in a downloaded source artifact."""

        candidates: list[SecretCandidate] = []
        content = source_file.content

        for signature in self.signatures:
            for match in signature.regex.finditer(content):
                value = match.group()
                entropy = shannon_entropy(value)
                if self._is_obvious_noise(value, signature.confidence, entropy):
                    continue

                line_number, column_number = self._line_and_column(content, match.start())
                candidates.append(
                    SecretCandidate(
                        repository=source_file.repository,
                        file_path=source_file.path,
                        url=source_file.url,
                        raw_url=source_file.raw_url,
                        value=value,
                        provider=signature.provider,
                        signature_confidence=signature.confidence,
                        start_index=match.start(),
                        end_index=match.end(),
                        line_number=line_number,
                        column_number=column_number,
                        entropy=entropy,
                        pattern_source=source_file.pattern_source,
                    )
                )

        return candidates

    @staticmethod
    def _line_and_column(content: str, offset: int) -> tuple[int, int]:
        prefix = content[:offset]
        line_number = prefix.count("\n") + 1
        line_start = prefix.rfind("\n")
        column_number = offset + 1 if line_start == -1 else offset - line_start
        return line_number, column_number

    @staticmethod
    def _is_obvious_noise(value: str, confidence: str, entropy: float) -> bool:
        """Drop only trivial noise; semantic filtering belongs to later layers."""

        if len(value) < 16:
            return True
        if confidence in {"CRITICAL", "HIGH"}:
            return False
        return entropy < 2.5
