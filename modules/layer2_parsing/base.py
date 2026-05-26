"""Base parser contracts for AST/context extraction."""

from __future__ import annotations

from abc import ABC, abstractmethod

from modules.core.models import AstContext, SecretCandidate


class CandidateParser(ABC):
    """Parser interface used by the parsing layer."""

    parser_name: str
    language: str

    @abstractmethod
    def analyze(self, file_path: str, content: str, candidate: SecretCandidate) -> AstContext:
        """Return syntactic context for a candidate."""
