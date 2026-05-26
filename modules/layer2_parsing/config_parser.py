"""Structural parser for configuration-like files."""

from __future__ import annotations

import re

from modules.core.models import AstContext, SecretCandidate
from modules.layer2_parsing.base import CandidateParser


class ConfigParser(CandidateParser):
    """Extract key/value context from env, yaml, json, and similar files."""

    parser_name = "config-structural-parser"
    language = "config"

    def analyze(self, file_path: str, content: str, candidate: SecretCandidate) -> AstContext:
        line = self._line_at(content, candidate.line_number)
        variable_name = self._extract_key(line)
        evidence = []
        if variable_name:
            evidence.append(f"Candidate appears in configuration key '{variable_name}'.")

        return AstContext(
            language=self.language,
            parser_name=self.parser_name,
            ast_node_type="ConfigProperty" if variable_name else "ConfigLine",
            parent_node_type="ConfigurationFile",
            variable_name=variable_name,
            usage_context=line.strip()[:240],
            evidence=evidence,
        )

    @staticmethod
    def _line_at(content: str, line_number: int) -> str:
        lines = content.splitlines()
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1]
        return ""

    @staticmethod
    def _extract_key(line: str) -> str | None:
        match = re.match(r"\s*['\"]?([A-Za-z0-9_.\-/]+)['\"]?\s*[:=]", line)
        if not match:
            return None
        return match.group(1)
