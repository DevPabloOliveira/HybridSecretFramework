"""Optional Tree-sitter parser adapter for non-Python languages."""

from __future__ import annotations

from pathlib import Path
import re

from modules.core.models import AstContext, SecretCandidate
from modules.layer2_parsing.base import CandidateParser


LANGUAGE_BY_SUFFIX = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "c_sharp",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".c": "c",
    ".h": "c",
}


class TreeSitterParser(CandidateParser):
    """Tree-sitter backed parsing for non-Python languages when available."""

    parser_name = "tree-sitter-adapter"
    language = "tree_sitter_candidate"

    def analyze(self, file_path: str, content: str, candidate: SecretCandidate) -> AstContext:
        try:
            from tree_sitter_language_pack import get_parser
        except Exception:
            return AstContext(
                language=self.language,
                parser_name=self.parser_name,
                ast_node_type="Line",
                usage_context=self._line_at(content, candidate.line_number).strip()[:240],
                parse_error="tree-sitter is not installed; using line-level context.",
                evidence=["Tree-sitter adapter is available but dependency is not installed."],
            )

        language = self._language_for_path(file_path)
        if not language:
            return self._line_context(content, candidate, "No Tree-sitter grammar mapped for this extension.")

        try:
            parser = get_parser(language)
            tree = parser.parse(content.encode("utf-8", errors="replace"))
        except Exception as exc:
            return self._line_context(content, candidate, f"Tree-sitter parse failed: {exc}")

        start_byte = len(content[: candidate.start_index].encode("utf-8", errors="replace"))
        end_byte = len(content[: candidate.end_index].encode("utf-8", errors="replace"))
        node = tree.root_node.descendant_for_byte_range(start_byte, max(start_byte, end_byte - 1))
        parent = node.parent if node else None
        line = self._line_at(content, candidate.line_number)
        variable_name = self._variable_from_line(line)
        call_name = self._call_from_line(line)
        evidence = [f"Tree-sitter parsed candidate as node '{node.type if node else 'unknown'}'."]
        if variable_name:
            evidence.append(f"Associated token from source line is '{variable_name}'.")
        if call_name:
            evidence.append(f"Candidate appears near call '{call_name}'.")

        return AstContext(
            language=language,
            parser_name=self.parser_name,
            ast_node_type=node.type if node else "unknown",
            parent_node_type=parent.type if parent else None,
            variable_name=variable_name,
            call_name=call_name,
            usage_context=line.strip()[:240],
            evidence=evidence,
        )

    def _line_context(self, content: str, candidate: SecretCandidate, reason: str) -> AstContext:
        return AstContext(
            language=self.language,
            parser_name=self.parser_name,
            ast_node_type="Line",
            usage_context=self._line_at(content, candidate.line_number).strip()[:240],
            parse_error=reason,
            evidence=[reason],
        )

    @staticmethod
    def _language_for_path(file_path: str) -> str | None:
        return LANGUAGE_BY_SUFFIX.get(Path(file_path).suffix.lower())

    @staticmethod
    def _variable_from_line(line: str) -> str | None:
        patterns = (
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=",
            r"\b([A-Za-z_$][\w$]*)\s*[:=]\s*['\"]",
            r"\.([A-Za-z_$][\w$]*)\s*=\s*['\"]",
        )
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def _call_from_line(line: str) -> str | None:
        match = re.search(r"\b([A-Za-z_$][\w$.]*)\s*\(", line)
        return match.group(1) if match else None

    @staticmethod
    def _line_at(content: str, line_number: int) -> str:
        lines = content.splitlines()
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1]
        return ""
