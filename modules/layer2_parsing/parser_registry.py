"""Parser selection by source artifact language."""

from __future__ import annotations

from modules.core.language import detect_language
from modules.core.models import AstContext, SecretCandidate
from modules.layer2_parsing.config_parser import ConfigParser
from modules.layer2_parsing.python_parser import PythonAstParser
from modules.layer2_parsing.tree_sitter_parser import TreeSitterParser


class ParserRegistry:
    """Select the best parser available for a candidate's file."""

    def __init__(self) -> None:
        self._python = PythonAstParser()
        self._config = ConfigParser()
        self._tree_sitter = TreeSitterParser()

    def analyze(self, file_path: str, content: str, candidate: SecretCandidate) -> AstContext:
        """Return AST or structural context for a candidate."""

        language = detect_language(file_path)
        if language == "python":
            return self._python.analyze(file_path, content, candidate)
        if language == "config":
            return self._config.analyze(file_path, content, candidate)
        if language in {"javascript", "jvm", "tree_sitter_candidate"}:
            return self._tree_sitter.analyze(file_path, content, candidate)

        return AstContext(
            language=language,
            parser_name="line-context",
            ast_node_type="Line",
            usage_context=self._line_at(content, candidate.line_number).strip()[:240],
            evidence=["No language-specific AST parser selected; using line-level context."],
        )

    @staticmethod
    def _line_at(content: str, line_number: int) -> str:
        lines = content.splitlines()
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1]
        return ""
