"""Python AST parser for candidate context extraction."""

from __future__ import annotations

import ast

from modules.core.models import AstContext, SecretCandidate
from modules.layer2_parsing.base import CandidateParser
from modules.layer2_parsing.python_data_flow import PythonDataFlowAnalyzer


class PythonAstParser(CandidateParser):
    """Use Python's native ast module to recover semantic context."""

    parser_name = "python-ast"
    language = "python"

    def __init__(self) -> None:
        self.data_flow = PythonDataFlowAnalyzer()

    def analyze(self, file_path: str, content: str, candidate: SecretCandidate) -> AstContext:
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError as exc:
            return AstContext(
                language=self.language,
                parser_name=self.parser_name,
                parse_error=f"SyntaxError: {exc.msg}",
                usage_context=self._line_at(content, candidate.line_number).strip()[:240],
            )

        parents = self._build_parent_map(tree)
        literal_node = self._find_literal_node(tree, candidate)
        if literal_node is None:
            return AstContext(
                language=self.language,
                parser_name=self.parser_name,
                ast_node_type="Module",
                usage_context=self._line_at(content, candidate.line_number).strip()[:240],
                evidence=["Candidate was not attached to a Python string literal."],
            )

        parent = parents.get(literal_node)
        variable_name = self._assignment_target(parent)
        enclosing_function = self._enclosing_function(literal_node, parents)
        call_name = self._enclosing_call_name(literal_node, parents)
        flow = self.data_flow.analyze(
            tree=tree,
            parents=parents,
            content=content,
            candidate_line=candidate.line_number,
            variable_name=variable_name,
            direct_call_name=call_name,
        )
        usage_context = ast.get_source_segment(content, parent or literal_node)
        evidence: list[str] = [
            f"Candidate is inside Python AST node {type(literal_node).__name__}.",
        ]
        if variable_name:
            evidence.append(f"Associated assignment target is '{variable_name}'.")
        if call_name:
            evidence.append(f"Candidate is used near call '{call_name}'.")
        if enclosing_function:
            evidence.append(f"Candidate is enclosed by function '{enclosing_function}'.")
        evidence.extend(flow.evidence)

        return AstContext(
            language=self.language,
            parser_name=self.parser_name,
            ast_node_type=type(literal_node).__name__,
            parent_node_type=type(parent).__name__ if parent else None,
            variable_name=variable_name,
            enclosing_function=enclosing_function,
            call_name=call_name,
            downstream_calls=flow.usage_calls,
            asset_references=flow.asset_references,
            asset_kinds=flow.asset_kinds,
            usage_context=(usage_context or self._line_at(content, candidate.line_number)).strip()[:240],
            evidence=evidence,
        )

    @staticmethod
    def _build_parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        return parents

    @staticmethod
    def _find_literal_node(tree: ast.AST, candidate: SecretCandidate) -> ast.Constant | None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            start_line = getattr(node, "lineno", None)
            end_line = getattr(node, "end_lineno", start_line)
            if start_line is None or end_line is None:
                continue
            if start_line <= candidate.line_number <= end_line and candidate.value in node.value:
                return node
        return None

    @staticmethod
    def _assignment_target(parent: ast.AST | None) -> str | None:
        if isinstance(parent, ast.Assign):
            names = [PythonAstParser._target_name(target) for target in parent.targets]
            return next((name for name in names if name), None)
        if isinstance(parent, ast.AnnAssign):
            return PythonAstParser._target_name(parent.target)
        if isinstance(parent, ast.keyword):
            return parent.arg
        return None

    @staticmethod
    def _target_name(target: ast.AST) -> str | None:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return target.attr
        if isinstance(target, ast.Subscript):
            return "subscript"
        return None

    @staticmethod
    def _enclosing_function(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str | None:
        current: ast.AST | None = node
        while current is not None:
            current = parents.get(current)
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current.name
        return None

    @staticmethod
    def _enclosing_call_name(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str | None:
        current: ast.AST | None = node
        while current is not None:
            current = parents.get(current)
            if isinstance(current, ast.Call):
                return PythonAstParser._call_name(current.func)
        return None

    @staticmethod
    def _call_name(func: ast.AST) -> str | None:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            base = PythonAstParser._call_name(func.value)
            return f"{base}.{func.attr}" if base else func.attr
        return None

    @staticmethod
    def _line_at(content: str, line_number: int) -> str:
        lines = content.splitlines()
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1]
        return ""
