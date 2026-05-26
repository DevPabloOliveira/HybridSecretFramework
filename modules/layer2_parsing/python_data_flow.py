"""Lightweight Python data-flow and secret-asset association analysis."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field


URL_RE = re.compile(r"https?://[^\s'\"<>]+")
HOST_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|dev|cloud|local|internal)\b")
DB_RE = re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb|redis|amqp|jdbc):\/\/[^\s'\"<>]+")


@dataclass(slots=True)
class DataFlowResult:
    """Minimal flow evidence connecting a candidate to use sites and assets."""

    usage_calls: list[str] = field(default_factory=list)
    asset_references: list[str] = field(default_factory=list)
    asset_kinds: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


class PythonDataFlowAnalyzer:
    """Associate assigned secrets with later call sites and nearby assets.

    This is intentionally intra-file and conservative. It implements the
    program-slicing direction from the mapping without pretending to solve
    whole-program interprocedural data flow.
    """

    def analyze(
        self,
        tree: ast.AST,
        parents: dict[ast.AST, ast.AST],
        content: str,
        candidate_line: int,
        variable_name: str | None,
        direct_call_name: str | None,
    ) -> DataFlowResult:
        result = DataFlowResult()

        if direct_call_name:
            result.usage_calls.append(direct_call_name)

        if variable_name and variable_name not in {"subscript"}:
            self._collect_variable_uses(tree, content, candidate_line, variable_name, result)

        if not result.asset_references:
            self._collect_assets_from_local_scope(tree, parents, content, candidate_line, result)

        result.usage_calls = _dedupe(result.usage_calls)
        result.asset_references = _dedupe(result.asset_references)
        result.asset_kinds = _dedupe(result.asset_kinds)

        if result.usage_calls:
            result.evidence.append(
                "Data-flow slice links candidate to call(s): "
                + ", ".join(result.usage_calls[:5])
            )
        if result.asset_references:
            result.evidence.append(
                "Secret-asset association found near candidate: "
                + ", ".join(result.asset_references[:3])
            )
        return result

    def _collect_variable_uses(
        self,
        tree: ast.AST,
        content: str,
        candidate_line: int,
        variable_name: str,
        result: DataFlowResult,
    ) -> None:
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            call_line = getattr(call, "lineno", 0)
            if call_line < candidate_line:
                continue
            if not self._call_uses_name(call, variable_name):
                continue

            call_name = self._call_name(call.func)
            if call_name:
                result.usage_calls.append(call_name)
            source = ast.get_source_segment(content, call) or ""
            self._collect_assets_from_text(source, result)

    def _collect_assets_from_local_scope(
        self,
        tree: ast.AST,
        parents: dict[ast.AST, ast.AST],
        content: str,
        candidate_line: int,
        result: DataFlowResult,
    ) -> None:
        scope = self._scope_for_line(tree, parents, candidate_line)
        source = ast.get_source_segment(content, scope) if scope else content
        self._collect_assets_from_text(source or "", result)

    @staticmethod
    def _scope_for_line(
        tree: ast.AST,
        parents: dict[ast.AST, ast.AST],
        line: int,
    ) -> ast.AST | None:
        best: ast.AST | None = None
        for node in ast.walk(tree):
            start = getattr(node, "lineno", None)
            end = getattr(node, "end_lineno", start)
            if start is None or end is None or not (start <= line <= end):
                continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
                best = node
        return best

    @staticmethod
    def _call_uses_name(call: ast.Call, variable_name: str) -> bool:
        for node in ast.walk(call):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == variable_name:
                return True
        return False

    @staticmethod
    def _collect_assets_from_text(text: str, result: DataFlowResult) -> None:
        for regex, kind in ((DB_RE, "database"), (URL_RE, "url"), (HOST_RE, "host")):
            for match in regex.finditer(text):
                value = match.group(0).rstrip(".,);]")
                result.asset_references.append(value)
                result.asset_kinds.append(kind)

    @staticmethod
    def _call_name(func: ast.AST) -> str | None:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            base = PythonDataFlowAnalyzer._call_name(func.value)
            return f"{base}.{func.attr}" if base else func.attr
        return None


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
