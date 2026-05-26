"""Syntactic features extracted from AST context."""

from __future__ import annotations

from modules.core.models import AstContext, FeatureValue


SENSITIVE_NAME_TERMS = (
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "auth",
    "apikey",
    "api_key",
    "client_secret",
    "access",
    "private",
)

AUTH_CALL_TERMS = (
    "auth",
    "login",
    "connect",
    "client",
    "session",
    "credential",
    "api",
    "token",
)


def extract_syntactic_features(context: AstContext) -> tuple[dict[str, FeatureValue], list[str]]:
    """Extract AST-backed semantic features.

    Feature extraction follows QP2 from the systematic mapping: variable-usage
    association, call context, scope, and syntactic node type provide semantic
    evidence that Regex cannot infer.
    """

    evidence: list[str] = list(context.evidence)
    variable = (context.variable_name or "").lower()
    call = (context.call_name or "").lower()
    node = context.ast_node_type or ""
    parent = context.parent_node_type or ""

    features: dict[str, FeatureValue] = {
        "has_ast_context": context.parse_error is None,
        "has_variable_name": bool(variable),
        "variable_name": context.variable_name,
        "variable_is_sensitive": any(term in variable for term in SENSITIVE_NAME_TERMS),
        "call_name": context.call_name,
        "call_is_auth_related": any(term in call for term in AUTH_CALL_TERMS),
        "downstream_call_count": len(context.downstream_calls),
        "has_downstream_usage": bool(context.downstream_calls),
        "downstream_calls": " | ".join(context.downstream_calls[:5]),
        "ast_node_type": node,
        "parent_node_type": parent,
        "is_assignment_context": parent in {"Assign", "AnnAssign"} or node == "ConfigProperty",
        "parse_error": context.parse_error,
    }

    if features["variable_is_sensitive"]:
        evidence.append(f"Variable name '{context.variable_name}' contains a secret-related term.")
    if features["call_is_auth_related"]:
        evidence.append(f"Call '{context.call_name}' appears authentication or client related.")
    if features["is_assignment_context"]:
        evidence.append("Candidate is bound through assignment or configuration property.")
    if features["has_downstream_usage"]:
        evidence.append("Candidate has downstream data-flow usage after assignment.")

    return features, evidence
