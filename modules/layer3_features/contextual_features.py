"""Contextual features from local code text around a candidate."""

from __future__ import annotations

import re

from modules.core.language import is_documentation_or_test_path
from modules.core.models import FeatureValue, SecretCandidate
from modules.layer3_features.placeholder_detection import contains_placeholder_signal


SECRET_TERMS = (
    "password",
    "passwd",
    "token",
    "secret",
    "credential",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "client_secret",
    "auth",
)

HASH_OR_ID_TERMS = (
    "checksum",
    "hash",
    "md5",
    "sha1",
    "sha256",
    "uuid",
    "guid",
    "image",
    "png",
    "svg",
    "color",
    "background",
    "selector",
    "class",
)

TEMPLATE_TERMS = (
    "only add",
    "leave others empty",
    "leave empty",
    "delete",
    "replace",
    "example",
    "sample",
    "template",
    "your ",
)

DOC_TEMPLATE_FILENAMES = (
    "api_keys.md",
    "example",
    "sample",
    "template",
)


def extract_contextual_features(
    content: str,
    candidate: SecretCandidate,
    window_size: int = 120,
) -> tuple[dict[str, FeatureValue], list[str]]:
    """Extract semantic proximity and placeholder features."""

    start = max(0, candidate.start_index - window_size)
    end = min(len(content), candidate.end_index + window_size)
    context = content[start:end].replace("\n", " ")
    context_lower = context.lower()

    nearest_secret_distance = _nearest_term_distance(context_lower, SECRET_TERMS)
    has_secret_term = nearest_secret_distance is not None
    has_hash_term = any(term in context_lower for term in HASH_OR_ID_TERMS)
    has_placeholder = contains_placeholder_signal(context_lower)
    has_template_language = any(term in context_lower for term in TEMPLATE_TERMS)
    is_doc_or_test = is_documentation_or_test_path(candidate.file_path)
    is_template_file = _is_template_file(candidate.file_path)
    is_weak_documentation_context = (
        (is_doc_or_test or is_template_file)
        and not _has_hardcoded_secret_list_shape(context_lower)
    )

    evidence: list[str] = []
    if has_secret_term:
        evidence.append("Nearby context contains secret-related terminology.")
    if has_hash_term:
        evidence.append("Nearby context contains hash/id terminology associated with false positives.")
    if has_placeholder:
        evidence.append("Nearby context contains placeholder or example terminology.")
    if has_template_language:
        evidence.append("Nearby context contains template instructions.")
    if is_doc_or_test:
        evidence.append("File path suggests documentation, tests, examples, or fixtures.")
    if is_weak_documentation_context:
        evidence.append("Documentation context lacks strong leaked-key list structure.")

    return (
        {
            "context_window": context.strip()[:300],
            "has_secret_term_nearby": has_secret_term,
            "nearest_secret_term_distance": nearest_secret_distance,
            "has_hash_or_identifier_term": has_hash_term,
            "has_placeholder_signal": has_placeholder,
            "has_template_language": has_template_language,
            "is_template_file": is_template_file,
            "is_documentation_or_test_path": is_doc_or_test,
            "is_weak_documentation_context": is_weak_documentation_context,
        },
        evidence,
    )


def _nearest_term_distance(context: str, terms: tuple[str, ...]) -> int | None:
    distances = []
    for term in terms:
        for match in re.finditer(re.escape(term), context):
            distances.append(abs(match.start() - len(context) // 2))
    if not distances:
        return None
    return min(distances)


def _has_hardcoded_secret_list_shape(context: str) -> bool:
    """Detect notes/dumps that list several real-looking secrets together."""

    strong_terms = (
        "access key id",
        "secret access key",
        "api-key:",
        "apikey:",
        "secret_key:",
        "api:",
        "github:",
        "amazon:",
    )
    return sum(1 for term in strong_terms if term in context) >= 2


def _is_template_file(file_path: str) -> bool:
    normalized = file_path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    return any(marker in name for marker in DOC_TEMPLATE_FILENAMES)
