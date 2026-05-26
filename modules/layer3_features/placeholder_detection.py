"""Placeholder and example-value detection features."""

from __future__ import annotations


PLACEHOLDER_TERMS = {
    "example",
    "sample",
    "dummy",
    "test",
    "testing",
    "changeme",
    "change_me",
    "your_key",
    "your-token",
    "replace",
    "placeholder",
    "only_add",
    "leave_others_empty",
    "leave_empty",
    "delete",
    "abcdefghijklmnopqrstuvwxyz",
    "1234567890",
    "foo",
    "bar",
    "fake",
    "mock",
}


def contains_placeholder_signal(text: str) -> bool:
    """Detect placeholder semantics in local context."""

    normalized = text.lower().replace(" ", "_")
    return any(term in normalized for term in PLACEHOLDER_TERMS)
