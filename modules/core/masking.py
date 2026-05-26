"""Utilities for safely presenting detected secrets."""

from __future__ import annotations


def mask_secret(value: str, visible_prefix: int = 4, visible_suffix: int = 4) -> str:
    """Return a stable masked representation of a secret candidate."""

    if not value:
        return ""
    if len(value) <= visible_prefix + visible_suffix:
        return "*" * len(value)
    return f"{value[:visible_prefix]}{'*' * 8}{value[-visible_suffix:]}"
