"""Entropy helpers used by retrieval and feature extraction."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy for a candidate string."""

    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log(count / length, 2) for count in counts.values())
