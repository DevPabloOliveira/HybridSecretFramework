"""Statistical features for recovered candidate strings."""

from __future__ import annotations

from modules.core.models import FeatureValue, SecretCandidate


def extract_statistical_features(candidate: SecretCandidate) -> dict[str, FeatureValue]:
    """Return entropy, length, and character composition features."""

    value = candidate.value
    length = len(value)
    if length == 0:
        return {
            "length": 0,
            "entropy": 0.0,
            "digit_ratio": 0.0,
            "alpha_ratio": 0.0,
            "symbol_ratio": 0.0,
            "is_hex": False,
            "is_uuid_like": False,
        }

    digit_count = sum(char.isdigit() for char in value)
    alpha_count = sum(char.isalpha() for char in value)
    symbol_count = length - digit_count - alpha_count
    is_hex = all(char in "0123456789abcdefABCDEF" for char in value.replace("-", ""))

    return {
        "length": length,
        "entropy": round(candidate.entropy, 4),
        "digit_ratio": digit_count / length,
        "alpha_ratio": alpha_count / length,
        "symbol_ratio": symbol_count / length,
        "is_hex": is_hex,
        "is_uuid_like": value.count("-") == 4 and length == 36,
    }
