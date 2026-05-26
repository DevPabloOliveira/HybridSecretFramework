from .base import BaseValidator


class GenericValidator(BaseValidator):
    """Fallback Strategy when no provider-specific validator exists.

    This validator is intentionally conservative: it never confirms a key as
    active. The goal is to avoid presenting a format-only match as a verified
    secret during Layer 5 explainability.
    """

    def check(self, key: str):
        if len(key) > 20:
            return {
                "valid": False,
                "details": "No provider-specific validator available; format-only review only.",
                "status": "unsupported",
            }
        return {
            "valid": False,
            "details": "Candidate too short for provider-agnostic review.",
            "status": "unsupported",
        }
