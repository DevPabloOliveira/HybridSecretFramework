from .base import BaseValidator


class PassiveOnlyValidator(BaseValidator):
    """Safe fallback for high-risk providers where live verification is avoided.

    We keep the Strategy interface stable, but intentionally skip active checks
    for providers that would require testing a potentially leaked credential
    against a third-party account.
    """

    def __init__(self, provider_label: str) -> None:
        super().__init__()
        self.provider_label = provider_label

    def check(self, key: str):
        return {
            "valid": False,
            "details": (
                f"Skipped active validation for {self.provider_label}; "
                "manual review recommended to avoid unsafe third-party credential testing."
            ),
            "status": "skipped",
        }
