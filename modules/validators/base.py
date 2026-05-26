import requests


class BaseValidator:
    """Base Strategy contract for active API validation."""

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "HybridSecretFramework/4.0"})

    def check(self, key: str):
        """Validate a candidate against a provider-specific API."""

        raise NotImplementedError("Subclasses must implement check().")
