from __future__ import annotations

from modules.core.models import PrioritizedFinding
from modules.validators.generic import GenericValidator
from modules.validators.passive import PassiveOnlyValidator
from modules.validators.google import GoogleValidator
from modules.validators.scrapingbee import ScrapingBeeValidator
from modules.validators.shodan import ShodanValidator


class HybridSecretValidator:
    """Strategy dispatcher for active validation checks.

    Validators are intentionally outside the classifier. They should be called
    only after Layer 4 approves a candidate with high confidence.
    """

    def __init__(self) -> None:
        self.validators_map = {
            "shodan": ShodanValidator,
            "google": GoogleValidator,
            "generic": GenericValidator,
            "scrapingbee": ScrapingBeeValidator,
        }
        self.sensitive_routes = {
            "aws access key": "passive",
            "github token": "passive",
            "gitlab personal access token": "passive",
            "stripe live key": "passive",
            "openai api key": "passive",
            "openai project key": "passive",
            "slack token": "passive",
            "twilio account sid": "passive",
            "mailgun api key": "passive",
            "pypi upload token": "passive",
            "discord bot token": "passive",
            "telegram bot token": "passive",
        }
        self.provider_routes = {
            "shodan": "shodan",
            "google": "google",
            "scrapingbee": "scrapingbee",
        }

    def resolve_service(self, secret_type: str, requested_service: str = "auto") -> str:
        """Resolve the validation strategy from the secret type.

        `auto` aligns the validation phase with Layer 4 output, instead of
        forcing the caller to guess a provider for mixed finding sets.
        """

        normalized_request = requested_service.lower().strip()
        if normalized_request and normalized_request != "auto":
            return normalized_request

        normalized_type = secret_type.lower().strip()
        if normalized_type in self.sensitive_routes:
            return self.sensitive_routes[normalized_type]

        for provider_hint, service_name in self.provider_routes.items():
            if provider_hint in normalized_type:
                return service_name

        return "generic"

    def validate(self, service_name: str, key: str, secret_type: str | None = None):
        """Instantiate the correct Strategy validator and run its check."""

        service_key = service_name.lower()
        if service_key == "passive":
            validator_instance = PassiveOnlyValidator(secret_type or "sensitive provider")
            return validator_instance.check(key)

        validator_class = self.validators_map.get(service_key, GenericValidator)
        validator_instance = validator_class()
        return validator_instance.check(key)

    def validate_finding(self, finding: PrioritizedFinding, requested_service: str = "auto"):
        """Validate a full finding using explicit or auto-routed strategy."""

        service_name = self.resolve_service(finding.secret_type, requested_service)
        result = self.validate(service_name, finding.raw_value, finding.secret_type)
        return service_name, result


# Backward-compatible alias kept to avoid breaking older local scripts.
OmniValidator = HybridSecretValidator
