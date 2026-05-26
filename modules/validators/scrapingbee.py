from .base import BaseValidator


class ScrapingBeeValidator(BaseValidator):
    """Strategy validator for ScrapingBee API keys."""

    def check(self, key: str):
        params = {
            "api_key": key,
            "url": "https://example.com",
            "render_js": "false",
        }

        try:
            response = self.session.get("https://app.scrapingbee.com/api/v1/", params=params, timeout=15)

            if response.status_code == 200:
                used_credits = response.headers.get("Spb-Used-Credits", "?")
                concurrency = response.headers.get("Spb-Max-Concurrency", "?")
                return {
                    "valid": True,
                    "details": (
                        "ScrapingBee Active | "
                        f"Max Concurrency: {concurrency} | Cost: {used_credits} cred"
                    ),
                }
            if response.status_code == 429:
                return {"valid": True, "details": "ScrapingBee Active (Rate Limit/Concurrency Full)"}
        except Exception:
            pass
        return None
