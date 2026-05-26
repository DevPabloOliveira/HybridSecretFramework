from .base import BaseValidator


class ShodanValidator(BaseValidator):
    """Strategy validator for Shodan API keys."""

    def check(self, key: str):
        try:
            response = self.session.get(f"https://api.shodan.io/api-info?key={key}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                plan = data.get("plan", "unknown")
                credits = data.get("query_credits", 0)
                return {"valid": True, "details": f"Plan: {plan} | Credits: {credits}"}
        except Exception:
            return None
        return None
