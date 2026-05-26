from .base import BaseValidator


class GoogleValidator(BaseValidator):
    """Strategy validator for Google API keys."""

    def check(self, key: str):
        try:
            url = (
                "https://maps.googleapis.com/maps/api/distancematrix/json"
                f"?units=imperial&origins=Washington,DC&destinations=New+York+City,NY&key={key}"
            )
            response = self.session.get(url, timeout=10)
            data = response.json()

            status = data.get("status")
            error_msg = data.get("error_message", "")

            if status == "OK":
                return {"valid": True, "details": "Google Maps (Active & Billing OK)"}
            if status == "REQUEST_DENIED" and "API key" not in error_msg:
                return {"valid": True, "details": f"Google Maps (Restricted: {error_msg})"}
            if "You have exceeded" in error_msg:
                return {"valid": True, "details": "Google Maps (Active but Quota Exceeded)"}
        except Exception:
            pass
        return None
