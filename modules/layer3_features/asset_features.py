"""Secret-asset association features.

The systematic mapping points to AssetHarvester/RiskHarvester-style evidence:
real operational risk increases when a candidate is linked to a host, endpoint,
database, or client initialization site.
"""

from __future__ import annotations

import re

from modules.core.models import AstContext, FeatureValue, SecretCandidate


URL_RE = re.compile(r"https?://[^\s'\"<>]+")
HOST_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|dev|cloud|local|internal)\b")
DB_RE = re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb|redis|amqp|jdbc):\/\/[^\s'\"<>]+")


def extract_asset_features(
    content: str,
    candidate: SecretCandidate,
    context: AstContext,
    window_size: int = 360,
) -> tuple[dict[str, FeatureValue], list[str]]:
    """Find nearby asset references and expose compact model features."""

    references = list(context.asset_references)
    kinds = list(context.asset_kinds)
    start = max(0, candidate.start_index - window_size)
    end = min(len(content), candidate.end_index + window_size)
    local_text = content[start:end]

    for regex, kind in ((DB_RE, "database"), (URL_RE, "url"), (HOST_RE, "host")):
        for match in regex.finditer(local_text):
            value = match.group(0).rstrip(".,);]")
            references.append(value)
            kinds.append(kind)

    references = _dedupe(references)
    kinds = _dedupe(kinds)
    evidence: list[str] = []
    if references:
        evidence.append("Candidate is near asset reference(s): " + ", ".join(references[:3]) + ".")

    return (
        {
            "has_asset_reference": bool(references),
            "asset_reference_count": len(references),
            "asset_kinds": ",".join(kinds),
            "asset_references": " | ".join(references[:5]),
            "has_database_asset": "database" in kinds,
            "has_url_asset": "url" in kinds,
            "has_host_asset": "host" in kinds,
        },
        evidence,
    )


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
