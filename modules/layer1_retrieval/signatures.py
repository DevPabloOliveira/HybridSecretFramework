"""Regex signatures for broad candidate recovery.

Regex is intentionally retained only as the first recovery layer, as the paper
argues it has high recall but insufficient semantic precision by itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern


@dataclass(frozen=True, slots=True)
class SecretSignature:
    provider: str
    regex: Pattern[str]
    confidence: str


DEFAULT_SIGNATURES: tuple[SecretSignature, ...] = (
    SecretSignature(
        "AWS Access Key",
        re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        "CRITICAL",
    ),
    SecretSignature("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "CRITICAL"),
    SecretSignature("GitHub Token", re.compile(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}"), "CRITICAL"),
    SecretSignature("GitLab Personal Access Token", re.compile(r"glpat-[0-9a-zA-Z\-_]{20}"), "CRITICAL"),
    SecretSignature("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{24}"), "CRITICAL"),
    SecretSignature("OpenAI API Key", re.compile(r"sk-[a-zA-Z0-9]{48}"), "CRITICAL"),
    SecretSignature("OpenAI Project Key", re.compile(r"sk-proj-[a-zA-Z0-9\-_]{20,}"), "CRITICAL"),
    SecretSignature("Slack Token", re.compile(r"xox[baprs]-([0-9a-zA-Z]{10,48})?"), "HIGH"),
    SecretSignature("Twilio Account SID", re.compile(r"AC[a-f0-9]{32}"), "HIGH"),
    SecretSignature("Mailgun API Key", re.compile(r"key-[0-9a-zA-Z]{32}"), "HIGH"),
    SecretSignature("PyPI Upload Token", re.compile(r"pypi-AgEI[a-zA-Z0-9\-_]{50,}"), "CRITICAL"),
    SecretSignature("Discord Bot Token", re.compile(r"[A-Za-z0-9]{24,}\.[A-Za-z0-9]{6}\.[A-Za-z0-9_-]{27,}"), "HIGH"),
    SecretSignature("Telegram Bot Token", re.compile(r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}"), "HIGH"),
    SecretSignature("UUID-like Secret", re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "LOW"),
    SecretSignature("Generic 32-char Candidate", re.compile(r"\b[a-zA-Z0-9]{32}\b"), "MEDIUM"),
    SecretSignature("Generic 40-char Hex Candidate", re.compile(r"\b[a-fA-F0-9]{40}\b"), "MEDIUM"),
    SecretSignature("Generic 64-char Hex Candidate", re.compile(r"\b[a-fA-F0-9]{64}\b"), "MEDIUM"),
)
