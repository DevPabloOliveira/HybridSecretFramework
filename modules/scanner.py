import csv
import logging
import os
import sys
import time
from typing import Any

import requests


class ColoredFormatter(logging.Formatter):
    """Small terminal formatter used by the GitHub discovery scanner."""

    grey = "\x1b[38;20m"
    blue = "\x1b[34;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format_str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format_str + reset,
        logging.INFO: blue + format_str + reset,
        logging.WARNING: yellow + format_str + reset,
        logging.ERROR: red + format_str + reset,
        logging.CRITICAL: bold_red + format_str + reset,
    }

    def format(self, record: logging.LogRecord) -> str:
        log_fmt = self.FORMATS.get(record.levelno, self.format_str)
        formatter = logging.Formatter(log_fmt, datefmt="%H:%M:%S")
        return formatter.format(record)


log = logging.getLogger("HybridSecretScanner")
log.setLevel(logging.INFO)
if not log.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColoredFormatter())
    log.addHandler(handler)


def github_search(token: str, query: str, page: int) -> dict[str, Any] | None:
    """Run one GitHub code-search request with rate-limit handling."""

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "HybridSecretFramework-Scanner/4.0",
    }
    params = {
        "q": query,
        "per_page": 100,
        "page": page,
        "sort": "indexed",
        "order": "desc",
    }

    try:
        response = requests.get(
            "https://api.github.com/search/code",
            headers=headers,
            params=params,
            timeout=20,
        )
        if response.status_code == 200:
            return response.json()
        if response.status_code == 401:
            log.critical("GitHub token is invalid or expired (HTTP 401).")
            return None
        if response.status_code in {403, 429}:
            wait_seconds = _rate_limit_wait_seconds(response)
            log.warning("GitHub rate limit reached. Sleeping for %s seconds.", wait_seconds)
            time.sleep(wait_seconds)
            return None

        log.error("HTTP %s while searching for '%s'.", response.status_code, query)
        return None
    except requests.exceptions.Timeout:
        log.error("GitHub API connection timed out.")
    except requests.RequestException as exc:
        log.error("GitHub API request failed: %s", exc)
    return None


def _rate_limit_wait_seconds(response: requests.Response) -> int:
    reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
    current_time = int(time.time())
    wait_seconds = max(10, reset_time - current_time + 2)
    return min(wait_seconds, 60)


class HybridSecretScanner:
    """Layer-zero discovery scanner that recovers candidate files from GitHub."""

    def __init__(self, token: str) -> None:
        self.token = token

    def run_scan(self, csv_path: str, pages: int = 1) -> list[dict[str, str]]:
        """Read a pattern CSV and return GitHub file metadata for analysis."""

        if not os.path.exists(csv_path):
            log.error("Pattern file not found: %s", csv_path)
            return []

        patterns = self._load_patterns(csv_path)
        if not patterns:
            log.error("No search patterns were loaded from %s.", csv_path)
            return []

        results: list[dict[str, str]] = []
        log.info("Loaded %s search patterns. Pages per pattern: %s", len(patterns), pages)

        for index, pattern in enumerate(patterns, start=1):
            log.info("[%s/%s] Searching pattern: %s", index, len(patterns), pattern)
            pattern_hits = self._scan_pattern(pattern, pages, results)
            if pattern_hits:
                log.info("Pattern '%s' recovered %s candidate files.", pattern, pattern_hits)
            time.sleep(3)

        log.info("Discovery finished. %s files recovered for hybrid analysis.", len(results))
        return results

    @staticmethod
    def _load_patterns(csv_path: str) -> list[str]:
        try:
            with open(csv_path, "r", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                return [
                    row["pattern"].strip()
                    for row in reader
                    if row.get("pattern") and row["pattern"].strip()
                ]
        except OSError as exc:
            log.error("Failed to read pattern CSV: %s", exc)
            return []

    def _scan_pattern(
        self,
        pattern: str,
        pages: int,
        results: list[dict[str, str]],
    ) -> int:
        pattern_hits = 0
        for page_num in range(1, pages + 1):
            data = github_search(self.token, pattern, page_num)
            if not data:
                break

            items = data.get("items", [])
            if not items:
                break

            for item in items:
                html_url = item["html_url"]
                results.append(
                    {
                        "Repository": item["repository"]["full_name"],
                        "File Path": item["path"],
                        "URL": html_url,
                        "Pattern Source": pattern,
                        "Raw URL": html_url.replace("github.com", "raw.githubusercontent.com").replace(
                            "/blob/",
                            "/",
                        ),
                    }
                )
                pattern_hits += 1

            if page_num < pages:
                time.sleep(2)

        return pattern_hits


# Backward-compatible alias kept to avoid breaking older local scripts.
OmniScanner = HybridSecretScanner
