"""Asynchronous raw content retrieval for GitHub search results."""

from __future__ import annotations

import asyncio
import logging

import aiohttp

from modules.core.models import SourceFile

log = logging.getLogger("OmniContentFetcher")


class AsyncContentFetcher:
    """Download files selected by the scanner before local analysis."""

    def __init__(self, concurrency: int = 20, timeout_seconds: int = 15) -> None:
        self._semaphore = asyncio.Semaphore(concurrency)
        self._timeout = aiohttp.ClientTimeout(total=timeout_seconds)

    async def fetch_many(self, items: list[dict[str, str]]) -> list[SourceFile]:
        """Fetch raw file contents concurrently."""

        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            tasks = [self._fetch_one(session, item) for item in items]
            results = await asyncio.gather(*tasks)
        return [item for item in results if item is not None]

    async def _fetch_one(
        self,
        session: aiohttp.ClientSession,
        item: dict[str, str],
    ) -> SourceFile | None:
        raw_url = item.get("Raw URL", "")
        if not raw_url:
            return None

        async with self._semaphore:
            try:
                async with session.get(raw_url) as response:
                    if response.status != 200:
                        log.debug("Skipping %s because HTTP status was %s", raw_url, response.status)
                        return None
                    content = await response.text(errors="replace")
            except Exception as exc:
                log.debug("Failed to fetch %s: %s", raw_url, exc)
                return None

        return SourceFile(
            repository=item.get("Repository", ""),
            path=item.get("File Path", ""),
            url=item.get("URL", ""),
            raw_url=raw_url,
            content=content,
            pattern_source=item.get("Pattern Source"),
        )
