from __future__ import annotations

from urllib.parse import urlparse

import httpx

from subharvest.sources.base import (
    DEFAULT_HTTP_HEADERS,
    Finding,
    Source,
    SourceKind,
    http_get_with_retry,
)


class WaybackSource(Source):
    name = "wayback"
    kind = SourceKind.PASSIVE
    requires_key = False
    timeout_seconds = 60.0

    URL = "https://web.archive.org/cdx/search/cdx"

    async def fetch(self, domain: str) -> list[Finding]:
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original,timestamp",
            "collapse": "urlkey",
        }
        async with httpx.AsyncClient(timeout=self.timeout_seconds, headers=DEFAULT_HTTP_HEADERS) as client:
            resp = await http_get_with_retry(client, self.URL, params=params)
            try:
                rows = resp.json()
            except Exception:
                return []

        if not rows or len(rows) < 2:
            return []

        seen: dict[str, Finding] = {}
        # First row is header
        for row in rows[1:]:
            if len(row) < 1:
                continue
            url = row[0]
            ts = row[1] if len(row) > 1 else None
            try:
                host = (urlparse(url).hostname or "").lower()
            except Exception:
                continue
            if not host or not host.endswith(domain):
                continue
            if host in seen:
                continue
            seen[host] = Finding(name=host, source=self.name, first_seen=ts)
        return list(seen.values())
