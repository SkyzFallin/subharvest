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


class UrlScanSource(Source):
    name = "urlscan"
    kind = SourceKind.PASSIVE
    requires_key = False
    timeout_seconds = 30.0

    URL = "https://urlscan.io/api/v1/search/"

    async def fetch(self, domain: str) -> list[Finding]:
        params = {"q": f"domain:{domain}", "size": 1000}
        async with httpx.AsyncClient(timeout=self.timeout_seconds, headers=DEFAULT_HTTP_HEADERS) as client:
            resp = await http_get_with_retry(client, self.URL, params=params)
            data = resp.json()

        seen: dict[str, Finding] = {}
        for hit in data.get("results", []):
            page = hit.get("page", {}) or {}
            host = (page.get("domain") or "").strip().lower()
            if not host:
                url = page.get("url") or hit.get("task", {}).get("url") or ""
                try:
                    host = (urlparse(url).hostname or "").lower()
                except Exception:
                    host = ""
            if not host or not host.endswith(domain):
                continue
            if host in seen:
                continue
            seen[host] = Finding(name=host, source=self.name, first_seen=hit.get("task", {}).get("time"))
        return list(seen.values())
