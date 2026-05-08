from __future__ import annotations

import httpx

from subharvest.sources.base import DEFAULT_HTTP_HEADERS, Finding, Source, SourceKind


class OTXSource(Source):
    name = "otx"
    kind = SourceKind.PASSIVE
    requires_key = False
    timeout_seconds = 30.0

    URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

    async def fetch(self, domain: str) -> list[Finding]:
        async with httpx.AsyncClient(timeout=self.timeout_seconds, headers=DEFAULT_HTTP_HEADERS) as client:
            resp = await client.get(self.URL.format(domain=domain))
            resp.raise_for_status()
            data = resp.json()

        seen: dict[str, Finding] = {}
        for record in data.get("passive_dns", []):
            hostname = (record.get("hostname") or "").strip().lower()
            if not hostname or not hostname.endswith(domain):
                continue
            first_seen = record.get("first")
            if hostname in seen:
                continue
            seen[hostname] = Finding(name=hostname, source=self.name, first_seen=first_seen)
        return list(seen.values())
