from __future__ import annotations

import httpx

from subharvest.sources.base import DEFAULT_HTTP_HEADERS, Finding, Source, SourceKind


class CrtShSource(Source):
    name = "crtsh"
    kind = SourceKind.PASSIVE
    requires_key = False
    timeout_seconds = 30.0

    URL = "https://crt.sh/"

    async def fetch(self, domain: str) -> list[Finding]:
        params = {"q": f"%.{domain}", "output": "json"}
        async with httpx.AsyncClient(timeout=self.timeout_seconds, headers=DEFAULT_HTTP_HEADERS) as client:
            resp = await client.get(self.URL, params=params)
            resp.raise_for_status()
            try:
                data = resp.json()
            except Exception:
                return []

        seen: dict[str, Finding] = {}
        for entry in data:
            raw = entry.get("name_value") or ""
            first_seen = entry.get("entry_timestamp") or entry.get("not_before")
            for name in raw.splitlines():
                name = name.strip().lower().lstrip("*.")
                if not name or not name.endswith(domain):
                    continue
                if name in seen:
                    continue
                seen[name] = Finding(name=name, source=self.name, first_seen=first_seen)
        return list(seen.values())
