from __future__ import annotations

import httpx
import pytest
import respx

from subharvest.sources.otx import OTXSource


@pytest.mark.asyncio
async def test_otx_parses_fixture(fixture_loader):
    payload = fixture_loader("otx_example.json")
    src = OTXSource()

    with respx.mock(base_url="https://otx.alienvault.com") as mock:
        mock.get("/api/v1/indicators/domain/example.com/passive_dns").mock(
            return_value=httpx.Response(200, json=payload)
        )
        findings = await src.fetch("example.com")

    names = sorted(f.name for f in findings)
    assert names == ["api.example.com", "blog.example.com", "www.example.com"]
    # earliest first_seen wins on dedupe — we only keep first occurrence
    api = next(f for f in findings if f.name == "api.example.com")
    assert api.first_seen == "2024-01-10T00:00:00"
