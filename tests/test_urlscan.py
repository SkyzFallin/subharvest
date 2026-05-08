from __future__ import annotations

import httpx
import pytest
import respx

from subharvest.sources.urlscan import UrlScanSource


@pytest.mark.asyncio
async def test_urlscan_parses_fixture(fixture_loader):
    payload = fixture_loader("urlscan_example.json")
    src = UrlScanSource()

    with respx.mock(base_url="https://urlscan.io") as mock:
        mock.get("/api/v1/search/").mock(
            return_value=httpx.Response(200, json=payload)
        )
        findings = await src.fetch("example.com")

    names = sorted(f.name for f in findings)
    assert names == ["docs.example.com", "shop.example.com", "www.example.com"]
