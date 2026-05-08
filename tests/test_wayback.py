from __future__ import annotations

import httpx
import pytest
import respx

from subharvest.sources.wayback import WaybackSource


@pytest.mark.asyncio
async def test_wayback_parses_fixture(fixture_loader):
    payload = fixture_loader("wayback_example.json")
    src = WaybackSource()

    with respx.mock(base_url="https://web.archive.org") as mock:
        mock.get("/cdx/search/cdx").mock(
            return_value=httpx.Response(200, json=payload)
        )
        findings = await src.fetch("example.com")

    names = sorted(f.name for f in findings)
    assert names == ["archive.example.com", "blog.example.com", "www.example.com"]
