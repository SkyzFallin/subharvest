from __future__ import annotations

import json

import httpx
import pytest
import respx

from subharvest.sources.crtsh import CrtShSource


@pytest.mark.asyncio
async def test_crtsh_parses_fixture(fixture_loader):
    payload = fixture_loader("crtsh_example.json")
    src = CrtShSource()

    with respx.mock(base_url="https://crt.sh") as mock:
        mock.get("/").mock(return_value=httpx.Response(200, json=payload))
        findings = await src.fetch("example.com")

    names = sorted(f.name for f in findings)
    # wildcard normalized to bare apex; multi-line entry split; case folded; out-of-zone dropped
    assert names == ["admin.example.com", "api.example.com", "example.com", "www.example.com"]
    # All findings carry source name
    assert all(f.source == "crtsh" for f in findings)


@pytest.mark.asyncio
async def test_crtsh_handles_invalid_json():
    src = CrtShSource()
    with respx.mock(base_url="https://crt.sh") as mock:
        mock.get("/").mock(return_value=httpx.Response(200, text="<html>error</html>"))
        findings = await src.fetch("example.com")
    assert findings == []
