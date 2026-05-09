from __future__ import annotations

import httpx
import pytest
import respx

from subharvest.sources.base import (
    _parse_retry_after,
    http_get_with_retry,
)


class FakeSleep:
    """Captures sleep calls without actually sleeping the test."""

    def __init__(self):
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


@pytest.mark.asyncio
async def test_retries_on_429_then_success():
    fake_sleep = FakeSleep()
    with respx.mock(base_url="https://example.test") as mock:
        route = mock.get("/api").mock(
            side_effect=[
                httpx.Response(429),
                httpx.Response(200, json={"ok": True}),
            ]
        )
        async with httpx.AsyncClient() as client:
            resp = await http_get_with_retry(
                client, "https://example.test/api", sleep=fake_sleep
            )
        assert resp.status_code == 200
        assert route.call_count == 2
        # one backoff delay between attempts
        assert len(fake_sleep.calls) == 1


@pytest.mark.asyncio
async def test_retries_on_5xx_chain_then_success():
    fake_sleep = FakeSleep()
    with respx.mock(base_url="https://example.test") as mock:
        mock.get("/api").mock(
            side_effect=[
                httpx.Response(503),
                httpx.Response(504),
                httpx.Response(200, json={"ok": True}),
            ]
        )
        async with httpx.AsyncClient() as client:
            resp = await http_get_with_retry(
                client, "https://example.test/api", sleep=fake_sleep
            )
        assert resp.status_code == 200
        # 1s, then 2s exponential backoff
        assert fake_sleep.calls == [1.0, 2.0]


@pytest.mark.asyncio
async def test_exhausts_retries_then_raises():
    fake_sleep = FakeSleep()
    with respx.mock(base_url="https://example.test") as mock:
        mock.get("/api").mock(return_value=httpx.Response(429))
        async with httpx.AsyncClient() as client:
            with pytest.raises(httpx.HTTPStatusError):
                await http_get_with_retry(
                    client, "https://example.test/api", sleep=fake_sleep
                )


@pytest.mark.asyncio
async def test_does_not_retry_on_4xx_other_than_429():
    fake_sleep = FakeSleep()
    with respx.mock(base_url="https://example.test") as mock:
        route = mock.get("/api").mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            with pytest.raises(httpx.HTTPStatusError):
                await http_get_with_retry(
                    client, "https://example.test/api", sleep=fake_sleep
                )
        assert route.call_count == 1
        assert fake_sleep.calls == []


@pytest.mark.asyncio
async def test_retries_on_timeout_then_success():
    fake_sleep = FakeSleep()
    with respx.mock(base_url="https://example.test") as mock:
        mock.get("/api").mock(
            side_effect=[
                httpx.ReadTimeout("timed out"),
                httpx.Response(200, json={"ok": True}),
            ]
        )
        async with httpx.AsyncClient() as client:
            resp = await http_get_with_retry(
                client, "https://example.test/api", sleep=fake_sleep
            )
        assert resp.status_code == 200
        assert fake_sleep.calls == [1.0]


@pytest.mark.asyncio
async def test_honors_retry_after_header():
    fake_sleep = FakeSleep()
    with respx.mock(base_url="https://example.test") as mock:
        mock.get("/api").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "5"}),
                httpx.Response(200, json={"ok": True}),
            ]
        )
        async with httpx.AsyncClient() as client:
            await http_get_with_retry(
                client, "https://example.test/api", sleep=fake_sleep
            )
        # Retry-After overrides exponential backoff
        assert fake_sleep.calls == [5.0]


@pytest.mark.asyncio
async def test_retry_after_capped():
    fake_sleep = FakeSleep()
    with respx.mock(base_url="https://example.test") as mock:
        mock.get("/api").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "9999"}),
                httpx.Response(200),
            ]
        )
        async with httpx.AsyncClient() as client:
            await http_get_with_retry(
                client, "https://example.test/api", sleep=fake_sleep
            )
        # Capped at 30s — never block the run on a hostile/buggy header
        assert fake_sleep.calls == [30.0]


def test_parse_retry_after_handles_garbage():
    assert _parse_retry_after(None) is None
    assert _parse_retry_after("") is None
    assert _parse_retry_after("not-a-number") is None
    assert _parse_retry_after("12") == 12.0
    assert _parse_retry_after("3.5") == 3.5
