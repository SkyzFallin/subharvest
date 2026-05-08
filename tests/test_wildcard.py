from __future__ import annotations

import pytest

from subharvest.core.resolver import Resolution
from subharvest.core.wildcard import WildcardFingerprint, detect_wildcard


class StubResolver:
    def __init__(self, ips: list[str], cnames: list[str] | None = None):
        self.ips = ips
        self.cnames = cnames or []
        self.calls = 0

    async def resolve(self, name: str) -> Resolution:
        self.calls += 1
        return Resolution(
            name=name,
            resolved=bool(self.ips),
            ips=list(self.ips),
            cnames=list(self.cnames),
        )


@pytest.mark.asyncio
async def test_wildcard_detected_when_random_probes_resolve():
    fp = await detect_wildcard("example.com", StubResolver(["1.2.3.4"]))
    assert fp.detected is True
    assert "1.2.3.4" in fp.ips
    assert len(fp.probes) == 3


@pytest.mark.asyncio
async def test_no_wildcard_when_probes_dont_resolve():
    fp = await detect_wildcard("example.com", StubResolver([]))
    assert fp.detected is False
    assert not fp.ips


def test_fingerprint_matches_only_when_subset():
    fp = WildcardFingerprint(detected=True, ips={"1.2.3.4"}, cnames=set())
    assert fp.matches(Resolution("a", True, ["1.2.3.4"], [])) is True
    assert fp.matches(Resolution("b", True, ["10.0.0.1"], [])) is False
