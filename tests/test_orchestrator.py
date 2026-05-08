from __future__ import annotations

import io
import json

import pytest

from subharvest.core.orchestrator import Orchestrator, SubdomainRecord, _classify_saas
from subharvest.core.resolver import Resolution
from subharvest.core.wildcard import WildcardFingerprint
from subharvest.output import write_csv, write_json, write_markdown, write_txt
from subharvest.sources.base import Finding, Source, SourceKind


class FakeSource(Source):
    name = "fake"
    kind = SourceKind.PASSIVE
    requires_key = False

    def __init__(self, findings: list[Finding], config: dict | None = None):
        super().__init__(config)
        self._findings = findings

    async def fetch(self, domain: str) -> list[Finding]:
        return self._findings


class FailingSource(Source):
    name = "failing"
    kind = SourceKind.PASSIVE
    requires_key = False

    async def fetch(self, domain: str) -> list[Finding]:
        raise RuntimeError("kaboom")


class StubResolver:
    """Deterministic resolver. Configurable per-name response."""

    def __init__(self, responses: dict[str, Resolution]):
        self.responses = responses

    async def resolve(self, name: str) -> Resolution:
        return self.responses.get(name, Resolution(name=name, resolved=False, ips=[], cnames=[]))

    async def resolve_many(self, names, concurrency: int = 50):
        return [await self.resolve(n) for n in names]


@pytest.mark.asyncio
async def test_orchestrator_merges_dedups_and_records_provenance():
    sources = [
        FakeSource([
            Finding(name="www.example.com", source="fake", first_seen="2024-01-01"),
            Finding(name="api.example.com", source="fake", first_seen="2024-02-01"),
        ]),
        FakeSource([
            Finding(name="api.example.com", source="fake2", first_seen="2023-12-01"),
            Finding(name="blog.example.com", source="fake2", first_seen="2024-03-01"),
        ]),
    ]
    sources[1].name = "fake2"

    orch = Orchestrator(sources=sources, resolver=StubResolver({}))
    report = await orch.run("example.com", resolve=False, check_wildcard=False)

    by_name = {s.name: s for s in report.subdomains}
    assert set(by_name) == {"www.example.com", "api.example.com", "blog.example.com"}
    # api was found by both sources
    assert sorted(by_name["api.example.com"].sources) == ["fake", "fake2"]
    # earliest first_seen wins
    assert by_name["api.example.com"].first_seen == "2023-12-01"


@pytest.mark.asyncio
async def test_orchestrator_handles_source_errors_gracefully():
    sources = [
        FakeSource([Finding(name="ok.example.com", source="fake")]),
        FailingSource(),
    ]
    orch = Orchestrator(sources=sources, resolver=StubResolver({}))
    report = await orch.run("example.com", resolve=False, check_wildcard=False)

    by_source = {s.source: s for s in report.sources}
    assert by_source["failing"].error is not None
    assert "kaboom" in by_source["failing"].error
    # The healthy source still produced findings
    assert any(s.name == "ok.example.com" for s in report.subdomains)


@pytest.mark.asyncio
async def test_resolve_and_wildcard_filter():
    # wildcard probe will resolve to 1.2.3.4
    wildcard_ip = "1.2.3.4"
    responses = {
        "real.example.com": Resolution("real.example.com", True, ["10.0.0.1"], []),
        "fake-wild.example.com": Resolution("fake-wild.example.com", True, [wildcard_ip], []),
    }

    # Pre-fingerprinted wildcard (we bypass the random probe by injecting one)
    class WildResolver(StubResolver):
        async def resolve(self, name: str) -> Resolution:
            if "subharvest-wildcard" in name:
                return Resolution(name=name, resolved=True, ips=[wildcard_ip], cnames=[])
            return await super().resolve(name)

    sources = [
        FakeSource([
            Finding(name="real.example.com", source="fake"),
            Finding(name="fake-wild.example.com", source="fake"),
        ])
    ]
    orch = Orchestrator(sources=sources, resolver=WildResolver(responses))
    report = await orch.run("example.com", resolve=True, check_wildcard=True)

    by_name = {s.name: s for s in report.subdomains}
    assert by_name["real.example.com"].resolved is True
    assert by_name["real.example.com"].filtered_wildcard is False
    assert by_name["fake-wild.example.com"].filtered_wildcard is True
    assert report.wildcard is not None and report.wildcard.detected is True


def test_classify_saas():
    assert _classify_saas(["foo.cloudfront.net"]) == "cloudfront.net"
    assert _classify_saas(["a.b.github.io"]) == "github.io"
    assert _classify_saas(["plain.example.com"]) is None
    # Trailing dot from DNS canonical form must not break matching
    assert _classify_saas(["foo.cloudfront.net."]) == "cloudfront.net"
    # Substring-but-not-suffix must NOT match: regression for v0.1 false-positive bug
    assert _classify_saas(["notgithub.io.attacker.com"]) is None
    assert _classify_saas(["evil-cloudfront.net.example.com"]) is None


@pytest.mark.asyncio
async def test_output_writers_round_trip(tmp_path):
    sources = [
        FakeSource([
            Finding(name="www.example.com", source="fake", first_seen="2024-01-01"),
            Finding(name="api.example.com", source="fake"),
        ])
    ]
    orch = Orchestrator(sources=sources, resolver=StubResolver({}))
    report = await orch.run("example.com", resolve=False, check_wildcard=False)

    # JSON
    buf = io.StringIO()
    write_json(report, buf)
    data = json.loads(buf.getvalue())
    assert data["domain"] == "example.com"
    assert data["total"] >= 2

    # TXT — sorted, one per line
    buf = io.StringIO()
    write_txt(report, buf)
    lines = [l for l in buf.getvalue().splitlines() if l]
    assert lines == sorted(lines)
    assert "www.example.com" in lines

    # CSV — header + rows
    buf = io.StringIO()
    write_csv(report, buf)
    csv_text = buf.getvalue()
    assert csv_text.splitlines()[0].startswith("name,sources,")

    # Markdown — well-formed
    buf = io.StringIO()
    write_markdown(report, buf)
    md = buf.getvalue()
    assert "# subharvest report" in md
    assert "## Subdomains" in md
