from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from subharvest.core.resolver import AsyncResolver, Resolution
from subharvest.core.wildcard import WildcardFingerprint, detect_wildcard
from subharvest.sources.base import Finding, Source, SourceResult


# Known SaaS providers commonly tied to dangling-CNAME takeover. Surfaced for
# the operator; not used to make takeover claims in v1.
SAAS_CNAME_PATTERNS = (
    "cloudfront.net",
    "azurewebsites.net",
    "github.io",
    "herokuapp.com",
    "s3.amazonaws.com",
    "shopify.com",
    "wordpress.com",
    "ghost.io",
    "readme.io",
    "netlify.app",
    "vercel.app",
    "fastly.net",
    "trafficmanager.net",
    "elasticbeanstalk.com",
    "cloudapp.net",
    "azure-api.net",
    "pantheonsite.io",
    "myshopify.com",
    "zendesk.com",
    "helpscoutdocs.com",
    "surge.sh",
    "bitbucket.io",
)


@dataclass
class SubdomainRecord:
    name: str
    sources: list[str] = field(default_factory=list)
    first_seen: str | None = None
    resolved: bool = False
    ips: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)
    filtered_wildcard: bool = False
    saas_cname: str | None = None

    def add_source(self, source: str, finding: Finding) -> None:
        if source not in self.sources:
            self.sources.append(source)
        if finding.first_seen and (
            self.first_seen is None or finding.first_seen < self.first_seen
        ):
            self.first_seen = finding.first_seen
        for k, v in finding.extra.items():
            existing = self.extra.get(k)
            if existing is None:
                self.extra[k] = v
            elif isinstance(existing, list):
                if v not in existing:
                    existing.append(v)
            elif existing != v:
                self.extra[k] = [existing, v]


@dataclass
class HarvestReport:
    domain: str
    started_at: str
    finished_at: str
    elapsed_ms: int
    sources: list[SourceResult]
    subdomains: list[SubdomainRecord]
    wildcard: WildcardFingerprint | None = None

    @property
    def total(self) -> int:
        return sum(1 for s in self.subdomains if not s.filtered_wildcard)

    @property
    def filtered(self) -> int:
        return sum(1 for s in self.subdomains if s.filtered_wildcard)


def _classify_saas(cnames: list[str]) -> str | None:
    for c in cnames:
        c_low = c.lower().rstrip(".")
        for pat in SAAS_CNAME_PATTERNS:
            # suffix match on label boundary — avoid `notgithub.io` matching `github.io`
            if c_low == pat or c_low.endswith("." + pat):
                return pat
    return None


async def _run_source(source: Source, domain: str) -> SourceResult:
    available, reason = source.available()
    if not available:
        return SourceResult(source=source.name, skipped=True, skip_reason=reason)

    started = time.perf_counter()
    try:
        findings = await asyncio.wait_for(
            source.fetch(domain), timeout=source.timeout_seconds + 5
        )
    except asyncio.TimeoutError:
        return SourceResult(
            source=source.name,
            error="timeout",
            elapsed_ms=int((time.perf_counter() - started) * 1000),
        )
    except Exception as exc:  # noqa: BLE001 - degrade gracefully per source
        return SourceResult(
            source=source.name,
            error=f"{type(exc).__name__}: {exc}",
            elapsed_ms=int((time.perf_counter() - started) * 1000),
        )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return SourceResult(source=source.name, findings=findings, elapsed_ms=elapsed_ms)


def _merge(results: list[SourceResult]) -> dict[str, SubdomainRecord]:
    records: dict[str, SubdomainRecord] = {}
    for sr in results:
        for f in sr.findings:
            rec = records.get(f.name)
            if rec is None:
                rec = SubdomainRecord(name=f.name)
                records[f.name] = rec
            rec.add_source(sr.source, f)
    return records


class Orchestrator:
    def __init__(
        self,
        sources: list[Source],
        resolver: AsyncResolver | None = None,
    ):
        self.sources = sources
        self.resolver = resolver

    async def run(
        self,
        domain: str,
        resolve: bool = False,
        check_wildcard: bool = True,
        resolve_concurrency: int = 50,
    ) -> HarvestReport:
        domain = domain.strip().lower().lstrip(".")
        started_at = datetime.now(timezone.utc).isoformat()
        t0 = time.perf_counter()

        results = await asyncio.gather(
            *[_run_source(s, domain) for s in self.sources]
        )

        records_map = _merge(results)

        wildcard_fp: WildcardFingerprint | None = None
        if (resolve or check_wildcard) and self.resolver is None:
            self.resolver = AsyncResolver()

        if check_wildcard and self.resolver is not None:
            wildcard_fp = await detect_wildcard(domain, self.resolver)

        if resolve and self.resolver is not None:
            names = list(records_map.keys())
            resolutions: list[Resolution] = await self.resolver.resolve_many(
                names, concurrency=resolve_concurrency
            )
            for res in resolutions:
                rec = records_map.get(res.name)
                if rec is None:
                    continue
                rec.resolved = res.resolved
                rec.ips = res.ips
                rec.cnames = res.cnames
                rec.saas_cname = _classify_saas(res.cnames)
                if wildcard_fp and wildcard_fp.matches(res):
                    rec.filtered_wildcard = True

        finished_at = datetime.now(timezone.utc).isoformat()
        elapsed_ms = int((time.perf_counter() - t0) * 1000)

        subdomains = sorted(records_map.values(), key=lambda r: r.name)
        return HarvestReport(
            domain=domain,
            started_at=started_at,
            finished_at=finished_at,
            elapsed_ms=elapsed_ms,
            sources=list(results),
            subdomains=subdomains,
            wildcard=wildcard_fp,
        )
