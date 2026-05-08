from __future__ import annotations

import asyncio
import re

import dns.asyncresolver
import dns.exception

from subharvest.sources.base import Finding, Source, SourceKind

_HOSTNAME_RE = re.compile(r"([a-z0-9_-]+\.)+[a-z0-9_-]+", re.IGNORECASE)
_INCLUDE_RE = re.compile(r"include:([^\s]+)", re.IGNORECASE)


class DNSRecordsSource(Source):
    """Harvest subdomains from the target's own zone records.

    Pulls SOA, NS, MX, TXT (SPF include: chain), and DMARC rua/ruf addresses.
    """

    name = "dns_records"
    kind = SourceKind.PASSIVE
    requires_key = False
    timeout_seconds = 15.0

    async def fetch(self, domain: str) -> list[Finding]:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = self.timeout_seconds

        seen: dict[str, Finding] = {}

        async def _add(name: str, kind: str) -> None:
            name = name.strip(".").lower()
            if not name or not name.endswith(domain):
                return
            if name in seen:
                return
            seen[name] = Finding(name=name, source=self.name, extra={"record": kind})

        async def _query(rtype: str, qname: str | None = None):
            try:
                ans = await resolver.resolve(qname or domain, rtype)
                return list(ans)
            except (dns.exception.DNSException, Exception):
                return []

        # SOA, NS, MX
        for record in await _query("SOA"):
            await _add(str(record.mname), "SOA")
        for record in await _query("NS"):
            await _add(str(record.target), "NS")
        for record in await _query("MX"):
            await _add(str(record.exchange), "MX")

        # TXT (SPF include chain — single hop)
        spf_hosts: list[str] = []
        for record in await _query("TXT"):
            text = b"".join(record.strings).decode("utf-8", errors="ignore")
            if "v=spf1" in text.lower():
                spf_hosts.extend(_INCLUDE_RE.findall(text))
                for host in _HOSTNAME_RE.findall(text):
                    await _add(host, "SPF")

        # Recurse one hop into SPF includes (often the interesting bit)
        for host in spf_hosts:
            for record in await _query("TXT", qname=host):
                text = b"".join(record.strings).decode("utf-8", errors="ignore")
                for h in _HOSTNAME_RE.findall(text):
                    await _add(h, "SPF-include")

        # DMARC
        for record in await _query("TXT", qname=f"_dmarc.{domain}"):
            text = b"".join(record.strings).decode("utf-8", errors="ignore")
            for match in re.findall(r"(?:rua|ruf)=([^;]+)", text, re.IGNORECASE):
                for addr in match.split(","):
                    addr = addr.strip()
                    if addr.startswith("mailto:"):
                        addr = addr[len("mailto:"):]
                    if "@" in addr:
                        addr = addr.split("@", 1)[1]
                    await _add(addr, "DMARC")

        return list(seen.values())
