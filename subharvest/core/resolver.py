from __future__ import annotations

import asyncio
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception


@dataclass
class Resolution:
    name: str
    resolved: bool
    ips: list[str]
    cnames: list[str]


class AsyncResolver:
    def __init__(self, nameservers: list[str] | None = None, timeout: float = 5.0):
        self.resolver = dns.asyncresolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        self.resolver.lifetime = timeout

    async def resolve(self, name: str) -> Resolution:
        ips: list[str] = []
        cnames: list[str] = []

        for rtype in ("A", "AAAA"):
            try:
                ans = await self.resolver.resolve(name, rtype)
                for r in ans:
                    ips.append(r.address)
                # Capture chain CNAMEs from the response
                if ans.chaining_result:
                    for rrset in ans.chaining_result.cnames:
                        for item in rrset:
                            cnames.append(str(item.target).rstrip("."))
            except dns.exception.DNSException:
                pass
            except Exception:
                pass

        if not ips:
            try:
                ans = await self.resolver.resolve(name, "CNAME")
                for r in ans:
                    cnames.append(str(r.target).rstrip("."))
            except Exception:
                pass

        # de-dupe preserving order
        ips = list(dict.fromkeys(ips))
        cnames = list(dict.fromkeys(cnames))
        return Resolution(name=name, resolved=bool(ips), ips=ips, cnames=cnames)

    async def resolve_many(
        self, names: list[str], concurrency: int = 50
    ) -> list[Resolution]:
        sem = asyncio.Semaphore(concurrency)

        async def _one(n: str) -> Resolution:
            async with sem:
                return await self.resolve(n)

        return await asyncio.gather(*[_one(n) for n in names])
