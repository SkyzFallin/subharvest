from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from subharvest.core.resolver import AsyncResolver, Resolution


@dataclass
class WildcardFingerprint:
    detected: bool
    ips: set[str] = field(default_factory=set)
    cnames: set[str] = field(default_factory=set)
    probes: list[str] = field(default_factory=list)

    def matches(self, res: Resolution) -> bool:
        if not self.detected:
            return False
        if res.ips and set(res.ips).issubset(self.ips) and self.ips:
            return True
        if res.cnames and set(res.cnames).issubset(self.cnames) and self.cnames:
            return True
        return False


async def detect_wildcard(
    domain: str, resolver: AsyncResolver, probe_count: int = 3
) -> WildcardFingerprint:
    """Probe the apex with random subdomains. If any resolve, capture the IPs/CNAMEs.

    Returns a fingerprint that callers can use to filter out wildcard-matching
    findings.
    """
    fp = WildcardFingerprint(detected=False)
    for _ in range(probe_count):
        nonce = secrets.token_hex(8)
        probe = f"{nonce}-subharvest-wildcard.{domain}"
        fp.probes.append(probe)
        res = await resolver.resolve(probe)
        if res.resolved or res.cnames:
            fp.detected = True
            fp.ips.update(res.ips)
            fp.cnames.update(res.cnames)
    return fp
