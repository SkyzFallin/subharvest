from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

import httpx

from subharvest import __version__

USER_AGENT = f"subharvest/{__version__} (+https://github.com/SkyzFallin/subharvest)"
DEFAULT_HTTP_HEADERS = {"User-Agent": USER_AGENT}

# Retry policy for transient upstream failures.
# Sources are independent and allowed to fail, but a single 429 or 504 from a
# flaky provider should not be enough to drop a source from the run.
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BASE_DELAY = 1.0  # seconds; exponentially backed off
RETRY_AFTER_CAP = 30.0  # seconds; never sleep longer than this on Retry-After


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        # HTTP-date form is allowed by spec but rare in practice; ignore.
        return None


async def http_get_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    base_delay: float = DEFAULT_BASE_DELAY,
    sleep=asyncio.sleep,
) -> httpx.Response:
    """Issue a GET with retry on transient errors.

    Retries on httpx network/timeout exceptions, HTTP 429, and HTTP 5xx.
    4xx responses other than 429 are surfaced immediately (permanent).
    Honors Retry-After (delta-seconds form), capped at RETRY_AFTER_CAP.
    """
    last_exc: BaseException | None = None
    last_resp: httpx.Response | None = None

    for attempt in range(max_attempts):
        try:
            resp = await client.get(url, params=params)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            last_exc = exc
            if attempt + 1 >= max_attempts:
                raise
            await sleep(base_delay * (2 ** attempt))
            continue

        transient = resp.status_code == 429 or 500 <= resp.status_code < 600
        if transient and attempt + 1 < max_attempts:
            last_resp = resp
            ra = _parse_retry_after(resp.headers.get("Retry-After"))
            delay = ra if ra is not None else base_delay * (2 ** attempt)
            delay = min(delay, RETRY_AFTER_CAP)
            await sleep(delay)
            continue

        resp.raise_for_status()
        return resp

    # All attempts exhausted on transient failure.
    if last_resp is not None:
        last_resp.raise_for_status()
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("retry loop exited without a response")


class SourceKind(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


@dataclass
class Finding:
    name: str
    source: str
    first_seen: str | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class SourceResult:
    source: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    elapsed_ms: int = 0
    skipped: bool = False
    skip_reason: str | None = None


class Source(ABC):
    name: str = "base"
    kind: SourceKind = SourceKind.PASSIVE
    requires_key: bool = False
    timeout_seconds: float = 30.0  # per-request HTTP timeout
    max_attempts: int = DEFAULT_MAX_ATTEMPTS

    def __init__(self, config: dict | None = None):
        self.config = config or {}

    @abstractmethod
    async def fetch(self, domain: str) -> list[Finding]:
        ...

    def available(self) -> tuple[bool, str | None]:
        if self.requires_key and not self.config.get("api_key"):
            return False, f"missing API key for {self.name}"
        return True, None

    @property
    def total_budget_seconds(self) -> float:
        """Total time the orchestrator allows for fetch(), accounting for retries
        and exponential backoff between attempts."""
        backoff_total = sum(
            DEFAULT_BASE_DELAY * (2 ** i) for i in range(self.max_attempts - 1)
        )
        # Cap any one backoff at RETRY_AFTER_CAP (matches helper)
        backoff_total = min(
            backoff_total, RETRY_AFTER_CAP * (self.max_attempts - 1)
        )
        return self.timeout_seconds * self.max_attempts + backoff_total + 5
