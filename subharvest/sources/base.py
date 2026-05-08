from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

from subharvest import __version__

USER_AGENT = f"subharvest/{__version__} (+https://github.com/SkyzFallin/subharvest)"
DEFAULT_HTTP_HEADERS = {"User-Agent": USER_AGENT}


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
    timeout_seconds: float = 30.0

    def __init__(self, config: dict | None = None):
        self.config = config or {}

    @abstractmethod
    async def fetch(self, domain: str) -> list[Finding]:
        ...

    def available(self) -> tuple[bool, str | None]:
        if self.requires_key and not self.config.get("api_key"):
            return False, f"missing API key for {self.name}"
        return True, None
