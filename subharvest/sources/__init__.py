from subharvest.sources.base import Finding, Source, SourceKind, SourceResult
from subharvest.sources.crtsh import CrtShSource
from subharvest.sources.otx import OTXSource
from subharvest.sources.urlscan import UrlScanSource
from subharvest.sources.wayback import WaybackSource
from subharvest.sources.dns_records import DNSRecordsSource

PASSIVE_SOURCES: list[type[Source]] = [
    CrtShSource,
    OTXSource,
    UrlScanSource,
    WaybackSource,
    DNSRecordsSource,
]

ALL_SOURCES: list[type[Source]] = list(PASSIVE_SOURCES)


def source_by_name(name: str) -> type[Source] | None:
    for s in ALL_SOURCES:
        if s.name == name:
            return s
    return None


__all__ = [
    "Finding",
    "Source",
    "SourceKind",
    "SourceResult",
    "PASSIVE_SOURCES",
    "ALL_SOURCES",
    "source_by_name",
]
