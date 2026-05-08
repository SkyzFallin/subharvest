from __future__ import annotations

from typing import IO

from subharvest.core.orchestrator import HarvestReport


def write_txt(report: HarvestReport, fp: IO[str]) -> None:
    names = sorted({s.name for s in report.subdomains if not s.filtered_wildcard})
    for n in names:
        fp.write(n + "\n")
