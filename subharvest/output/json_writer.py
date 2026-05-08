from __future__ import annotations

import dataclasses
import json
from typing import IO

from subharvest.core.orchestrator import HarvestReport


def _report_to_dict(report: HarvestReport) -> dict:
    return {
        "domain": report.domain,
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "elapsed_ms": report.elapsed_ms,
        "total": report.total,
        "filtered_wildcard": report.filtered,
        "wildcard": (
            {
                "detected": report.wildcard.detected,
                "ips": sorted(report.wildcard.ips),
                "cnames": sorted(report.wildcard.cnames),
            }
            if report.wildcard
            else None
        ),
        "sources": [dataclasses.asdict(s) for s in report.sources],
        "subdomains": [dataclasses.asdict(s) for s in report.subdomains],
    }


def write_json(report: HarvestReport, fp: IO[str]) -> None:
    json.dump(_report_to_dict(report), fp, indent=2, sort_keys=False, default=str)
    fp.write("\n")
