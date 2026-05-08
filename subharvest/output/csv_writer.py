from __future__ import annotations

import csv
from typing import IO

from subharvest.core.orchestrator import HarvestReport


def write_csv(report: HarvestReport, fp: IO[str]) -> None:
    writer = csv.writer(fp, lineterminator="\n")
    writer.writerow(
        [
            "name",
            "sources",
            "first_seen",
            "resolved",
            "ips",
            "cnames",
            "saas_cname",
            "filtered_wildcard",
        ]
    )
    for s in report.subdomains:
        writer.writerow(
            [
                s.name,
                ";".join(s.sources),
                s.first_seen or "",
                "true" if s.resolved else "false",
                ";".join(s.ips),
                ";".join(s.cnames),
                s.saas_cname or "",
                "true" if s.filtered_wildcard else "false",
            ]
        )
