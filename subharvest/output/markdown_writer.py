from __future__ import annotations

from collections import Counter
from typing import IO

from subharvest.core.orchestrator import HarvestReport


def write_markdown(report: HarvestReport, fp: IO[str]) -> None:
    fp.write(f"# subharvest report — `{report.domain}`\n\n")
    fp.write(f"- Started: `{report.started_at}`\n")
    fp.write(f"- Finished: `{report.finished_at}`\n")
    fp.write(f"- Elapsed: `{report.elapsed_ms} ms`\n")
    fp.write(f"- Total subdomains: **{report.total}**\n")
    if report.filtered:
        fp.write(f"- Filtered (wildcard): {report.filtered}\n")
    fp.write("\n")

    if report.wildcard and report.wildcard.detected:
        fp.write("## Wildcard\n\n")
        fp.write(
            f"Wildcard DNS detected. Probes: `{', '.join(report.wildcard.probes)}`\n\n"
        )
        if report.wildcard.ips:
            fp.write(f"- Wildcard IPs: `{', '.join(sorted(report.wildcard.ips))}`\n")
        if report.wildcard.cnames:
            fp.write(
                f"- Wildcard CNAMEs: `{', '.join(sorted(report.wildcard.cnames))}`\n"
            )
        fp.write("\n")

    fp.write("## Sources\n\n")
    fp.write("| Source | Findings | Elapsed (ms) | Status |\n")
    fp.write("|---|---:|---:|---|\n")
    for s in report.sources:
        if s.skipped:
            status = f"skipped ({s.skip_reason or 'n/a'})"
        elif s.error:
            status = f"error: {s.error}"
        else:
            status = "ok"
        fp.write(
            f"| {s.source} | {len(s.findings)} | {s.elapsed_ms} | {status} |\n"
        )
    fp.write("\n")

    # Source breakdown
    counts: Counter[str] = Counter()
    for sub in report.subdomains:
        for src in sub.sources:
            counts[src] += 1
    if counts:
        fp.write("## Unique subdomains by source\n\n")
        for src, n in counts.most_common():
            fp.write(f"- `{src}`: {n}\n")
        fp.write("\n")

    # Interesting findings
    saas = [s for s in report.subdomains if s.saas_cname and not s.filtered_wildcard]
    if saas:
        fp.write("## SaaS CNAME candidates (potential takeover surface)\n\n")
        fp.write("| Subdomain | CNAME(s) | Provider |\n|---|---|---|\n")
        for s in saas:
            fp.write(
                f"| `{s.name}` | `{', '.join(s.cnames)}` | {s.saas_cname} |\n"
            )
        fp.write("\n")

    fp.write("## Subdomains\n\n")
    fp.write("| Name | Sources | Resolved | IPs | CNAMEs |\n|---|---|---|---|---|\n")
    for s in report.subdomains:
        if s.filtered_wildcard:
            continue
        fp.write(
            f"| `{s.name}` | {', '.join(s.sources) or '—'} | "
            f"{'yes' if s.resolved else 'no'} | "
            f"{', '.join(s.ips) or '—'} | {', '.join(s.cnames) or '—'} |\n"
        )
    fp.write("\n")
