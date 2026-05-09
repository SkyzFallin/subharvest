from __future__ import annotations

import asyncio
import os
import re
import sys
import tomllib
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from subharvest import __version__
from subharvest.core.orchestrator import Orchestrator
from subharvest.core.resolver import AsyncResolver
from subharvest.output import WRITERS
from subharvest.sources import ALL_SOURCES, source_by_name

app = typer.Typer(
    add_completion=False,
    help="subharvest — passive subdomain enumeration from public sources.",
    no_args_is_help=True,
)


DEFAULT_CONFIG_PATH = Path.home() / ".subharvest" / "config.toml"


def _load_config(path: Path | None) -> dict:
    target = path or DEFAULT_CONFIG_PATH
    if not target.exists():
        return {}
    try:
        with open(target, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


def _build_sources(
    config: dict,
    only: list[str],
    skip: list[str],
    active: bool,
):
    selected: list = []
    only_set = set(only) if only else None
    skip_set = set(skip)
    for cls in ALL_SOURCES:
        if only_set is not None and cls.name not in only_set:
            continue
        if cls.name in skip_set:
            continue
        # Active sources only when --active is given (none registered in v0.1)
        if cls.kind.value == "active" and not active:
            continue
        src_cfg = (config.get("sources") or {}).get(cls.name, {}) or {}
        # Allow API key from env var SUBHARVEST_<NAME>_API_KEY
        env_key = os.environ.get(f"SUBHARVEST_{cls.name.upper()}_API_KEY")
        if env_key and "api_key" not in src_cfg:
            src_cfg = {**src_cfg, "api_key": env_key}
        selected.append(cls(config=src_cfg))
    return selected


@app.command()
def main(
    domain: Optional[str] = typer.Argument(None, help="Target apex domain (e.g. example.com)"),
    active: bool = typer.Option(False, "--active", help="Enable active discovery (brute force, permutation, AXFR)"),
    skip: list[str] = typer.Option([], "--skip", help="Skip a specific source (repeatable)"),
    only: list[str] = typer.Option([], "--only", help="Only use this source (repeatable)"),
    list_sources: bool = typer.Option(False, "--list-sources", help="Print all available sources and exit"),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", help="Custom DNS brute force wordlist"),
    permutations: Optional[Path] = typer.Option(None, "--permutations", help="Custom permutation list"),
    no_permute: bool = typer.Option(False, "--no-permute", help="Disable permutation even in active mode"),
    threads: int = typer.Option(50, "--threads", help="Brute force concurrency"),
    resolve: bool = typer.Option(False, "--resolve", help="Resolve each subdomain after collection"),
    resolver_ip: Optional[str] = typer.Option(None, "--resolver", help="Custom DNS resolver IP"),
    doh: bool = typer.Option(False, "--doh", help="Use DNS-over-HTTPS"),
    fmt: str = typer.Option("json", "--format", help="Output format: json, txt, csv, md"),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Write to file instead of stdout"),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress progress output"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show per-source query trace"),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Custom config file"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI color"),
    output_dir: Path = typer.Option(
        Path("output"),
        "--output-dir",
        help="Directory for the auto-saved txt artifact (relative to cwd)",
    ),
    no_auto_output: bool = typer.Option(
        False, "--no-auto-output", help="Disable auto-save of txt artifact"
    ),
    version: bool = typer.Option(False, "--version", help="Print version and exit"),
):
    """Passive subdomain enumeration. Active probing optional, never default."""
    console = Console(stderr=True, no_color=no_color, quiet=False)
    stdout_console = Console(stderr=False, no_color=no_color)

    if version:
        stdout_console.print(f"subharvest {__version__}")
        raise typer.Exit(0)

    if list_sources:
        table = Table(title="Available sources")
        table.add_column("name")
        table.add_column("kind")
        table.add_column("requires key")
        for cls in ALL_SOURCES:
            table.add_row(cls.name, cls.kind.value, "yes" if cls.requires_key else "no")
        stdout_console.print(table)
        raise typer.Exit(0)

    if not domain:
        console.print("[red]error:[/red] missing domain argument")
        raise typer.Exit(2)

    if fmt not in WRITERS:
        console.print(f"[red]error:[/red] unknown format '{fmt}' (choose: {', '.join(WRITERS)})")
        raise typer.Exit(2)

    # Validate --only names
    for name in only:
        if source_by_name(name) is None:
            console.print(f"[red]error:[/red] unknown source in --only: {name}")
            raise typer.Exit(2)

    if active:
        console.print(
            "[yellow]warning:[/yellow] --active is not implemented in v0.1; "
            "active sources will be skipped."
        )

    if doh and not quiet:
        console.print("[yellow]note:[/yellow] --doh is recognized but uses system resolver in v0.1.")

    config = _load_config(config_path)
    sources = _build_sources(config, only=only, skip=skip, active=active)

    if not sources:
        console.print("[red]error:[/red] no sources selected")
        raise typer.Exit(2)

    if not quiet:
        names = ", ".join(s.name for s in sources)
        console.print(f"[cyan]subharvest[/cyan] querying {len(sources)} source(s): {names}")

    # DNS resolver is only built when we actually need to send queries.
    # In pure passive mode (no --resolve, no --active) we MUST NOT generate
    # any traffic toward the target's nameservers — that would violate the
    # "zero traffic to target by default" guarantee.
    needs_dns = resolve or active
    nameservers = [resolver_ip] if resolver_ip else None
    resolver = AsyncResolver(nameservers=nameservers) if needs_dns else None

    orch = Orchestrator(sources=sources, resolver=resolver)

    try:
        report = asyncio.run(
            orch.run(domain=domain, resolve=resolve, check_wildcard=needs_dns)
        )
    except KeyboardInterrupt:
        console.print("[yellow]aborted by user[/yellow]")
        raise typer.Exit(130)

    if not quiet:
        if report.wildcard and report.wildcard.detected:
            console.print(
                f"[yellow]wildcard detected[/yellow]: ips={sorted(report.wildcard.ips)} "
                f"cnames={sorted(report.wildcard.cnames)}"
            )
        for s in report.sources:
            if s.skipped:
                if verbose:
                    console.print(f"  - [dim]{s.source} skipped: {s.skip_reason}[/dim]")
                continue
            if s.error:
                console.print(f"  - [red]{s.source} error[/red]: {s.error}")
                continue
            console.print(
                f"  - [green]{s.source}[/green]: {len(s.findings)} findings ({s.elapsed_ms} ms)"
            )
        console.print(
            f"[bold]total:[/bold] {report.total} subdomain(s)"
            + (f", filtered (wildcard): {report.filtered}" if report.filtered else "")
        )

        # Show the actual list of subdomains. Skip when we're already going to
        # print the txt list to stdout (would just duplicate it).
        will_print_txt_to_stdout = output is None and fmt == "txt"
        visible = [s for s in report.subdomains if not s.filtered_wildcard]
        if visible and not will_print_txt_to_stdout:
            console.print()
            console.print("[bold]subdomains:[/bold]")
            for s in sorted(visible, key=lambda r: r.name):
                if s.resolved and s.ips:
                    suffix = f" [dim]→ {', '.join(s.ips[:3])}[/dim]"
                elif s.cnames:
                    suffix = f" [dim]→ {s.cnames[0]}[/dim]"
                else:
                    suffix = ""
                saas = (
                    f" [yellow](saas: {s.saas_cname})[/yellow]"
                    if s.saas_cname
                    else ""
                )
                console.print(f"  [cyan]{s.name}[/cyan]{suffix}{saas}")

    writer = WRITERS[fmt]
    if output:
        with open(output, "w", encoding="utf-8") as f:
            writer(report, f)
        if not quiet:
            console.print(f"wrote {output}")
    else:
        writer(report, sys.stdout)

    # Auto-save plaintext artifact alongside any other output. Independent of
    # --format / -o so piping JSON to another tool still leaves a usable file.
    if not no_auto_output:
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            safe_domain = re.sub(r"[^A-Za-z0-9._-]", "_", domain)
            artifact = output_dir / f"{safe_domain}-{stamp}.txt"
            with open(artifact, "w", encoding="utf-8") as f:
                WRITERS["txt"](report, f)
            if not quiet:
                console.print(f"[dim]artifact:[/dim] {artifact}")
        except OSError as exc:
            console.print(f"[yellow]warning:[/yellow] could not write artifact: {exc}")


if __name__ == "__main__":
    app()
