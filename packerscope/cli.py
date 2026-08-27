"""PackerScope command-line interface.

Provides the ``packerscope`` CLI for single file analysis and batch
scanning.

Usage:
    packerscope scan sample.exe
    packerscope scan --format json,html samples/
    packerscope batch samples/ --workers 8
    packerscope info sample.exe
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from packerscope import __version__
from packerscope.config import Config
from packerscope.orchestrator import Orchestrator
from packerscope.utils.logger import setup_logging

console = Console()


@click.group()
@click.version_option(__version__, prog_name="PackerScope")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.option("--json-log", is_flag=True, help="Output logs in JSON format")
@click.option("--log-file", type=click.Path(), default=None, help="Log to file")
@click.pass_context
def main(ctx: click.Context, verbose: bool, debug: bool, json_log: bool, log_file: str | None) -> None:
    """PackerScope — Automatic packer detection, classification & unpacking."""
    level = "DEBUG" if debug else ("INFO" if verbose else "WARNING")
    log_path = Path(log_file) if log_file else None
    setup_logging(level=level, log_file=log_path, json_output=json_log)
    ctx.ensure_object(dict)
    ctx.obj["config"] = Config()


@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--format", "-f", "formats", default="json", help="Report formats (comma-separated: json,csv,md,html)")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output directory")
@click.option("--no-unpack", is_flag=True, help="Skip unpacking step")
@click.option("--no-verify", is_flag=True, help="Skip unpacking verification")
@click.pass_context
def scan(
    ctx: click.Context,
    target: str,
    formats: str,
    output: str | None,
    no_unpack: bool,
    no_verify: bool,
) -> None:
    """Analyze a PE file or directory for packer detection."""
    config: Config = ctx.obj["config"]

    if output:
        config.output_dir = Path(output)
    if no_unpack:
        config.enable_unpack = False
    if no_verify:
        config.enable_verification = False

    # Parse report formats
    from packerscope.core.enums import ReportFormat
    fmt_map = {"json": ReportFormat.JSON, "csv": ReportFormat.CSV, "md": ReportFormat.MARKDOWN, "html": ReportFormat.HTML}
    config.report_formats = [fmt_map[f.strip()] for f in formats.split(",") if f.strip() in fmt_map]

    target_path = Path(target)
    orch = Orchestrator(config)

    if target_path.is_file():
        _analyze_single(orch, target_path)
    elif target_path.is_dir():
        _analyze_directory(orch, target_path, config)
    else:
        console.print(f"[red]Error: {target} is not a valid file or directory[/red]")
        sys.exit(1)


@main.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--workers", "-w", type=int, default=None, help="Number of concurrent workers")
@click.option("--format", "-f", "formats", default="json,csv", help="Report formats")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output directory")
@click.pass_context
def batch(
    ctx: click.Context,
    directory: str,
    workers: int | None,
    formats: str,
    output: str | None,
) -> None:
    """Batch-analyze all PE files in a directory."""
    config: Config = ctx.obj["config"]
    if output:
        config.output_dir = Path(output)

    from packerscope.core.enums import ReportFormat
    fmt_map = {"json": ReportFormat.JSON, "csv": ReportFormat.CSV, "md": ReportFormat.MARKDOWN, "html": ReportFormat.HTML}
    config.report_formats = [fmt_map[f.strip()] for f in formats.split(",") if f.strip() in fmt_map]

    dir_path = Path(directory)
    pe_files = _find_pe_files(dir_path)

    if not pe_files:
        console.print(f"[yellow]No PE files found in {directory}[/yellow]")
        return

    console.print(f"[cyan]Found {len(pe_files)} PE file(s) to analyze[/cyan]")
    orch = Orchestrator(config)
    orch.initialize()

    reports = orch.analyze_batch(pe_files, max_workers=workers)

    # Summary table
    table = Table(title="Batch Analysis Results", show_lines=True)
    table.add_column("File", style="cyan")
    table.add_column("Packed", justify="center")
    table.add_column("Packer", style="yellow")
    table.add_column("Confidence")
    table.add_column("Duration")

    for r in reports:
        packed_str = "[red]YES[/red]" if r.verdict.is_packed else "[green]NO[/green]"
        table.add_row(
            r.file_name,
            packed_str,
            r.verdict.packer.value,
            f"{r.verdict.confidence:.1%}",
            f"{r.analysis_duration_seconds:.2f}s",
        )

    console.print(table)
    packed_count = sum(1 for r in reports if r.verdict.is_packed)
    console.print(f"\n[bold]Summary:[/bold] {packed_count}/{len(reports)} files detected as packed")


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.pass_context
def info(ctx: click.Context, file: str) -> None:
    """Show quick PE file information (no detection pipeline)."""
    from packerscope.context import PEContext

    file_path = Path(file)
    with PEContext(file_path) as pctx:
        pctx.initialize()

        console.print(Panel(f"[bold cyan]{file_path.name}[/bold cyan]", subtitle=f"{file_path}"))

        if pctx.metadata:
            m = pctx.metadata
            table = Table(title="File Metadata")
            table.add_column("Property", style="cyan")
            table.add_column("Value")
            table.add_row("MD5", m.md5)
            table.add_row("SHA256", m.sha256)
            table.add_row("Imphash", m.imphash or "N/A")
            table.add_row("Size", f"{m.file_size:,} bytes")
            table.add_row("Machine", m.machine_type)
            console.print(table)

        if pctx.pe and pctx.pe.is_valid:
            pe = pctx.pe
            sec_table = Table(title="Sections")
            sec_table.add_column("Name")
            sec_table.add_column("VSize", justify="right")
            sec_table.add_column("RSize", justify="right")
            sec_table.add_column("Entropy", justify="right")
            from packerscope.utils.entropy import calculate_entropy
            for sec in pe.sections:
                data = sec.data if sec.data else b""
                ent = calculate_entropy(data) if data else 0.0
                sec_table.add_row(
                    sec.name, f"{sec.virtual_size:,}",
                    f"{sec.raw_size:,}", f"{ent:.4f}",
                )
            console.print(sec_table)


def _analyze_single(orch: Orchestrator, file_path: Path) -> None:
    """Analyze a single file and print results."""
    try:
        report = orch.analyze(file_path)
        _print_report(report)
    except Exception as e:
        console.print(f"[red]Analysis failed: {e}[/red]")
        sys.exit(1)


def _analyze_directory(orch: Orchestrator, dir_path: Path, config: Config) -> None:
    """Analyze all PE files in a directory."""
    pe_files = _find_pe_files(dir_path)
    if not pe_files:
        console.print(f"[yellow]No PE files found in {dir_path}[/yellow]")
        return

    console.print(f"[cyan]Found {len(pe_files)} PE file(s)[/cyan]")
    orch.initialize()
    for f in pe_files:
        try:
            report = orch.analyze(f)
            _print_report_summary(report)
        except Exception as e:
            console.print(f"[red]{f.name}: Error — {e}[/red]")


def _find_pe_files(directory: Path) -> list[Path]:
    """Recursively find PE files in a directory."""
    extensions = {".exe", ".dll", ".sys", ".drv", ".ocx", ".scr"}
    files = []
    for ext in extensions:
        files.extend(directory.rglob(f"*{ext}"))
    return sorted(files)


def _print_report(report) -> None:
    """Print a detailed Rich-formatted analysis report."""
    v = report.verdict
    color = "red" if v.is_packed else "green"
    status = "PACKED" if v.is_packed else "NOT PACKED"

    console.print(Panel(
        Text.from_markup(f"[bold {color}]{status}[/bold {color}]"),
        title=f"{report.file_name}",
        subtitle=f"Confidence: {v.confidence:.1%} ({v.confidence_level.value})",
    ))

    if v.is_packed:
        console.print(f"  Packer: [yellow bold]{v.packer.value}[/yellow bold]")

    if v.reasons:
        console.print("\n  [bold]Reasons:[/bold]")
        for r in v.reasons[:8]:
            console.print(f"    • {r}")

    console.print(f"\n  MD5:    [dim]{report.metadata.md5}[/dim]")
    console.print(f"  SHA256: [dim]{report.metadata.sha256}[/dim]")
    console.print(f"  Size:   {report.metadata.file_size:,} bytes")
    console.print(f"  Time:   {report.analysis_duration_seconds:.3f}s")
    console.print()


def _print_report_summary(report) -> None:
    """Print a one-line summary for batch processing."""
    v = report.verdict
    status = "[red]PACKED[/red]" if v.is_packed else "[green]CLEAN[/green]"
    packer = f" [{v.packer.value}]" if v.is_packed else ""
    console.print(
        f"  {report.file_name:40s} {status}{packer} "
        f"({v.confidence:.0%}) {report.analysis_duration_seconds:.2f}s"
    )


if __name__ == "__main__":
    main()
