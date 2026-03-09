"""
SecAudit CLI entry point.
"""

from __future__ import annotations

import sys
import urllib3
from pathlib import Path

import click

from . import __version__
from .core.target import Target
from .modules import (
    HeaderCheckerModule,
    PortScannerModule,
    SSLCheckerModule,
    TechFingerprintModule,
    VulnScannerModule,
)
from .report.generator import ReportGenerator
from .utils.console import Console

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ALL_MODULES = {
    "ports":       PortScannerModule,
    "headers":     HeaderCheckerModule,
    "ssl":         SSLCheckerModule,
    "fingerprint": TechFingerprintModule,
    "vulns":       VulnScannerModule,
}


@click.group()
@click.version_option(__version__, prog_name="secaudit")
def cli() -> None:
    """SecAudit — Web & Network Security Assessment Toolkit."""


@cli.command()
@click.argument("target_url")
@click.option(
    "--modules", "-m",
    default="all",
    show_default=True,
    help=(
        "Comma-separated list of modules to run. "
        f"Available: {', '.join(ALL_MODULES)}. Use 'all' to run everything."
    ),
)
@click.option("--output", "-o", default=None, help="Output HTML report path (e.g. report.html)")
@click.option("--json-output", "-j", default=None, help="Output JSON report path")
@click.option("--timeout", "-t", default=10, show_default=True, help="Request timeout in seconds")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed finding descriptions")
@click.option(
    "--ports", "-p",
    default=None,
    help="Custom ports for port scanner, e.g. '22,80,443,8080' (default: common ports)"
)
@click.option("--workers", default=100, show_default=True, help="Max concurrent threads for port scan")
def scan(
    target_url: str,
    modules: str,
    output: str | None,
    json_output: str | None,
    timeout: int,
    verbose: bool,
    ports: str | None,
    workers: int,
) -> None:
    """
    Run a security assessment against TARGET_URL.

    \b
    Examples:
      secaudit scan https://example.com
      secaudit scan https://example.com -m headers,ssl,vulns -v
      secaudit scan 192.168.1.1 -m ports -p 22,80,443,3306 -o report.html

    \b
    WARNING: Only scan systems you own or have explicit written authorization to test.
    Unauthorized testing is illegal under the CFAA, Computer Misuse Act, and similar laws.
    """
    console = Console(verbose=verbose)
    console.banner()

    # Parse target
    try:
        target = Target(target_url)
    except ValueError as e:
        console.error(str(e))
        sys.exit(1)

    console.info(f"Target: [bold]{target}[/bold]  (IP: {target.ip or 'unresolved'})")

    # Resolve modules
    if modules.strip().lower() == "all":
        selected = list(ALL_MODULES.keys())
    else:
        selected = [m.strip() for m in modules.split(",")]
        invalid = [m for m in selected if m not in ALL_MODULES]
        if invalid:
            console.error(f"Unknown module(s): {', '.join(invalid)}")
            console.info(f"Available: {', '.join(ALL_MODULES)}")
            sys.exit(1)

    console.info(f"Modules: [cyan]{', '.join(selected)}[/cyan]")
    console.info(f"Timeout: {timeout}s  |  Verbose: {verbose}")

    results = []
    custom_ports = [int(p) for p in ports.split(",")] if ports else None

    for module_name in selected:
        module_cls = ALL_MODULES[module_name]

        # Build module-specific kwargs
        kwargs: dict = {"timeout": timeout, "verbose": verbose}
        if module_name == "ports":
            if custom_ports:
                kwargs["ports"] = custom_ports
            kwargs["max_workers"] = workers

        module = module_cls(**kwargs)
        console.info(f"Running [bold]{module.name}[/bold]...")

        with console.spinner(f"  Scanning with {module.name}...") as progress:
            task = progress.add_task(f"  {module.description}", total=None)
            result = module.run(target)
            progress.update(task, completed=True)

        console.print_module_result(result)
        results.append(result)

    # Summary
    console.print_summary(results)

    # Reports
    if output:
        path = Path(output)
        gen = ReportGenerator(results, str(target))
        gen.generate(path)
        console.success(f"HTML report saved to [bold]{path}[/bold]")

    if json_output:
        path = Path(json_output)
        gen = ReportGenerator(results, str(target))
        gen.generate_json(path)
        console.success(f"JSON report saved to [bold]{path}[/bold]")


@cli.command("list-modules")
def list_modules() -> None:
    """List all available scanner modules."""
    console = Console()
    console.rich.print("\n[bold cyan]Available modules:[/bold cyan]\n")
    for name, cls in ALL_MODULES.items():
        console.rich.print(f"  [bold]{name:<15}[/bold] {cls.description}")
    console.rich.print()


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
