"""
Rich-based console output helpers for SecAudit.
"""

from __future__ import annotations

from rich.console import Console as RichConsole
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from ..core.base_module import Finding, ModuleResult, Severity

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "bold bright_red",
    Severity.MEDIUM:   "bold yellow",
    Severity.LOW:      "bold cyan",
    Severity.INFO:     "bold green",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "[!]",
    Severity.HIGH:     "[!]",
    Severity.MEDIUM:   "[~]",
    Severity.LOW:      "[-]",
    Severity.INFO:     "[+]",
}


class Console:
    """Wrapper around Rich console with SecAudit-specific helpers."""

    def __init__(self, verbose: bool = False) -> None:
        self.rich = RichConsole()
        self.verbose = verbose

    def banner(self) -> None:
        banner_text = Text()
        banner_text.append(
            r"""
  ____            _                  _ _ _
 / ___|  ___  ___/ \  _   _  __| (_) |_
 \___ \ / _ \/ __/ _ \| | | |/ _` | | __|
  ___) |  __/ (_/ ___ \ |_| | (_| | | |_
 |____/ \___|\___\/ \_/\__,_|\__,_|_|\__|

""",
            style="bold cyan",
        )
        banner_text.append("  Web & Network Security Assessment Toolkit\n", style="dim")
        banner_text.append("  For authorized use only — unauthorized testing is illegal\n", style="bold red")
        self.rich.print(banner_text)

    def section(self, title: str) -> None:
        self.rich.print(f"\n[bold cyan]{'─' * 60}[/bold cyan]")
        self.rich.print(f"[bold white]  {title}[/bold white]")
        self.rich.print(f"[bold cyan]{'─' * 60}[/bold cyan]")

    def spinner(self, description: str) -> Progress:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=self.rich,
        )

    def print_finding(self, finding: Finding) -> None:
        style = SEVERITY_STYLES.get(finding.severity, "white")
        icon = SEVERITY_ICONS.get(finding.severity, " ")
        self.rich.print(f"  {icon} [{style}]{finding.severity.value}[/{style}] {finding.title}")
        if self.verbose:
            if finding.description:
                self.rich.print(f"     [dim]{finding.description}[/dim]")
            if finding.evidence:
                self.rich.print(f"     [blue]Evidence:[/blue] [dim]{finding.evidence}[/dim]")
            if finding.recommendation:
                self.rich.print(f"     [green]Fix:[/green] [dim]{finding.recommendation}[/dim]")

    def print_module_result(self, result: ModuleResult) -> None:
        self.section(result.module_name.replace("_", " ").upper())

        if result.error:
            self.rich.print(f"  [bold red]ERROR:[/bold red] {result.error}")
            return

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        rank = {s: i for i, s in enumerate(severity_order)}
        for finding in sorted(result.findings, key=lambda f: rank.get(f.severity, 99)):
            self.print_finding(finding)

    def print_summary(self, results: list[ModuleResult]) -> None:
        table = Table(title="Scan Summary", border_style="cyan", show_lines=True)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="center")

        from collections import Counter
        counter: Counter = Counter()
        for result in results:
            for finding in result.findings:
                counter[finding.severity] += 1

        styles = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH:     "bold bright_red",
            Severity.MEDIUM:   "bold yellow",
            Severity.LOW:      "bold cyan",
            Severity.INFO:     "bold green",
        }
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = counter.get(sev, 0)
            if count > 0 or sev in (Severity.CRITICAL, Severity.HIGH):
                table.add_row(f"[{styles[sev]}]{sev.value}[/{styles[sev]}]", str(count))

        self.rich.print()
        self.rich.print(table)

    def success(self, msg: str) -> None:
        self.rich.print(f"[bold green][+][/bold green] {msg}")

    def info(self, msg: str) -> None:
        self.rich.print(f"[bold cyan][*][/bold cyan] {msg}")

    def error(self, msg: str) -> None:
        self.rich.print(f"[bold red][!][/bold red] {msg}")

    def warning(self, msg: str) -> None:
        self.rich.print(f"[bold yellow][~][/bold yellow] {msg}")
