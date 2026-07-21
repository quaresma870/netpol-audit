"""Terminal report rendering for netpol-audit."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.table import Table

console = Console()

_SEVERITY_COLUMNS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_STYLE_MAP = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}


def print_findings(cluster_label: str, findings: list[dict]) -> None:
    console.print(f"\n[bold]── {cluster_label} ──[/bold]\n")

    if not findings:
        console.print("  No findings.")
        return

    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Target")

    for f in sorted(findings, key=lambda f: _SEVERITY_COLUMNS.index(f["severity"])):
        style = _STYLE_MAP[f["severity"]]
        table.add_row(f"[{style}]{f['severity']}[/{style}]", f["title"], f["target"])
    console.print(table)

    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in _SEVERITY_COLUMNS}
    summary = "  ".join(f"{counts[sev]} {sev}" for sev in _SEVERITY_COLUMNS if counts[sev] > 0)
    console.print(f"\n  {summary}\n")


def print_history(runs: list) -> None:
    """Renders past scan runs (most recent first) as a trend table —
    the terminal-native "dashboard" view over a `--db` history, one
    row per run with its severity counts side by side so a regression
    or improvement across runs is visible at a glance."""
    console.print("\n[bold]── Scan history ──[/bold]\n")

    if not runs:
        console.print("  No recorded runs.")
        return

    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("Timestamp")
    table.add_column("Label")
    table.add_column("Pods")
    table.add_column("Policies")
    for sev in _SEVERITY_COLUMNS:
        table.add_column(sev)
    table.add_column("Total")

    for run in runs:
        row = [run.timestamp, run.label, str(run.pod_count), str(run.policy_count)]
        for sev in _SEVERITY_COLUMNS:
            count = run.severity_counts[sev]
            style = _STYLE_MAP[sev]
            row.append(f"[{style}]{count}[/{style}]" if count else str(count))
        row.append(str(run.total_findings))
        table.add_row(*row)

    console.print(table)
    console.print()
