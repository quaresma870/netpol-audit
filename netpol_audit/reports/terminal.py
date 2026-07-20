"""Terminal report rendering for netpol-audit."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.table import Table

console = Console()


def print_findings(cluster_label: str, findings: list[dict]) -> None:
    console.print(f"\n[bold]── {cluster_label} ──[/bold]\n")

    if not findings:
        console.print("  No findings.")
        return

    style_map = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Target")

    for f in sorted(findings, key=lambda f: order.index(f["severity"])):
        style = style_map[f["severity"]]
        table.add_row(f"[{style}]{f['severity']}[/{style}]", f["title"], f["target"])
    console.print(table)

    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in order}
    summary = "  ".join(f"{counts[sev]} {sev}" for sev in order if counts[sev] > 0)
    console.print(f"\n  {summary}\n")
