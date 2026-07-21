"""netpol-audit CLI. No authorization.yml/Engagement gate — this tool
operates entirely through the user's own already-authenticated
kubeconfig access, the same reasoning already applied to the sibling
sbom-audit and netwatch repos."""

from __future__ import annotations

import sys

import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option(package_name="netpol-audit")
def cli():
    """🛡️ netpol-audit — Kubernetes NetworkPolicy coverage & permissiveness auditing."""


@cli.command()
@click.option("--namespace", "-n", default=None, help="Limit to a single namespace (default: all).")
@click.option("--kubeconfig", default=None, help="Path to a kubeconfig file (default: standard kubectl resolution).")
@click.option("--context", default=None, help="kubeconfig context to use (default: current context).")
@click.option("--json", "json_output", default=None, type=click.Path())
@click.option("--db", "db_path", default=None, type=click.Path(),
              help="SQLite database path — records this run for historical tracking (see 'netpol-audit history').")
@click.option("--baseline", "baseline_path", default=None, type=click.Path(exists=True),
              help="JSON file of max allowed findings per severity (e.g. {\"max_high\": 0}) for CI gating. "
                   "Without this, the default gate is: fail on any CRITICAL/HIGH finding.")
def scan(namespace, kubeconfig, context, json_output, db_path, baseline_path):
    """Scan a Kubernetes cluster for NetworkPolicy coverage gaps and overly permissive rules."""
    from netpol_audit.core.analyze import analyze
    from netpol_audit.core.cluster import (
        ClusterConnectionError,
        fetch_network_policies,
        fetch_pods,
        load_kube_config,
    )
    from netpol_audit.reports.terminal import print_findings

    try:
        load_kube_config(kubeconfig_path=kubeconfig, context=context)
        pods = fetch_pods(namespace=namespace)
        policies = fetch_network_policies(namespace=namespace)
    except ClusterConnectionError as exc:
        console.print(f"[red]✘ {exc}[/red]")
        sys.exit(1)

    console.print(f"Fetched {len(pods)} pod(s) and {len(policies)} NetworkPolic{'y' if len(policies) == 1 else 'ies'}.")

    findings = analyze(pods, policies)
    label = f"namespace: {namespace}" if namespace else "all namespaces"
    print_findings(label, findings)

    if json_output:
        import json as json_module
        with open(json_output, "w") as f:
            json_module.dump(findings, f, indent=2)
        console.print(f"[green]✔[/green] Wrote {len(findings)} finding(s) to {json_output}")

    if db_path:
        from netpol_audit.core.db import record_run
        run_id = record_run(db_path, label=label, pod_count=len(pods), policy_count=len(policies), findings=findings)
        console.print(f"[green]✔[/green] Recorded run #{run_id} to {db_path}")

    if baseline_path:
        from netpol_audit.core.baseline import evaluate_baseline, load_baseline
        limits = load_baseline(baseline_path)
        violations = evaluate_baseline(findings, limits)
        if violations:
            console.print("[red]✘ Baseline gate failed:[/red]")
            for v in violations:
                console.print(f"  [red]•[/red] {v}")
            sys.exit(1)
        console.print("[green]✔[/green] Baseline gate passed.")
    elif any(f["severity"] in ("CRITICAL", "HIGH") for f in findings):
        sys.exit(1)


@cli.command()
@click.option("--db", "db_path", required=True, type=click.Path(exists=True), help="SQLite database written by previous 'scan --db' runs.")
@click.option("--limit", default=20, show_default=True, help="Number of most recent runs to show.")
def history(db_path, limit):
    """Show past scan runs recorded via 'scan --db' as a trend table."""
    from netpol_audit.core.db import fetch_history
    from netpol_audit.reports.terminal import print_history

    runs = fetch_history(db_path, limit=limit)
    print_history(runs)


@cli.command("verify-enforcement")
@click.option("--namespace", "-n", default=None,
              help="Existing namespace to run the test in (default: create and delete a temporary one).")
@click.option("--kubeconfig", default=None, help="Path to a kubeconfig file (default: standard kubectl resolution).")
@click.option("--context", default=None, help="kubeconfig context to use (default: current context).")
@click.option("--timeout", default=60, show_default=True, help="Seconds to wait for the test pods to become ready.")
@click.option("--keep", is_flag=True, default=False,
              help="Don't delete the test pods/policy/namespace afterward (for debugging).")
@click.option("--json", "json_output", default=None, type=click.Path())
def verify_enforcement(namespace, kubeconfig, context, timeout, keep, json_output):
    """Actively verify the cluster's CNI enforces NetworkPolicy at all.

    Deploys a real client pod, a real server pod, and a deny-all ingress
    NetworkPolicy, then attempts a real connection to check whether it's
    actually blocked. Auditing declared NetworkPolicy objects (as 'scan'
    does) can't catch this: some CNIs (e.g. kind's default kindnet) accept
    NetworkPolicy objects without enforcing them, silently making every
    policy in the cluster non-functional. This creates and deletes real
    cluster resources.
    """
    from netpol_audit.core.cluster import ClusterConnectionError, load_kube_config
    from netpol_audit.core.enforcement import run_enforcement_probe
    from netpol_audit.reports.terminal import print_findings

    try:
        load_kube_config(kubeconfig_path=kubeconfig, context=context)
    except ClusterConnectionError as exc:
        console.print(f"[red]✘ {exc}[/red]")
        sys.exit(1)

    console.print("Deploying a real client pod, server pod, and deny-all NetworkPolicy to test enforcement...")
    try:
        finding = run_enforcement_probe(namespace=namespace, timeout=timeout, keep=keep)
    except Exception as exc:
        console.print(f"[red]✘ Enforcement probe failed: {exc}[/red]")
        sys.exit(1)

    findings = [finding] if finding else [{
        "severity": "INFO",
        "title": "CNI correctly enforces NetworkPolicy",
        "target": "cluster",
        "description": "A deny-all ingress NetworkPolicy was applied to a real test pod, and a "
                        "real connection attempt from another pod was correctly blocked.",
    }]
    print_findings("CNI enforcement verification", findings)

    if json_output:
        import json as json_module
        with open(json_output, "w") as f:
            json_module.dump(findings, f, indent=2)
        console.print(f"[green]✔[/green] Wrote {len(findings)} finding(s) to {json_output}")

    if any(f["severity"] == "CRITICAL" for f in findings):
        sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
