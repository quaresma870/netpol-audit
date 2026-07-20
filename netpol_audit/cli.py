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
def scan(namespace, kubeconfig, context, json_output):
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

    if any(f["severity"] in ("CRITICAL", "HIGH") for f in findings):
        sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
