"""Orchestrates a full cluster analysis: coverage gaps (pods with no
NetworkPolicy at all) and permissive-policy findings (policies that
exist but don't actually restrict anything meaningfully)."""

from __future__ import annotations

from netpol_audit.core.netpol import NetworkPolicyInfo, PodInfo, find_uncovered_pods


def analyze(pods: list[PodInfo], policies: list[NetworkPolicyInfo]) -> list[dict]:
    findings: list[dict] = []

    uncovered_ingress = find_uncovered_pods(pods, policies, direction="Ingress")
    by_namespace: dict[str, list[PodInfo]] = {}
    for pod in uncovered_ingress:
        by_namespace.setdefault(pod.namespace, []).append(pod)

    for namespace, ns_pods in by_namespace.items():
        findings.append({
            "severity": "HIGH",
            "title": f"{len(ns_pods)} pod(s) with no NetworkPolicy (all ingress traffic allowed)",
            "target": namespace,
            "description": (
                f"In namespace '{namespace}', {len(ns_pods)} pod(s) are not selected by any "
                f"NetworkPolicy with 'Ingress' in policyTypes: "
                f"{', '.join(p.name for p in ns_pods[:10])}"
                f"{'...' if len(ns_pods) > 10 else ''}. A pod not selected by any NetworkPolicy "
                f"is non-isolated — ALL ingress traffic is allowed by default, independent of "
                f"whatever other NetworkPolicies exist for other pods in the namespace."
            ),
            "remediation": "Add a NetworkPolicy selecting these pods (even a default-deny policy "
                            "as a baseline, then explicit allow rules for legitimate traffic).",
        })

    for policy in policies:
        if not policy.has_ingress_rules:
            continue  # this policy doesn't touch ingress at all — nothing to say here
        if policy.ingress_rules_allow_all:
            findings.append({
                "severity": "MEDIUM",
                "title": f"NetworkPolicy '{policy.name}' has an ingress rule allowing all sources",
                "target": f"{policy.namespace}/{policy.name}",
                "description": (
                    f"'{policy.name}' in namespace '{policy.namespace}' has at least one ingress "
                    f"rule with no 'from' restriction — per Kubernetes' documented semantics, an "
                    f"empty/missing 'from' field matches all sources. The policy exists and "
                    f"selects pods, but doesn't actually restrict who can reach them."
                ),
                "remediation": "Add explicit podSelector/namespaceSelector/ipBlock entries to the "
                                "'from' field of this rule to restrict it to legitimate sources.",
            })
        if policy.ingress_allows_0_0_0_0:
            findings.append({
                "severity": "HIGH",
                "title": f"NetworkPolicy '{policy.name}' explicitly allows 0.0.0.0/0",
                "target": f"{policy.namespace}/{policy.name}",
                "description": (
                    f"'{policy.name}' in namespace '{policy.namespace}' has an ingress rule with "
                    f"an explicit ipBlock CIDR of 0.0.0.0/0 — allowing traffic from any IPv4 "
                    f"address, not just other pods in the cluster. This is sometimes a deliberate "
                    f"choice (a genuinely public-facing service) but is also a common accidental "
                    f"misconfiguration when the intent was 'anywhere in the cluster.'"
                ),
                "remediation": "Confirm this is intentional for a genuinely public-facing "
                                "service. If not, replace with a podSelector/namespaceSelector "
                                "scoped to the actual expected traffic sources.",
            })

    if not findings:
        findings.append({
            "severity": "INFO",
            "title": "No coverage gaps or permissive-rule findings",
            "target": f"{len(pods)} pod(s), {len(policies)} NetworkPolic{'y' if len(policies) == 1 else 'ies'}",
            "description": "Every pod is covered by at least one ingress-restricting "
                            "NetworkPolicy, and no policy has an unrestricted 'from' or an "
                            "explicit 0.0.0.0/0 allowance.",
        })

    return findings
