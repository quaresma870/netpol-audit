"""Orchestrates a full cluster analysis: coverage gaps (pods with no
NetworkPolicy at all) and permissive-policy findings (policies that
exist but don't actually restrict anything meaningfully) — for both
ingress and egress, which apply symmetrically."""

from __future__ import annotations

from netpol_audit.core.netpol import NetworkPolicyInfo, PodInfo, find_uncovered_pods


def _coverage_gap_findings(pods: list[PodInfo], policies: list[NetworkPolicyInfo], direction: str) -> list[dict]:
    uncovered = find_uncovered_pods(pods, policies, direction=direction)
    by_namespace: dict[str, list[PodInfo]] = {}
    for pod in uncovered:
        by_namespace.setdefault(pod.namespace, []).append(pod)

    verb = "ingress" if direction == "Ingress" else "egress"
    findings = []
    for namespace, ns_pods in by_namespace.items():
        findings.append({
            "severity": "HIGH",
            "title": f"{len(ns_pods)} pod(s) with no NetworkPolicy (all {verb} traffic allowed)",
            "target": namespace,
            "description": (
                f"In namespace '{namespace}', {len(ns_pods)} pod(s) are not selected by any "
                f"NetworkPolicy with '{direction}' in policyTypes: "
                f"{', '.join(p.name for p in ns_pods[:10])}"
                f"{'...' if len(ns_pods) > 10 else ''}. A pod not selected by any NetworkPolicy "
                f"is non-isolated — ALL {verb} traffic is allowed by default, independent of "
                f"whatever other NetworkPolicies exist for other pods in the namespace."
            ),
            "remediation": "Add a NetworkPolicy selecting these pods (even a default-deny policy "
                            "as a baseline, then explicit allow rules for legitimate traffic).",
        })
    return findings


def _permissive_rule_findings(policies: list[NetworkPolicyInfo], direction: str) -> list[dict]:
    if direction == "Ingress":
        verb, peer_field, has_rules_attr, allow_all_attr, allow_0000_attr = (
            "ingress", "from", "has_ingress_rules", "ingress_rules_allow_all", "ingress_allows_0_0_0_0",
        )
    else:
        verb, peer_field, has_rules_attr, allow_all_attr, allow_0000_attr = (
            "egress", "to", "has_egress_rules", "egress_rules_allow_all", "egress_allows_0_0_0_0",
        )

    findings = []
    for policy in policies:
        if not getattr(policy, has_rules_attr):
            continue  # this policy doesn't touch this direction at all — nothing to say here
        if getattr(policy, allow_all_attr):
            findings.append({
                "severity": "MEDIUM",
                "title": f"NetworkPolicy '{policy.name}' has an {verb} rule allowing all "
                         f"{'sources' if direction == 'Ingress' else 'destinations'}",
                "target": f"{policy.namespace}/{policy.name}",
                "description": (
                    f"'{policy.name}' in namespace '{policy.namespace}' has at least one {verb} "
                    f"rule with no '{peer_field}' restriction — per Kubernetes' documented "
                    f"semantics, an empty/missing '{peer_field}' field matches all "
                    f"{'sources' if direction == 'Ingress' else 'destinations'}. The policy exists "
                    f"and selects pods, but doesn't actually restrict "
                    f"{'who can reach them' if direction == 'Ingress' else 'what they can reach'}."
                ),
                "remediation": f"Add explicit podSelector/namespaceSelector/ipBlock entries to the "
                                f"'{peer_field}' field of this rule to restrict it to legitimate "
                                f"{'sources' if direction == 'Ingress' else 'destinations'}.",
            })
        if getattr(policy, allow_0000_attr):
            findings.append({
                "severity": "HIGH",
                "title": f"NetworkPolicy '{policy.name}' explicitly allows 0.0.0.0/0 {verb}",
                "target": f"{policy.namespace}/{policy.name}",
                "description": (
                    f"'{policy.name}' in namespace '{policy.namespace}' has an {verb} rule with "
                    f"an explicit ipBlock CIDR of 0.0.0.0/0 — allowing traffic "
                    f"{'from any IPv4 address' if direction == 'Ingress' else 'to any IPv4 address'}, "
                    f"not just other pods in the cluster. This is sometimes a deliberate choice "
                    f"(a genuinely public-facing service, or a workload that legitimately needs "
                    f"open internet egress) but is also a common accidental misconfiguration when "
                    f"the intent was 'anywhere in the cluster.'"
                ),
                "remediation": "Confirm this is intentional. If not, replace with a "
                                "podSelector/namespaceSelector scoped to the actual expected "
                                f"traffic {'sources' if direction == 'Ingress' else 'destinations'}.",
            })
    return findings


def analyze(pods: list[PodInfo], policies: list[NetworkPolicyInfo]) -> list[dict]:
    findings: list[dict] = []

    findings.extend(_coverage_gap_findings(pods, policies, direction="Ingress"))
    findings.extend(_coverage_gap_findings(pods, policies, direction="Egress"))
    findings.extend(_permissive_rule_findings(policies, direction="Ingress"))
    findings.extend(_permissive_rule_findings(policies, direction="Egress"))

    if not findings:
        findings.append({
            "severity": "INFO",
            "title": "No coverage gaps or permissive-rule findings",
            "target": f"{len(pods)} pod(s), {len(policies)} NetworkPolic{'y' if len(policies) == 1 else 'ies'}",
            "description": "Every pod is covered by at least one ingress- and egress-restricting "
                            "NetworkPolicy, and no policy has an unrestricted 'from'/'to' or an "
                            "explicit 0.0.0.0/0 allowance.",
        })

    return findings
