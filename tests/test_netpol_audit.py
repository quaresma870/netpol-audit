"""
Tests for core NetworkPolicy parsing/analysis logic.

These test the parsing and coverage-gap logic against realistic
fixture data (including a real round-trip through the actual
kubernetes client library's own serialization, confirming the data
shape assumption is correct) — a real cluster isn't available in this
project's local dev environment, so the full live-cluster integration
path is verified separately on real CI using a real `kind` cluster
(see .github/workflows/ci.yml).
"""

from __future__ import annotations

from netpol_audit.core.analyze import analyze
from netpol_audit.core.netpol import (
    NetworkPolicyInfo,
    PodInfo,
    find_uncovered_pods,
    parse_network_policy,
)


class TestParseNetworkPolicySemantics:
    """Each case here corresponds to a specific, documented Kubernetes
    NetworkPolicy semantic confirmed against the official API
    reference before writing any detection logic — these are
    genuinely counter-intuitive and easy to get backwards, so each
    test exists to pin down one specific documented behavior."""

    def test_empty_ingress_list_denies_all_not_allow_all(self):
        """ingress: [] means DENY all ingress — the policy isolates
        the pod but the empty rule list means nothing matches."""
        info = parse_network_policy(
            {"podSelector": {"matchLabels": {"app": "web"}}, "policyTypes": ["Ingress"], "ingress": []},
            name="deny-all", namespace="default",
        )
        assert info.has_ingress_rules is True
        assert info.ingress_rules_allow_all is False

    def test_single_empty_rule_allows_all(self):
        """ingress: [{}] (one rule with neither from nor ports) means
        ALLOW all ingress — an empty rule has no restriction on
        either field, so it matches everything."""
        info = parse_network_policy(
            {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": [{}]},
            name="allow-all", namespace="default",
        )
        assert info.ingress_rules_allow_all is True

    def test_explicit_from_is_restrictive(self):
        info = parse_network_policy(
            {
                "podSelector": {"matchLabels": {"app": "web"}}, "policyTypes": ["Ingress"],
                "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "frontend"}}}]}],
            },
            name="restrictive", namespace="default",
        )
        assert info.ingress_rules_allow_all is False

    def test_explicit_0_0_0_0_cidr_flagged(self):
        info = parse_network_policy(
            {
                "podSelector": {}, "policyTypes": ["Ingress"],
                "ingress": [{"from": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}],
            },
            name="open-cidr", namespace="default",
        )
        assert info.ingress_allows_0_0_0_0 is True
        # A populated (even if permissive) ipBlock still counts as a
        # non-empty 'from' -- these are two independent findings
        # (allow_all vs allows_0_0_0_0), not the same thing.
        assert info.ingress_rules_allow_all is False

    def test_scoped_cidr_not_flagged_as_0_0_0_0(self):
        info = parse_network_policy(
            {
                "podSelector": {}, "policyTypes": ["Ingress"],
                "ingress": [{"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}],
            },
            name="scoped-cidr", namespace="default",
        )
        assert info.ingress_allows_0_0_0_0 is False

    def test_missing_ingress_key_entirely_has_no_ingress_rules(self):
        """A policy that only specifies egress (policyTypes: [Egress])
        has no 'ingress' key at all — distinct from ingress: [] (which
        DOES have the key, just empty)."""
        info = parse_network_policy(
            {"podSelector": {}, "policyTypes": ["Egress"], "egress": [{}]},
            name="egress-only", namespace="default",
        )
        assert info.has_ingress_rules is False
        assert info.has_egress_rules is True
        assert info.egress_rules_allow_all is True

    def test_missing_egress_key_entirely_has_no_egress_rules(self):
        """Symmetric to the ingress-only case above: an ingress-only
        policy has no 'egress' key at all."""
        info = parse_network_policy(
            {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": [{}]},
            name="ingress-only", namespace="default",
        )
        assert info.has_egress_rules is False

    def test_empty_egress_list_denies_all_not_allow_all(self):
        """egress: [] means DENY all egress -- same semantics as
        ingress: [] for the symmetric 'to' field."""
        info = parse_network_policy(
            {"podSelector": {"matchLabels": {"app": "web"}}, "policyTypes": ["Egress"], "egress": []},
            name="deny-all-egress", namespace="default",
        )
        assert info.has_egress_rules is True
        assert info.egress_rules_allow_all is False

    def test_single_empty_egress_rule_allows_all(self):
        """egress: [{}] (one rule with neither to nor ports) means
        ALLOW all egress."""
        info = parse_network_policy(
            {"podSelector": {}, "policyTypes": ["Egress"], "egress": [{}]},
            name="allow-all-egress", namespace="default",
        )
        assert info.egress_rules_allow_all is True

    def test_explicit_to_is_restrictive(self):
        info = parse_network_policy(
            {
                "podSelector": {"matchLabels": {"app": "web"}}, "policyTypes": ["Egress"],
                "egress": [{"to": [{"podSelector": {"matchLabels": {"app": "db"}}}]}],
            },
            name="restrictive-egress", namespace="default",
        )
        assert info.egress_rules_allow_all is False

    def test_explicit_0_0_0_0_egress_cidr_flagged(self):
        info = parse_network_policy(
            {
                "podSelector": {}, "policyTypes": ["Egress"],
                "egress": [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}],
            },
            name="open-cidr-egress", namespace="default",
        )
        assert info.egress_allows_0_0_0_0 is True
        assert info.egress_rules_allow_all is False

    def test_scoped_egress_cidr_not_flagged_as_0_0_0_0(self):
        info = parse_network_policy(
            {
                "podSelector": {}, "policyTypes": ["Egress"],
                "egress": [{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}],
            },
            name="scoped-cidr-egress", namespace="default",
        )
        assert info.egress_allows_0_0_0_0 is False

    def test_ingress_and_egress_parsed_independently(self):
        """A policy covering both directions can be permissive on one
        and restrictive on the other -- the two must not leak into
        each other."""
        info = parse_network_policy(
            {
                "podSelector": {}, "policyTypes": ["Ingress", "Egress"],
                "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "frontend"}}}]}],
                "egress": [{}],
            },
            name="mixed", namespace="default",
        )
        assert info.ingress_rules_allow_all is False
        assert info.egress_rules_allow_all is True

    def test_real_kubernetes_client_serialization_round_trip(self):
        """Confirms the data shape assumption end-to-end through the
        REAL kubernetes client library's own object model and
        sanitize_for_serialization method, not just a hand-constructed
        dict that happens to match what I assumed the shape would be."""
        from kubernetes import client

        spec = client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(match_labels={"app": "web"}),
            policy_types=["Ingress"],
            ingress=[client.V1NetworkPolicyIngressRule(
                _from=[client.V1NetworkPolicyPeer(ip_block=client.V1IPBlock(cidr="0.0.0.0/0"))]
            )],
        )
        sanitized = client.ApiClient().sanitize_for_serialization(spec)
        info = parse_network_policy(sanitized, name="test-policy", namespace="default")
        assert info.ingress_allows_0_0_0_0 is True

    def test_real_kubernetes_client_serialization_round_trip_egress(self):
        """Same round-trip confirmation as above, for the egress side
        of the client's object model (V1NetworkPolicyEgressRule /
        `to` instead of `from`)."""
        from kubernetes import client

        spec = client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(match_labels={"app": "web"}),
            policy_types=["Egress"],
            egress=[client.V1NetworkPolicyEgressRule(
                to=[client.V1NetworkPolicyPeer(ip_block=client.V1IPBlock(cidr="0.0.0.0/0"))]
            )],
        )
        sanitized = client.ApiClient().sanitize_for_serialization(spec)
        info = parse_network_policy(sanitized, name="test-policy", namespace="default")
        assert info.egress_allows_0_0_0_0 is True


class TestFindUncoveredPods:
    def test_pod_with_no_matching_policy_is_uncovered(self):
        pods = [PodInfo(name="web-1", namespace="default", labels={"app": "web"})]
        policies = [NetworkPolicyInfo(
            name="db-policy", namespace="default", pod_selector_labels={"app": "db"},
            policy_types=["Ingress"], has_ingress_rules=True,
            ingress_rules_allow_all=False, ingress_allows_0_0_0_0=False,
        )]
        uncovered = find_uncovered_pods(pods, policies)
        assert len(uncovered) == 1
        assert uncovered[0].name == "web-1"

    def test_pod_with_matching_policy_is_covered(self):
        pods = [PodInfo(name="web-1", namespace="default", labels={"app": "web"})]
        policies = [NetworkPolicyInfo(
            name="web-policy", namespace="default", pod_selector_labels={"app": "web"},
            policy_types=["Ingress"], has_ingress_rules=True,
            ingress_rules_allow_all=False, ingress_allows_0_0_0_0=False,
        )]
        assert find_uncovered_pods(pods, policies) == []

    def test_empty_pod_selector_covers_all_pods_in_namespace(self):
        """An empty podSelector matches all pods in the namespace, per
        the API reference's explicit documented semantics."""
        pods = [
            PodInfo(name="web-1", namespace="default", labels={"app": "web"}),
            PodInfo(name="db-1", namespace="default", labels={"app": "db"}),
        ]
        policies = [NetworkPolicyInfo(
            name="catch-all", namespace="default", pod_selector_labels={},
            policy_types=["Ingress"], has_ingress_rules=True,
            ingress_rules_allow_all=True, ingress_allows_0_0_0_0=False,
        )]
        assert find_uncovered_pods(pods, policies) == []

    def test_policy_in_different_namespace_does_not_cover(self):
        pods = [PodInfo(name="web-1", namespace="prod", labels={"app": "web"})]
        policies = [NetworkPolicyInfo(
            name="web-policy", namespace="staging", pod_selector_labels={"app": "web"},
            policy_types=["Ingress"], has_ingress_rules=True,
            ingress_rules_allow_all=False, ingress_allows_0_0_0_0=False,
        )]
        uncovered = find_uncovered_pods(pods, policies)
        assert len(uncovered) == 1

    def test_egress_only_policy_does_not_cover_ingress(self):
        pods = [PodInfo(name="web-1", namespace="default", labels={"app": "web"})]
        policies = [NetworkPolicyInfo(
            name="egress-only", namespace="default", pod_selector_labels={"app": "web"},
            policy_types=["Egress"], has_ingress_rules=False,
            ingress_rules_allow_all=False, ingress_allows_0_0_0_0=False,
        )]
        uncovered = find_uncovered_pods(pods, policies, direction="Ingress")
        assert len(uncovered) == 1

    def test_ingress_only_policy_does_not_cover_egress(self):
        """Symmetric to the egress-only case above."""
        pods = [PodInfo(name="web-1", namespace="default", labels={"app": "web"})]
        policies = [NetworkPolicyInfo(
            name="ingress-only", namespace="default", pod_selector_labels={"app": "web"},
            policy_types=["Ingress"], has_ingress_rules=True,
            ingress_rules_allow_all=False, ingress_allows_0_0_0_0=False,
        )]
        uncovered = find_uncovered_pods(pods, policies, direction="Egress")
        assert len(uncovered) == 1

    def test_no_pods_no_policies_produces_no_findings(self):
        assert find_uncovered_pods([], []) == []


class TestAnalyze:
    def test_uncovered_pods_produce_high_finding(self):
        """An uncovered pod is non-isolated in BOTH directions, so it
        produces two HIGH findings -- one for ingress, one for
        egress -- not just one."""
        pods = [PodInfo(name="web-1", namespace="default", labels={"app": "web"})]
        findings = analyze(pods, [])
        assert len(findings) == 2
        assert all(f["severity"] == "HIGH" for f in findings)
        assert all("web-1" in f["description"] for f in findings)
        titles = " ".join(f["title"] for f in findings)
        assert "ingress" in titles and "egress" in titles

    def test_allow_all_rule_produces_medium_finding(self):
        pods = [PodInfo(name="web-1", namespace="default", labels={"app": "web"})]
        policies = [NetworkPolicyInfo(
            name="allow-all", namespace="default", pod_selector_labels={"app": "web"},
            policy_types=["Ingress", "Egress"], has_ingress_rules=True,
            ingress_rules_allow_all=True, ingress_allows_0_0_0_0=False,
            has_egress_rules=True, egress_rules_allow_all=False, egress_allows_0_0_0_0=False,
        )]
        findings = analyze(pods, policies)
        assert any(f["severity"] == "MEDIUM" and "allow-all" in f["target"] for f in findings)
        # Pod IS covered (a policy selects it, in both directions), so no HIGH coverage-gap finding
        assert not any(f["severity"] == "HIGH" and "web-1" in f.get("description", "") for f in findings)

    def test_0_0_0_0_produces_high_finding(self):
        pods = []
        policies = [NetworkPolicyInfo(
            name="open", namespace="default", pod_selector_labels={},
            policy_types=["Ingress"], has_ingress_rules=True,
            ingress_rules_allow_all=False, ingress_allows_0_0_0_0=True,
        )]
        findings = analyze(pods, policies)
        assert any(f["severity"] == "HIGH" and "0.0.0.0/0" in f["title"] for f in findings)

    def test_0_0_0_0_egress_produces_high_finding(self):
        pods = []
        policies = [NetworkPolicyInfo(
            name="open-egress", namespace="default", pod_selector_labels={},
            policy_types=["Egress"], has_ingress_rules=False,
            ingress_rules_allow_all=False, ingress_allows_0_0_0_0=False,
            has_egress_rules=True, egress_rules_allow_all=False, egress_allows_0_0_0_0=True,
        )]
        findings = analyze(pods, policies)
        assert any(f["severity"] == "HIGH" and "0.0.0.0/0" in f["title"] and "egress" in f["title"] for f in findings)

    def test_fully_covered_and_restrictive_produces_info_only(self):
        pods = [PodInfo(name="web-1", namespace="default", labels={"app": "web"})]
        policies = [NetworkPolicyInfo(
            name="restrictive", namespace="default", pod_selector_labels={"app": "web"},
            policy_types=["Ingress", "Egress"], has_ingress_rules=True,
            ingress_rules_allow_all=False, ingress_allows_0_0_0_0=False,
            has_egress_rules=True, egress_rules_allow_all=False, egress_allows_0_0_0_0=False,
        )]
        findings = analyze(pods, policies)
        assert len(findings) == 1
        assert findings[0]["severity"] == "INFO"

    def test_empty_cluster_produces_info_only_no_crash(self):
        findings = analyze([], [])
        assert len(findings) == 1
        assert findings[0]["severity"] == "INFO"
