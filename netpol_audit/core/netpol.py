"""
Kubernetes cluster inspection — pods, namespaces, and NetworkPolicy
analysis.

NetworkPolicy semantics confirmed against the official Kubernetes API
reference (kubernetes.io/docs/reference/kubernetes-api/policy-resources/
network-policy-v1) before writing any detection logic, since these are
genuinely counter-intuitive and easy to get backwards:

- A pod not selected by ANY NetworkPolicy is non-isolated: ALL traffic
  (ingress and egress) is allowed by default. This is the single most
  important thing to check for — "NetworkPolicy exists in this
  namespace" does NOT mean "every pod here is covered."
- ingress: [] (an empty LIST of rules) on a NetworkPolicy that DOES
  select a pod means DENY ALL ingress — the policy isolates the pod
  but permits nothing.
- ingress: [{}] (a list containing one EMPTY rule object) means ALLOW
  ALL ingress — an ingress rule's `from` and `ports` fields each
  independently mean "matches everything" when empty or omitted, so a
  rule with neither restricts nothing at all.
- The same empty-means-match-all semantics apply per-field within an
  otherwise-populated rule too: a rule with `ports` set but no `from`
  still matches traffic from ANY source on those ports.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PodInfo:
    name: str
    namespace: str
    labels: dict[str, str]


@dataclass
class NetworkPolicyInfo:
    name: str
    namespace: str
    pod_selector_labels: dict[str, str]  # empty dict = selects all pods in namespace
    policy_types: list[str]
    has_ingress_rules: bool  # True if `ingress` key is present at all (even as [])
    ingress_rules_allow_all: bool  # True if any single ingress rule has no from/ports restriction
    ingress_allows_0_0_0_0: bool  # True if any ingress rule explicitly allows 0.0.0.0/0


def _labels_match(pod_labels: dict[str, str], selector_labels: dict[str, str]) -> bool:
    """A LabelSelector's matchLabels are ANDed — every key in the
    selector must be present with the same value on the pod. An empty
    selector matches every pod (per the API reference: "An empty
    podSelector matches all pods in this namespace")."""
    if not selector_labels:
        return True
    return all(pod_labels.get(k) == v for k, v in selector_labels.items())


def parse_network_policy(raw_spec: dict, name: str, namespace: str) -> NetworkPolicyInfo:
    """Parses a NetworkPolicy's spec (as a plain dict, matching what
    the Kubernetes client's to_dict() or a raw API response gives) into
    a NetworkPolicyInfo with the permissiveness questions already
    answered — kept separate from the live-cluster-querying code so
    this parsing logic can be unit tested against realistic fixture
    data without needing a real cluster at all."""
    pod_selector = raw_spec.get("podSelector") or {}
    selector_labels = pod_selector.get("matchLabels") or {}
    policy_types = raw_spec.get("policyTypes") or []

    ingress = raw_spec.get("ingress")
    has_ingress_rules = ingress is not None
    ingress_rules = ingress or []

    allow_all = False
    allow_0000 = False
    for rule in ingress_rules:
        rule = rule or {}
        peers = rule.get("from")
        if not peers:
            # No `from` at all (or an empty list) on a present rule ->
            # matches all sources, per the API reference's explicit
            # documented semantics for this field.
            allow_all = True
        else:
            for peer in peers:
                ip_block = (peer or {}).get("ipBlock") or {}
                if ip_block.get("cidr") == "0.0.0.0/0":
                    allow_0000 = True

    return NetworkPolicyInfo(
        name=name,
        namespace=namespace,
        pod_selector_labels=selector_labels,
        policy_types=policy_types,
        has_ingress_rules=has_ingress_rules,
        ingress_rules_allow_all=allow_all,
        ingress_allows_0_0_0_0=allow_0000,
    )


def find_uncovered_pods(
    pods: list[PodInfo], policies: list[NetworkPolicyInfo], direction: str = "Ingress",
) -> list[PodInfo]:
    """Returns every pod NOT selected by any NetworkPolicy that
    includes `direction` in its policyTypes — these pods are
    non-isolated for that direction, meaning ALL traffic in that
    direction is allowed by default, independent of whatever other
    NetworkPolicies exist in the namespace for OTHER pods."""
    uncovered = []
    for pod in pods:
        covered = False
        for policy in policies:
            if policy.namespace != pod.namespace:
                continue
            if direction not in policy.policy_types:
                continue
            if _labels_match(pod.labels, policy.pod_selector_labels):
                covered = True
                break
        if not covered:
            uncovered.append(pod)
    return uncovered
