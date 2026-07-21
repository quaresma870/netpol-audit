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
- Egress is the symmetric counterpart of all of the above: `to` plays
  the same role as `from` (an egress rule's `to` field empty/omitted
  means "matches all destinations"), `egress: []` denies all egress
  while `egress: [{}]` allows all egress, and a pod not selected by
  any NetworkPolicy with 'Egress' in policyTypes is non-isolated for
  egress just as it is for ingress -- ALL outbound traffic allowed by
  default.
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
    has_egress_rules: bool = False  # True if `egress` key is present at all (even as [])
    egress_rules_allow_all: bool = False  # True if any single egress rule has no to/ports restriction
    egress_allows_0_0_0_0: bool = False  # True if any egress rule explicitly allows 0.0.0.0/0


def _labels_match(pod_labels: dict[str, str], selector_labels: dict[str, str]) -> bool:
    """A LabelSelector's matchLabels are ANDed — every key in the
    selector must be present with the same value on the pod. An empty
    selector matches every pod (per the API reference: "An empty
    podSelector matches all pods in this namespace")."""
    if not selector_labels:
        return True
    return all(pod_labels.get(k) == v for k, v in selector_labels.items())


def _scan_rules(rules: list[dict], peer_key: str) -> tuple[bool, bool]:
    """Shared by ingress ('from') and egress ('to') rule scanning --
    the peer-matching semantics (an empty/missing peer list matches
    everything; an ipBlock CIDR of 0.0.0.0/0 is a full-open allowance)
    are identical for both directions, only the field name storing the
    peer list differs."""
    allow_all = False
    allow_0000 = False
    for rule in rules:
        rule = rule or {}
        peers = rule.get(peer_key)
        if not peers:
            # No peers at all (or an empty list) on a present rule ->
            # matches all sources/destinations, per the API
            # reference's explicit documented semantics for this field.
            allow_all = True
        else:
            for peer in peers:
                ip_block = (peer or {}).get("ipBlock") or {}
                if ip_block.get("cidr") == "0.0.0.0/0":
                    allow_0000 = True
    return allow_all, allow_0000


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
    ingress_allow_all, ingress_allow_0000 = _scan_rules(ingress or [], "from")

    egress = raw_spec.get("egress")
    has_egress_rules = egress is not None
    egress_allow_all, egress_allow_0000 = _scan_rules(egress or [], "to")

    return NetworkPolicyInfo(
        name=name,
        namespace=namespace,
        pod_selector_labels=selector_labels,
        policy_types=policy_types,
        has_ingress_rules=has_ingress_rules,
        ingress_rules_allow_all=ingress_allow_all,
        ingress_allows_0_0_0_0=ingress_allow_0000,
        has_egress_rules=has_egress_rules,
        egress_rules_allow_all=egress_allow_all,
        egress_allows_0_0_0_0=egress_allow_0000,
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
