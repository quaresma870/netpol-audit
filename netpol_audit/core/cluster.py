"""
Kubernetes cluster client — fetches real pods and NetworkPolicies from
a live cluster via the official `kubernetes` Python client, using
whatever kubeconfig context is already active (the same credentials
`kubectl` would use). No separate Authorization/Engagement gate here —
this tool operates entirely through the user's own already-authenticated
kubeconfig access (Kubernetes' own RBAC is the real access-control
layer), the same reasoning already applied to the sibling sbom-audit
and netwatch repos for why they don't have one either.
"""

from __future__ import annotations

from kubernetes import client, config

from netpol_audit.core.netpol import NetworkPolicyInfo, PodInfo, parse_network_policy


class ClusterConnectionError(Exception):
    """Raised when the cluster genuinely can't be reached or the
    active kubeconfig context can't be loaded — distinct from a
    successful connection that simply finds zero pods/policies, which
    is itself a valid (if perhaps surprising) result."""


def load_kube_config(kubeconfig_path: str | None = None, context: str | None = None) -> None:
    try:
        if kubeconfig_path:
            config.load_kube_config(config_file=kubeconfig_path, context=context)
        else:
            config.load_kube_config(context=context)
    except config.ConfigException as exc:
        raise ClusterConnectionError(f"Could not load kubeconfig: {exc}") from exc


def fetch_pods(namespace: str | None = None) -> list[PodInfo]:
    v1 = client.CoreV1Api()
    try:
        if namespace:
            resp = v1.list_namespaced_pod(namespace)
        else:
            resp = v1.list_pod_for_all_namespaces()
    except client.ApiException as exc:
        raise ClusterConnectionError(f"Could not list pods: {exc}") from exc

    return [
        PodInfo(name=p.metadata.name, namespace=p.metadata.namespace, labels=p.metadata.labels or {})
        for p in resp.items
    ]


def fetch_network_policies(namespace: str | None = None) -> list[NetworkPolicyInfo]:
    net_v1 = client.NetworkingV1Api()
    try:
        if namespace:
            resp = net_v1.list_namespaced_network_policy(namespace)
        else:
            resp = net_v1.list_network_policy_for_all_namespaces()
    except client.ApiException as exc:
        raise ClusterConnectionError(f"Could not list NetworkPolicies: {exc}") from exc

    policies = []
    for np in resp.items:
        # .to_dict() converts the whole client object tree (including
        # the spec) into plain dicts with camelCase-preserved keys via
        # the client's own attribute_map, matching exactly the shape
        # parse_network_policy expects and was tested against.
        spec_dict = client.ApiClient().sanitize_for_serialization(np.spec)
        policies.append(parse_network_policy(spec_dict, name=np.metadata.name, namespace=np.metadata.namespace))
    return policies


def list_namespaces() -> list[str]:
    v1 = client.CoreV1Api()
    try:
        resp = v1.list_namespace()
    except client.ApiException as exc:
        raise ClusterConnectionError(f"Could not list namespaces: {exc}") from exc
    return [ns.metadata.name for ns in resp.items]
