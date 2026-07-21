"""Linkerd mTLS awareness. Linkerd's mTLS model differs fundamentally
from Istio's (see core/mesh.py) -- there's no single declarative
"mode" field to audit. Instead, mTLS is automatic and mandatory for
meshed-to-meshed traffic once a pod has the linkerd-proxy sidecar
injected; injection itself is controlled by the `linkerd.io/inject`
annotation, settable at the namespace level (applies to all pods
there) and overridable per-pod.

The real-world gap this catches: a namespace or pod is *annotated*
for injection ("linkerd.io/inject: enabled") -- meaning it's intended
to be meshed and get mTLS -- but the pod doesn't actually have the
linkerd-proxy sidecar container running. This happens when injection
was enabled after the pod was already created (the mutating webhook
only runs at pod creation), when the webhook itself is down or
misconfigured, or when a namespace-wide default is silently not
picked up. A pod in this state looks meshed (the annotation says so)
but its traffic is entirely unencrypted and unauthenticated, same as
if it were never meshed at all -- and unlike Istio's
PeerAuthentication, there's no central object recording "mTLS is off
here" to audit; the mismatch only shows up by comparing intent (the
annotation) against reality (the container list).

Split the same way as the rest of core/: `pod_needs_injection_but_missing_proxy`
is pure and unit tested; the fetch functions do live cluster reads and
are only exercised against a real cluster in CI. Unlike core/mesh.py's
Istio check, this doesn't even need a real Linkerd control plane
installed to test for real -- the check only inspects pod annotations
and container names, both of which a plain kubectl-created test pod
can carry without Linkerd actually running.
"""

from __future__ import annotations

from dataclasses import dataclass

INJECT_ANNOTATION = "linkerd.io/inject"
PROXY_CONTAINER_NAME = "linkerd-proxy"


@dataclass
class PodInjectionInfo:
    name: str
    namespace: str
    inject_annotation: str | None  # this pod's OWN linkerd.io/inject annotation, if any
    has_proxy_container: bool


def pod_needs_injection_but_missing_proxy(
    namespace_inject: str | None, pod_inject: str | None, has_proxy_container: bool,
) -> bool:
    """Pure precedence resolution: a pod-level `linkerd.io/inject`
    annotation overrides the namespace-level one, per Linkerd's own
    documented behavior -- a pod's own explicit 'disabled' opts it out
    of an otherwise-injected namespace, and vice versa. Returns True
    if the pod is intended to be meshed (the effective annotation is
    'enabled') but doesn't actually have the linkerd-proxy sidecar."""
    effective = pod_inject if pod_inject is not None else namespace_inject
    return effective == "enabled" and not has_proxy_container


def analyze_injection(pods: list[PodInjectionInfo], namespace_annotations: dict[str, str | None]) -> list[dict]:
    """Groups pods that are annotated for Linkerd injection but aren't
    actually meshed, by namespace -- mirroring core/analyze.py's
    coverage-gap grouping, so a namespace with many affected pods
    produces one finding, not a flood of near-identical ones."""
    by_namespace: dict[str, list[str]] = {}
    for pod in pods:
        namespace_inject = namespace_annotations.get(pod.namespace)
        if pod_needs_injection_but_missing_proxy(namespace_inject, pod.inject_annotation, pod.has_proxy_container):
            by_namespace.setdefault(pod.namespace, []).append(pod.name)

    findings = []
    for namespace, pod_names in by_namespace.items():
        findings.append({
            "severity": "HIGH",
            "title": f"{len(pod_names)} pod(s) annotated for Linkerd injection but not actually meshed",
            "target": namespace,
            "description": (
                f"In namespace '{namespace}', {len(pod_names)} pod(s) are annotated with "
                f"'{INJECT_ANNOTATION}: enabled' (directly or inherited from the namespace) but "
                f"have no '{PROXY_CONTAINER_NAME}' sidecar container: "
                f"{', '.join(pod_names[:10])}{'...' if len(pod_names) > 10 else ''}. These pods "
                f"look meshed -- the annotation says so -- but their traffic is entirely "
                f"unencrypted and unauthenticated, exactly as if Linkerd were never involved. "
                f"This typically happens when injection was enabled after the pod was already "
                f"running (the mutating webhook only runs at pod creation), or when the "
                f"injection webhook itself is down or misconfigured."
            ),
            "remediation": "Restart/recreate these pods so the Linkerd injection webhook can add "
                            "the proxy sidecar, and confirm the webhook itself is healthy "
                            "(`linkerd check`).",
        })
    return findings


def fetch_pod_injection_info(namespace: str | None = None) -> list[PodInjectionInfo]:
    """Live fetch of every pod's own inject annotation and whether it
    actually has a linkerd-proxy container -- both plain fields on the
    Pod object, so this needs no more RBAC than the pod listing 'scan'
    already does."""
    from kubernetes import client

    v1 = client.CoreV1Api()
    resp = v1.list_namespaced_pod(namespace) if namespace else v1.list_pod_for_all_namespaces()

    return [
        PodInjectionInfo(
            name=p.metadata.name,
            namespace=p.metadata.namespace,
            inject_annotation=(p.metadata.annotations or {}).get(INJECT_ANNOTATION),
            has_proxy_container=any(c.name == PROXY_CONTAINER_NAME for c in (p.spec.containers or [])),
        )
        for p in resp.items
    ]


def fetch_namespace_inject_annotations(namespace: str | None = None) -> dict[str, str | None]:
    """Returns each namespace's own linkerd.io/inject annotation, used
    to resolve a pod's effective annotation when the pod itself
    doesn't set one. If `namespace` is given, only that namespace is
    read (a single read_namespace call, needing far less RBAC than
    listing every namespace in the cluster) -- otherwise all
    namespaces are listed. Returns an empty dict (not an error) if
    this can't be determined because RBAC denies it: pods are then
    evaluated using only their own pod-level annotation, without
    namespace-level inheritance, rather than failing the whole scan
    over a permission this check alone needs."""
    from kubernetes import client

    v1 = client.CoreV1Api()
    try:
        if namespace:
            ns = v1.read_namespace(namespace)
            return {ns.metadata.name: (ns.metadata.annotations or {}).get(INJECT_ANNOTATION)}
        resp = v1.list_namespace()
        return {ns.metadata.name: (ns.metadata.annotations or {}).get(INJECT_ANNOTATION) for ns in resp.items}
    except client.ApiException as exc:
        if exc.status == 403:
            return {}
        raise
