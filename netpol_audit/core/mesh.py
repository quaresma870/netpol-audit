"""Service mesh mTLS awareness: NetworkPolicy is only the L3/L4 layer
-- this checks whether mTLS is actually *enforced* by Istio (via its
PeerAuthentication custom resource's `mtls.mode`), not just whether
NetworkPolicy objects exist. A cluster with no Istio installed
produces no findings from this module at all -- running a service
mesh isn't a requirement this tool assumes, so a missing CRD is a
no-op, not an error.

Istio's PeerAuthentication modes (security.istio.io/v1beta1):
- STRICT: only mTLS connections are accepted. Enforced.
- PERMISSIVE: both mTLS and plaintext are accepted. This is Istio's
  own default, and a common "forgot to lock it down" misconfiguration
  -- traffic that should be authenticated can still arrive in the
  clear.
- DISABLE: mTLS is not used at all for the selected workloads.
- unset `mtls` field entirely: this PeerAuthentication doesn't set a
  mode at this scope (e.g. it exists only for portLevelMtls overrides)
  -- the effective mode is inherited from a broader-scoped policy,
  which this module doesn't attempt to resolve, so it produces no
  finding for that object in isolation.

Split the same way as netpol.py/cluster.py: `interpret_peer_authentication`
is pure and unit tested against fixture data shaped like Istio's real
API objects; `fetch_peer_authentications` does the live CustomResource
lookup and is only exercised against a real cluster in CI -- which
confirms the no-mesh-installed case degrades gracefully, since
installing a full Istio control plane just for CI is out of scope for
this tool.

Linkerd isn't covered here: its default mTLS is automatic at the proxy
level for meshed pods rather than a single declarative mode field like
Istio's, so it needs a different model entirely -- see core/linkerd.py.
"""

from __future__ import annotations

PEER_AUTH_GROUP = "security.istio.io"
PEER_AUTH_VERSION = "v1beta1"
PEER_AUTH_PLURAL = "peerauthentications"


def interpret_peer_authentication(mode: str | None, namespace: str, name: str) -> dict | None:
    """Pure interpretation of one PeerAuthentication's mtls.mode.
    Returns a finding if mode is PERMISSIVE or DISABLE, or None if
    mode is STRICT (mTLS required, plaintext rejected) or unset
    (this object doesn't set a mode at this scope)."""
    if mode == "DISABLE":
        return {
            "severity": "HIGH",
            "title": f"PeerAuthentication '{name}' explicitly disables mTLS",
            "target": f"{namespace}/{name}",
            "description": (
                f"'{name}' in namespace '{namespace}' sets mtls.mode to DISABLE -- workloads "
                f"covered by this policy accept plaintext traffic only, with no mTLS at all. "
                f"NetworkPolicy operates at L3/L4 and can't detect this: a connection this tool "
                f"reports as correctly restricted by NetworkPolicy may still be unauthenticated "
                f"and unencrypted at the transport layer."
            ),
            "remediation": "Set mtls.mode to STRICT unless plaintext traffic to these workloads "
                            "is genuinely required (e.g. during a migration).",
        }
    if mode == "PERMISSIVE":
        return {
            "severity": "MEDIUM",
            "title": f"PeerAuthentication '{name}' allows plaintext traffic (PERMISSIVE mode)",
            "target": f"{namespace}/{name}",
            "description": (
                f"'{name}' in namespace '{namespace}' sets mtls.mode to PERMISSIVE -- workloads "
                f"covered by this policy accept BOTH mTLS and plaintext connections. This is "
                f"Istio's own default and is often left in place after the initial mesh rollout "
                f"instead of being locked down to STRICT, silently allowing unauthenticated "
                f"plaintext traffic to reach these workloads alongside the intended mTLS traffic."
            ),
            "remediation": "Set mtls.mode to STRICT once all clients in the mesh are confirmed "
                            "to be sending mTLS -- PERMISSIVE is meant as a migration aid, not a "
                            "steady-state setting.",
        }
    return None


def fetch_peer_authentications(namespace: str | None = None) -> list[dict] | None:
    """Returns the raw PeerAuthentication objects visible to the
    current kubeconfig context, or None if this can't be determined --
    either the security.istio.io CRD isn't installed at all (no Istio
    service mesh present), or the current kubeconfig's RBAC doesn't
    permit listing it. Neither is raised as an error: not every
    cluster this tool audits runs a service mesh, and this check is
    additive on top of the core NetworkPolicy audit, not required for
    it to succeed."""
    from kubernetes import client

    co = client.CustomObjectsApi()
    try:
        if namespace:
            resp = co.list_namespaced_custom_object(
                PEER_AUTH_GROUP, PEER_AUTH_VERSION, namespace, PEER_AUTH_PLURAL,
            )
        else:
            resp = co.list_cluster_custom_object(
                PEER_AUTH_GROUP, PEER_AUTH_VERSION, PEER_AUTH_PLURAL,
            )
    except client.ApiException as exc:
        if exc.status in (403, 404):
            return None
        raise
    return resp.get("items", [])


def analyze_peer_authentications(items: list[dict]) -> list[dict]:
    """Parses raw PeerAuthentication objects (as returned by the
    Kubernetes API, matching `fetch_peer_authentications`' shape) into
    findings."""
    findings = []
    for item in items:
        metadata = item.get("metadata") or {}
        name = metadata.get("name", "<unknown>")
        namespace = metadata.get("namespace") or "istio-system"
        spec = item.get("spec") or {}
        mtls = spec.get("mtls") or {}
        mode = mtls.get("mode")
        finding = interpret_peer_authentication(mode, namespace, name)
        if finding:
            findings.append(finding)
    return findings
