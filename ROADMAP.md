# Roadmap

## Shipped

### v0.1.0
- Coverage-gap detection (pods with no NetworkPolicy at all).
- Permissive-rule detection (allow-all ingress rules, explicit
  0.0.0.0/0 CIDR).
- NetworkPolicy semantics confirmed against the official Kubernetes
  API reference before implementation, tested against realistic
  fixture data including a real round-trip through the kubernetes
  client library's own serialization.
- CI: a real `kind` cluster (via `helm/kind-action`), real pods and
  NetworkPolicies covering every detection case, real `netpol-audit
  scan` run against it.

## Next

### mTLS / service mesh awareness (Istio, Linkerd)
NetworkPolicy is only the L3/L4 layer — many real cloud-native NF
deployments also run a service mesh for mTLS between services. A
future module checking whether mTLS is actually enforced
(PeerAuthentication in Istio, or Linkerd's equivalent), not just
whether NetworkPolicy objects exist, would cover the layer this v0.1
release doesn't touch at all.

### CNI baseline / CNF-specific checks
Broader cluster-level checks beyond per-pod NetworkPolicy coverage:
whether the cluster's CNI actually enforces NetworkPolicy at all (some
CNIs, including kind's own default kindnet, don't enforce it even when
policy objects exist and are perfectly well-formed — a real,
easy-to-miss gap this tool doesn't currently detect, since it audits
the *declared* configuration via the Kubernetes API, not actual
enforced network behavior).

### Egress policy analysis
v0.1 focuses entirely on ingress. The same coverage-gap and
permissive-rule questions apply symmetrically to egress traffic
(unrestricted egress is how a compromised pod exfiltrates data or
reaches command-and-control infrastructure) and are a natural,
similarly-scoped extension.

### Persistence + dashboard + CI integration mode
A `--db` flag for historical tracking (matching the sibling repos'
pattern), and a CI-friendly mode (exit-code-based pass/fail against a
configurable policy baseline) for running this as a gate in a
cluster's own deployment pipeline, not just an ad-hoc manual audit
tool.
