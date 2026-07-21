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

### v0.2.0
- `--db` flag on `scan` for historical tracking: every run's pod/policy counts and findings are
  recorded to a local SQLite database (stdlib `sqlite3`, no new dependency).
- `netpol-audit history --db <path>` — a terminal trend table of past runs, most recent first,
  with severity counts side by side so a regression or improvement across runs is visible at a
  glance (the CLI-native form of the "dashboard" this item originally described).
- `--baseline` flag on `scan` for CI-friendly gating: a JSON file of `max_<severity>` counts
  (e.g. `{"max_critical": 0, "max_high": 0, "max_medium": 3}`) that the run's findings are
  checked against, exiting non-zero only when a severity exceeds its configured budget — instead
  of the blanket "fail on any CRITICAL/HIGH" default, which still applies when `--baseline` is
  omitted.

### v0.3.0
- Egress policy analysis: the same coverage-gap and permissive-rule questions v0.1 asked about
  ingress now apply symmetrically to egress — pods not selected by any NetworkPolicy with
  'Egress' in policyTypes, egress rules with no `to` restriction, and egress rules with an
  explicit `0.0.0.0/0` CIDR.

### v0.4.0
- `netpol-audit verify-enforcement`: active CNI baseline check. Deploys a real client pod, a real
  server pod, and a deny-all ingress NetworkPolicy, then attempts a real connection to confirm
  whether it's actually blocked — catching the gap where NetworkPolicy objects exist and are
  well-formed but the cluster's CNI silently doesn't enforce them at all (some CNIs and CNI
  configurations don't), which the rest of this tool can't detect since it only audits *declared*
  configuration via the Kubernetes API, not actual enforced network behavior.

## Next

### mTLS / service mesh awareness (Istio, Linkerd)
NetworkPolicy is only the L3/L4 layer — many real cloud-native NF
deployments also run a service mesh for mTLS between services. A
future module checking whether mTLS is actually enforced
(PeerAuthentication in Istio, or Linkerd's equivalent), not just
whether NetworkPolicy objects exist, would cover the layer this tool
doesn't touch at all yet.
