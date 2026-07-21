# Changelog

All notable changes to this project are documented here. See the
[README](README.md) for current features and usage.

### v0.6.0
- feat: **Linkerd mTLS awareness** — `scan` now also compares Linkerd injection intent against
  reality (read-only, part of the normal scan, no new flag needed): a pod or namespace annotated
  with `linkerd.io/inject: enabled` (pod-level overrides namespace-level, per Linkerd's own
  precedence) but whose pod has no `linkerd-proxy` sidecar container is flagged HIGH — it looks
  meshed but its traffic is entirely unencrypted, exactly as if Linkerd were never involved. This
  happens when injection is enabled after a pod already exists (the mutating webhook only runs at
  pod creation) or the injection webhook itself is down/misconfigured. Unlike Istio's
  `PeerAuthentication`, Linkerd has no central object recording "mTLS is off here," so this only
  shows up by comparing declared intent against the pod's actual container list.
- fix: RBAC-denied namespace listing (403) no longer aborts the whole scan — the Linkerd check
  falls back to evaluating pods on their own annotation only, without namespace-level inheritance,
  and `--namespace` scans only need to read that one namespace, not list the whole cluster.
- test: 12 new tests for `core/linkerd.py`'s pure precedence/interpretation logic (pod-level
  overriding namespace-level, correctly-injected pods, unmeshed namespaces, namespace-grouped
  finding output) plus fixtures for the RBAC-fallback case. The live pod/namespace fetch needs a
  real cluster and is only exercised in CI — but unlike the Istio check, that verification doesn't
  need a real Linkerd control plane installed, since the check only inspects pod annotations and
  container names.
- CI: the real `kind` cluster integration test now deploys two real pods for this check — one
  annotated for injection without a proxy container (must be flagged) and one with a placeholder
  `linkerd-proxy` container present (must not be flagged) — and directly exercises
  `fetch_pod_injection_info` / `fetch_namespace_inject_annotations` / `analyze_injection` against
  the real cluster, not just through the CLI.

### v0.5.0
- feat: **Istio mTLS awareness** — `scan` now also reads Istio's `PeerAuthentication` custom
  resources (read-only, part of the normal scan, no new flag needed) and flags `PERMISSIVE` mode
  (MEDIUM — accepts both mTLS and plaintext, Istio's own default and often left unlocked after
  rollout) and `DISABLE` mode (HIGH — no mTLS at all). NetworkPolicy operates at L3/L4 and can't
  see this layer at all; a cluster with no Istio installed (or without RBAC to list the CRD) is
  unaffected — the check silently finds nothing to say rather than erroring, since running a
  service mesh isn't a requirement this tool assumes.
- scope: Linkerd isn't covered by this check. Its default mTLS is automatic at the proxy level for
  meshed pods rather than a single declarative mode field like Istio's `PeerAuthentication`, so a
  comparable check needs a different model — left as a follow-up (see ROADMAP.md).
- test: 9 new tests for `core/mesh.py`'s pure PeerAuthentication-mode interpretation, using
  fixtures shaped like real Istio API objects (nested metadata/spec/mtls, missing fields, implicit
  istio-system namespace). The live CustomObjectsApi lookup needs a real cluster and is only
  exercised in CI.
- CI: the real `kind` cluster integration test now also confirms the Istio check degrades
  gracefully against a cluster that genuinely has no Istio installed — `scan` produces no mTLS
  findings and no error, and a direct call to `fetch_peer_authentications` confirms the CRD lookup
  returns `None` rather than raising.

### v0.4.0
- feat: **`netpol-audit verify-enforcement`** — actively verifies the cluster's CNI enforces
  NetworkPolicy at all, not just that NetworkPolicy objects exist and are well-formed. Deploys a
  real client pod, a real server pod, and a deny-all ingress NetworkPolicy, then attempts a real
  connection to check whether it's actually blocked. Reports a CRITICAL finding if the connection
  succeeds anyway (some CNIs and CNI configurations accept NetworkPolicy objects without enforcing
  them). Supports `--namespace` (default: create/delete a temporary one), `--keep` (skip cleanup
  for debugging), and `--json`.
- test: 2 new tests for the pure probe-result interpretation logic in `core/enforcement.py`. The
  live pod/policy/exec mechanics need a real cluster and are only exercised in CI, matching how
  `core/cluster.py`'s live-fetching functions are tested.
- CI: the real `kind` cluster integration test now also runs `verify-enforcement` for real.
  Whether the cluster's actual CNI enforces NetworkPolicy depends on the specific kindnet build in
  use, so rather than hardcoding an expected outcome, CI asserts the command's real
  exit-code/finding-severity contract holds for whatever the live probe result actually is.

### v0.3.0
- feat: **egress policy analysis** — coverage-gap and permissive-rule detection now apply
  symmetrically to egress, not just ingress: pods not selected by any NetworkPolicy with
  'Egress' in policyTypes (all outbound traffic allowed by default), egress rules with no `to`
  restriction (allow-all), and egress rules with an explicit `0.0.0.0/0` CIDR.
- refactor: `core/analyze.py`'s ingress finding-generation logic factored into
  direction-parameterized helpers (`_coverage_gap_findings`, `_permissive_rule_findings`) shared
  by both ingress and egress, instead of duplicating it.
- test: 12 new tests mirroring every existing ingress semantics/coverage test for egress
  (including a real kubernetes-client serialization round trip for `V1NetworkPolicyEgressRule`),
  plus a test confirming ingress and egress are parsed independently on a mixed policy.
- CI: the real `kind` cluster integration test now deploys egress-specific cases (egress
  allow-all, egress explicit 0.0.0.0/0) alongside the existing ingress cases, and the
  properly-restricted control case is now restricted on both directions.

### v0.2.0
- feat: **`--db` historical tracking** — `scan --db <path>` records every run's pod/policy counts
  and findings to a local SQLite database (stdlib `sqlite3`, no new dependency).
- feat: **`netpol-audit history`** — a terminal trend table of past runs from a `--db` database,
  most recent first, with severity counts side by side.
- feat: **`--baseline` CI gating** — `scan --baseline <path>` checks findings against a JSON file
  of `max_<severity>` counts and exits non-zero only when a severity exceeds its configured
  budget, for use as a deployment-pipeline gate instead of an ad-hoc manual audit. The default
  "fail on any CRITICAL/HIGH" behavior is unchanged when `--baseline` is omitted.
- test: 12 new tests covering run persistence/round-trip, history ordering, and baseline
  evaluation (within limits, exceeding limits, unlisted severities, unknown baseline keys).

### v0.1.0
- feat: **initial release** — Kubernetes NetworkPolicy coverage & permissiveness auditing CLI.
- feat: **coverage-gap detection** — pods not selected by any NetworkPolicy at all (non-isolated,
  all ingress traffic allowed by default).
- feat: **permissive-rule detection** — allow-all ingress rules (empty/missing `from`) and explicit
  `0.0.0.0/0` CIDR allowances. NetworkPolicy semantics (`ingress: []` denies all vs `ingress: [{}]`
  allows all) confirmed against the official Kubernetes API reference before implementation.
- test: 18 tests including a real round-trip through the kubernetes client library's own
  serialization, confirming the data shape assumption end-to-end.
- CI: a real `kind` cluster (via `helm/kind-action`) with real pods and NetworkPolicies covering
  every detection case — the only genuine end-to-end verification of the live-cluster path, since
  a real cluster isn't available in the local dev sandbox this was built in.
