# Changelog

All notable changes to this project are documented here. See the
[README](README.md) for current features and usage.

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
