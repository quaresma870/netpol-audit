# Changelog

All notable changes to this project are documented here. See the
[README](README.md) for current features and usage.

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
