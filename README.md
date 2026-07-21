# 🛡️ netpol-audit

Kubernetes NetworkPolicy coverage & permissiveness auditing.

5G Core and telecom network functions are increasingly cloud-native,
running as Kubernetes workloads — this audits the NetworkPolicy layer
that's supposed to segment them.

No `authorization.yml` needed — this operates entirely through your own
already-authenticated kubeconfig access (the same credentials `kubectl`
already uses). Kubernetes' own RBAC is the real access-control layer
here, matching the same reasoning already applied to the sibling
sbom-audit and netwatch repos.

## Status

Early, actively developed. Covers:

- **Coverage gaps** — pods not selected by any NetworkPolicy at all, for
  **both ingress and egress**. A pod not selected by any NetworkPolicy
  is *non-isolated*: **all** traffic in that direction is allowed by
  default, regardless of what other NetworkPolicies exist for other
  pods in the namespace. This is the single most important thing to
  check for.
- **Permissive-rule detection** — NetworkPolicies that exist and select
  pods but don't actually restrict anything, checked symmetrically on
  both sides: an ingress rule with no `from` restriction or an egress
  rule with no `to` restriction (matches all sources/destinations, per
  Kubernetes' own documented semantics), or an explicit `0.0.0.0/0`
  CIDR allowance on either side.
- **Historical tracking** — `scan --db findings.db` records every run
  (pod/policy counts, findings) to a local SQLite database; `netpol-audit
  history --db findings.db` shows a trend table of past runs.
- **CI gating** — `scan --baseline baseline.json` exits non-zero only
  when findings exceed a configurable per-severity budget (e.g.
  `{"max_critical": 0, "max_high": 0, "max_medium": 3}`), for use as a
  deployment-pipeline gate. Without `--baseline`, the default gate is
  "fail on any CRITICAL/HIGH finding."
- **Active CNI enforcement verification** — `netpol-audit
  verify-enforcement` deploys a real client pod, a real server pod, and
  a deny-all ingress NetworkPolicy, then attempts a real connection to
  check whether it's actually blocked. Everything above audits
  *declared* NetworkPolicy objects via the Kubernetes API; this instead
  catches the case where those objects exist and are well-formed but
  the cluster's CNI silently doesn't enforce them at all (true of some
  CNIs and CNI configurations) — a CRITICAL finding, since it means
  every NetworkPolicy in the cluster is non-functional.

NetworkPolicy semantics here are genuinely counter-intuitive
(`ingress: []` denies everything; `ingress: [{}]` allows everything —
a single empty object vs an empty list) — confirmed against the
official Kubernetes API reference before writing any detection logic,
not assumed. Egress (`egress`/`to`) follows the exact same semantics
as ingress (`ingress`/`from`). See `core/netpol.py`'s own docstring
for the full breakdown.

See [ROADMAP.md](ROADMAP.md) for what's planned next.

## Installation

```bash
git clone https://github.com/quaresma870/netpol-audit.git
cd netpol-audit
pip install .
```

## Quickstart

```bash
netpol-audit scan                          # all namespaces, current kubeconfig context
netpol-audit scan --namespace production
netpol-audit scan --context my-cluster --json findings.json

netpol-audit scan --db findings.db         # also record this run for historical tracking
netpol-audit history --db findings.db      # trend table of past runs, most recent first

# CI gate: exit non-zero only if findings exceed a configured per-severity budget
echo '{"max_critical": 0, "max_high": 0, "max_medium": 3}' > baseline.json
netpol-audit scan --baseline baseline.json

# Actively verify the cluster's CNI actually enforces NetworkPolicy (creates
# and deletes real test pods/policy; add --namespace to reuse an existing one)
netpol-audit verify-enforcement
```

## Project structure

```
netpol-audit/
├── netpol_audit/
│   ├── cli.py                # scan, history, verify-enforcement
│   ├── core/
│   │   ├── netpol.py         # NetworkPolicy semantics — parsing + coverage-gap detection
│   │   ├── cluster.py        # real kubeconfig-authenticated cluster fetching
│   │   ├── analyze.py        # orchestrates parsing into findings
│   │   ├── db.py             # --db historical persistence (stdlib sqlite3)
│   │   ├── baseline.py       # --baseline CI gating
│   │   └── enforcement.py    # verify-enforcement — active CNI enforcement probe
│   └── reports/terminal.py   # findings table + history trend table
├── tests/
│   ├── test_netpol_audit.py      # fixture-based, including a real kubernetes-client round trip
│   ├── test_persistence.py       # --db / --baseline
│   └── test_enforcement.py       # verify-enforcement's pure result-interpretation logic
└── .github/workflows/ci.yml      # spins up a real `kind` cluster for full integration testing
```

## CI

Builds the real wheel, installs it in a clean venv, and — since a real
Kubernetes cluster isn't available in a typical local dev sandbox —
spins up a real [kind](https://kind.sigs.k8s.io/) (Kubernetes in
Docker) cluster via `helm/kind-action`, deploys real pods and
NetworkPolicies covering every detection case on both ingress and
egress (coverage gap, allow-all rule, explicit 0.0.0.0/0, and a
properly-restricted control case), and runs `netpol-audit scan`,
`history`, and `--baseline` gating against it for real. It also runs
`verify-enforcement` for real against this same cluster — since
whether the cluster's actual CNI enforces NetworkPolicy depends on the
specific kindnet build in use, CI doesn't assume a fixed outcome; it
asserts the command's real exit-code/finding-severity contract holds
for whatever the live probe result actually is. This is the first and
only place this tool's live-cluster path is genuinely verified
end-to-end, not
just unit-tested against fixture data.

---

## License

MIT — see [LICENSE](LICENSE).
