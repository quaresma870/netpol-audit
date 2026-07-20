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

Early, actively developed. v0.1 covers:

- **Coverage gaps** — pods not selected by any NetworkPolicy at all. A
  pod not selected by any NetworkPolicy is *non-isolated*: **all**
  ingress traffic is allowed by default, regardless of what other
  NetworkPolicies exist for other pods in the namespace. This is the
  single most important thing to check for.
- **Permissive-rule detection** — NetworkPolicies that exist and select
  pods but don't actually restrict anything: an ingress rule with no
  `from` restriction (matches all sources, per Kubernetes' own
  documented semantics), or an explicit `0.0.0.0/0` CIDR allowance.

NetworkPolicy semantics here are genuinely counter-intuitive
(`ingress: []` denies everything; `ingress: [{}]` allows everything —
a single empty object vs an empty list) — confirmed against the
official Kubernetes API reference before writing any detection logic,
not assumed. See `core/netpol.py`'s own docstring for the full
breakdown.

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
```

## Project structure

```
netpol-audit/
├── netpol_audit/
│   ├── cli.py                # scan
│   ├── core/
│   │   ├── netpol.py         # NetworkPolicy semantics — parsing + coverage-gap detection
│   │   ├── cluster.py        # real kubeconfig-authenticated cluster fetching
│   │   └── analyze.py        # orchestrates parsing into findings
│   └── reports/terminal.py
├── tests/test_netpol_audit.py    # fixture-based, including a real kubernetes-client round trip
└── .github/workflows/ci.yml      # spins up a real `kind` cluster for full integration testing
```

## CI

Builds the real wheel, installs it in a clean venv, and — since a real
Kubernetes cluster isn't available in a typical local dev sandbox —
spins up a real [kind](https://kind.sigs.k8s.io/) (Kubernetes in
Docker) cluster via `helm/kind-action`, deploys real pods and
NetworkPolicies covering every detection case (coverage gap, allow-all
rule, explicit 0.0.0.0/0, and a properly-restricted control case), and
runs `netpol-audit scan` against it for real. This is the first and
only place this tool's live-cluster path is genuinely verified
end-to-end, not just unit-tested against fixture data.

---

## License

MIT — see [LICENSE](LICENSE).
