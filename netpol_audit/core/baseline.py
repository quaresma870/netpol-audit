"""CI gating: pass/fail a scan's findings against a configurable
policy baseline, instead of the blanket "fail on any CRITICAL/HIGH"
default — lets a pipeline gate on its own accepted risk level (e.g.
"fail on any CRITICAL, but allow up to 3 known MEDIUM findings")."""

from __future__ import annotations

import json

from netpol_audit.core.db import SEVERITIES

BASELINE_KEYS = {f"max_{sev.lower()}": sev for sev in SEVERITIES}


def load_baseline(path: str) -> dict[str, int]:
    """A baseline file is JSON with `max_<severity>` integer keys,
    e.g. {"max_critical": 0, "max_high": 0, "max_medium": 3}. A
    severity with no key set is treated as unlimited -- only listed
    severities are gated on."""
    with open(path) as f:
        raw = json.load(f)

    unknown = set(raw) - set(BASELINE_KEYS)
    if unknown:
        raise ValueError(
            f"Unknown baseline key(s): {', '.join(sorted(unknown))}. "
            f"Valid keys: {', '.join(sorted(BASELINE_KEYS))}."
        )

    return raw


def evaluate_baseline(findings: list[dict], limits: dict[str, int]) -> list[str]:
    """Returns a list of human-readable violation messages, one per
    severity that exceeds its configured limit. An empty list means
    the scan passes the baseline."""
    counts = {sev: 0 for sev in SEVERITIES}
    for f in findings:
        counts[f["severity"]] += 1

    violations = []
    for key, max_allowed in limits.items():
        sev = BASELINE_KEYS[key]
        actual = counts[sev]
        if actual > max_allowed:
            violations.append(
                f"{sev}: found {actual}, baseline allows at most {max_allowed}"
            )
    return violations
