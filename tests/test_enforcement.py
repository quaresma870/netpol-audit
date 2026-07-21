"""Tests for the pure interpretation logic of the active CNI
enforcement probe (core/enforcement.py). The live pod/policy/exec
mechanics in `run_enforcement_probe` need a real cluster and are only
exercised against a real `kind` cluster in CI (see
.github/workflows/ci.yml), same as core/cluster.py's live-fetching
functions."""

from __future__ import annotations

from netpol_audit.core.enforcement import interpret_probe_result


class TestInterpretProbeResult:
    def test_connection_succeeded_despite_deny_all_produces_critical_finding(self):
        """If a real connection got through despite a deny-all ingress
        NetworkPolicy being applied, the CNI isn't enforcing
        NetworkPolicy at all -- the most severe possible finding,
        since it silently voids every other NetworkPolicy in the
        cluster."""
        finding = interpret_probe_result(connection_blocked=False)
        assert finding is not None
        assert finding["severity"] == "CRITICAL"
        assert "does not enforce" in finding["title"]

    def test_connection_correctly_blocked_produces_no_finding(self):
        assert interpret_probe_result(connection_blocked=True) is None
