"""Tests for Istio PeerAuthentication mTLS-mode interpretation
(core/mesh.py). The live CustomObjectsApi lookup in
`fetch_peer_authentications` needs a real cluster and is only
exercised against the real `kind` cluster in CI (confirming the
no-mesh-installed case degrades gracefully), same as
core/cluster.py's live-fetching functions."""

from __future__ import annotations

from netpol_audit.core.mesh import analyze_peer_authentications, interpret_peer_authentication


class TestInterpretPeerAuthentication:
    def test_strict_mode_produces_no_finding(self):
        assert interpret_peer_authentication("STRICT", "default", "strict-policy") is None

    def test_permissive_mode_produces_medium_finding(self):
        finding = interpret_peer_authentication("PERMISSIVE", "default", "permissive-policy")
        assert finding is not None
        assert finding["severity"] == "MEDIUM"
        assert "permissive-policy" in finding["target"]

    def test_disable_mode_produces_high_finding(self):
        finding = interpret_peer_authentication("DISABLE", "default", "disabled-policy")
        assert finding is not None
        assert finding["severity"] == "HIGH"
        assert "disabled-policy" in finding["target"]

    def test_unset_mode_produces_no_finding(self):
        """A PeerAuthentication with no `mtls.mode` set at all (e.g.
        used only for portLevelMtls overrides) doesn't set an
        effective mode at this scope -- this module doesn't attempt
        full precedence resolution, so it produces no finding for the
        object in isolation rather than guessing."""
        assert interpret_peer_authentication(None, "default", "port-level-only") is None


class TestAnalyzePeerAuthentications:
    def test_real_istio_api_shape_strict(self):
        """Fixture shaped exactly like a real PeerAuthentication
        object returned by the Kubernetes API (CustomObjectsApi),
        confirming the parsing path handles the real nested
        metadata/spec/mtls structure, not just a flattened stand-in."""
        items = [{
            "apiVersion": "security.istio.io/v1beta1",
            "kind": "PeerAuthentication",
            "metadata": {"name": "default", "namespace": "istio-system"},
            "spec": {"mtls": {"mode": "STRICT"}},
        }]
        assert analyze_peer_authentications(items) == []

    def test_real_istio_api_shape_permissive_and_disable(self):
        items = [
            {
                "metadata": {"name": "ns-default", "namespace": "payments"},
                "spec": {"mtls": {"mode": "PERMISSIVE"}},
            },
            {
                "metadata": {"name": "legacy-workload", "namespace": "payments"},
                "spec": {
                    "selector": {"matchLabels": {"app": "legacy"}},
                    "mtls": {"mode": "DISABLE"},
                },
            },
        ]
        findings = analyze_peer_authentications(items)
        assert len(findings) == 2
        assert any(f["severity"] == "MEDIUM" and "ns-default" in f["target"] for f in findings)
        assert any(f["severity"] == "HIGH" and "legacy-workload" in f["target"] for f in findings)

    def test_missing_spec_or_mtls_does_not_crash(self):
        items = [{"metadata": {"name": "bare", "namespace": "default"}}]
        assert analyze_peer_authentications(items) == []

    def test_no_namespace_in_metadata_defaults_to_istio_system(self):
        """A cluster-scoped list response can omit namespace on items
        that live in istio-system without it being explicitly echoed
        back in every case -- shouldn't crash or mislabel."""
        items = [{"metadata": {"name": "mesh-default"}, "spec": {"mtls": {"mode": "PERMISSIVE"}}}]
        findings = analyze_peer_authentications(items)
        assert findings[0]["target"] == "istio-system/mesh-default"

    def test_empty_list_produces_no_findings(self):
        assert analyze_peer_authentications([]) == []
