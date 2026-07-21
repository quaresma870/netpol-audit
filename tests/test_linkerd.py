"""Tests for Linkerd injection-mismatch detection (core/linkerd.py).
The live pod/namespace fetching in `fetch_pod_injection_info` /
`fetch_namespace_inject_annotations` needs a real cluster and is only
exercised in CI -- but unlike core/mesh.py's Istio check, that CI
verification doesn't need a real Linkerd control plane installed,
since the check only inspects pod annotations and container names."""

from __future__ import annotations

from netpol_audit.core.linkerd import (
    PodInjectionInfo,
    analyze_injection,
    pod_needs_injection_but_missing_proxy,
)


class TestPodNeedsInjectionButMissingProxy:
    def test_pod_level_enabled_without_proxy_is_flagged(self):
        assert pod_needs_injection_but_missing_proxy(
            namespace_inject=None, pod_inject="enabled", has_proxy_container=False,
        ) is True

    def test_pod_level_enabled_with_proxy_is_not_flagged(self):
        assert pod_needs_injection_but_missing_proxy(
            namespace_inject=None, pod_inject="enabled", has_proxy_container=True,
        ) is False

    def test_namespace_level_enabled_inherited_without_proxy_is_flagged(self):
        """No pod-level annotation at all -- inherits the namespace's."""
        assert pod_needs_injection_but_missing_proxy(
            namespace_inject="enabled", pod_inject=None, has_proxy_container=False,
        ) is True

    def test_pod_level_disabled_overrides_namespace_enabled(self):
        """A pod explicitly opting out of an otherwise-injected
        namespace is correctly NOT flagged, even with no proxy --
        it was never supposed to be meshed."""
        assert pod_needs_injection_but_missing_proxy(
            namespace_inject="enabled", pod_inject="disabled", has_proxy_container=False,
        ) is False

    def test_neither_level_annotated_is_not_flagged(self):
        assert pod_needs_injection_but_missing_proxy(
            namespace_inject=None, pod_inject=None, has_proxy_container=False,
        ) is False

    def test_disabled_namespace_with_proxy_container_present_not_flagged(self):
        """Not our concern either way -- injection wasn't intended,
        regardless of what containers happen to exist."""
        assert pod_needs_injection_but_missing_proxy(
            namespace_inject="disabled", pod_inject=None, has_proxy_container=True,
        ) is False


class TestAnalyzeInjection:
    def test_flagged_pods_grouped_by_namespace(self):
        pods = [
            PodInjectionInfo(name="web-1", namespace="payments", inject_annotation=None, has_proxy_container=False),
            PodInjectionInfo(name="web-2", namespace="payments", inject_annotation=None, has_proxy_container=False),
        ]
        findings = analyze_injection(pods, {"payments": "enabled"})
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert "2 pod(s)" in findings[0]["title"]
        assert "web-1" in findings[0]["description"]
        assert "web-2" in findings[0]["description"]

    def test_correctly_injected_pod_produces_no_finding(self):
        pods = [
            PodInjectionInfo(name="web-1", namespace="payments", inject_annotation=None, has_proxy_container=True),
        ]
        assert analyze_injection(pods, {"payments": "enabled"}) == []

    def test_unmeshed_namespace_produces_no_finding(self):
        pods = [
            PodInjectionInfo(name="web-1", namespace="default", inject_annotation=None, has_proxy_container=False),
        ]
        assert analyze_injection(pods, {"default": None}) == []

    def test_different_namespaces_produce_separate_findings(self):
        pods = [
            PodInjectionInfo(name="web-1", namespace="payments", inject_annotation=None, has_proxy_container=False),
            PodInjectionInfo(name="api-1", namespace="checkout", inject_annotation=None, has_proxy_container=False),
        ]
        findings = analyze_injection(pods, {"payments": "enabled", "checkout": "enabled"})
        assert len(findings) == 2
        targets = {f["target"] for f in findings}
        assert targets == {"payments", "checkout"}

    def test_missing_namespace_annotation_entry_treated_as_unset(self):
        """A pod in a namespace with no entry in the annotations dict
        (e.g. because fetch_namespace_inject_annotations returned {}
        after an RBAC denial) falls back to just the pod's own
        annotation, not a crash."""
        pods = [
            PodInjectionInfo(name="web-1", namespace="payments", inject_annotation="enabled", has_proxy_container=False),
        ]
        findings = analyze_injection(pods, {})
        assert len(findings) == 1

    def test_empty_pod_list_produces_no_findings(self):
        assert analyze_injection([], {}) == []
