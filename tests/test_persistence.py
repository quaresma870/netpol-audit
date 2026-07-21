"""Tests for historical persistence (core/db.py) and CI baseline
gating (core/baseline.py) — the --db / --baseline scan options."""

from __future__ import annotations

import json

import pytest

from netpol_audit.core.baseline import evaluate_baseline, load_baseline
from netpol_audit.core.db import fetch_history, fetch_run_findings, record_run

FINDINGS = [
    {"severity": "HIGH", "title": "coverage gap", "target": "default", "description": "d"},
    {"severity": "MEDIUM", "title": "allow-all", "target": "default/np", "description": "d"},
    {"severity": "MEDIUM", "title": "allow-all-2", "target": "default/np2", "description": "d"},
]


class TestRecordAndFetchRuns:
    def test_record_run_returns_incrementing_ids(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        first_id = record_run(db_path, label="all namespaces", pod_count=3, policy_count=2, findings=FINDINGS)
        second_id = record_run(db_path, label="all namespaces", pod_count=3, policy_count=2, findings=[])
        assert second_id == first_id + 1

    def test_fetch_history_orders_most_recent_first(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        record_run(db_path, label="run-1", pod_count=1, policy_count=1, findings=[])
        record_run(db_path, label="run-2", pod_count=1, policy_count=1, findings=[])
        runs = fetch_history(db_path)
        assert [r.label for r in runs] == ["run-2", "run-1"]

    def test_severity_counts_match_findings(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        record_run(db_path, label="all namespaces", pod_count=5, policy_count=1, findings=FINDINGS)
        runs = fetch_history(db_path)
        assert runs[0].severity_counts["HIGH"] == 1
        assert runs[0].severity_counts["MEDIUM"] == 2
        assert runs[0].severity_counts["CRITICAL"] == 0
        assert runs[0].total_findings == 3

    def test_fetch_history_limit(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        for i in range(5):
            record_run(db_path, label=f"run-{i}", pod_count=1, policy_count=1, findings=[])
        assert len(fetch_history(db_path, limit=2)) == 2

    def test_fetch_run_findings_round_trips(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        run_id = record_run(db_path, label="all namespaces", pod_count=1, policy_count=1, findings=FINDINGS)
        stored = fetch_run_findings(db_path, run_id)
        assert len(stored) == 3
        assert {f["title"] for f in stored} == {"coverage gap", "allow-all", "allow-all-2"}

    def test_empty_history_returns_empty_list(self, tmp_path):
        db_path = str(tmp_path / "history.db")
        assert fetch_history(db_path) == []


class TestBaseline:
    def test_load_baseline_parses_json(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text(json.dumps({"max_critical": 0, "max_high": 0, "max_medium": 3}))
        limits = load_baseline(str(path))
        assert limits == {"max_critical": 0, "max_high": 0, "max_medium": 3}

    def test_load_baseline_rejects_unknown_keys(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text(json.dumps({"max_bogus": 1}))
        with pytest.raises(ValueError):
            load_baseline(str(path))

    def test_within_limits_produces_no_violations(self):
        violations = evaluate_baseline(FINDINGS, {"max_high": 1, "max_medium": 2})
        assert violations == []

    def test_exceeding_limit_produces_violation(self):
        violations = evaluate_baseline(FINDINGS, {"max_high": 0})
        assert len(violations) == 1
        assert "HIGH" in violations[0]

    def test_unlisted_severity_is_unlimited(self):
        """A severity with no max_<severity> key in the baseline isn't
        gated on at all -- only explicitly listed severities count."""
        violations = evaluate_baseline(FINDINGS, {"max_critical": 0})
        assert violations == []

    def test_empty_findings_pass_any_baseline(self):
        assert evaluate_baseline([], {"max_critical": 0, "max_high": 0}) == []
