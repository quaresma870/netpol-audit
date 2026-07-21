"""Historical persistence for scan runs, via stdlib `sqlite3` — no
extra dependency, matching the sibling repos' `--db` pattern for
tracking findings over time instead of only ever seeing the latest
snapshot."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    label TEXT NOT NULL,
    pod_count INTEGER NOT NULL,
    policy_count INTEGER NOT NULL,
    critical INTEGER NOT NULL,
    high INTEGER NOT NULL,
    medium INTEGER NOT NULL,
    low INTEGER NOT NULL,
    info INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    target TEXT NOT NULL,
    description TEXT NOT NULL,
    remediation TEXT
);
"""


@dataclass
class RunSummary:
    id: int
    timestamp: str
    label: str
    pod_count: int
    policy_count: int
    severity_counts: dict[str, int]

    @property
    def total_findings(self) -> int:
        return sum(self.severity_counts.values())


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    return conn


def record_run(db_path: str, label: str, pod_count: int, policy_count: int, findings: list[dict]) -> int:
    """Persists one scan run and its findings, returning the new run's
    id. Severity counts are stored on the run row itself (not just
    derivable from the findings table) so `fetch_history` can list
    runs without joining/aggregating every time."""
    counts = {sev: 0 for sev in SEVERITIES}
    for f in findings:
        counts[f["severity"]] += 1

    conn = _connect(db_path)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO runs (timestamp, label, pod_count, policy_count, critical, high, medium, low, info) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.now(UTC).isoformat(),
                    label,
                    pod_count,
                    policy_count,
                    counts["CRITICAL"],
                    counts["HIGH"],
                    counts["MEDIUM"],
                    counts["LOW"],
                    counts["INFO"],
                ),
            )
            run_id = cur.lastrowid
            conn.executemany(
                "INSERT INTO findings (run_id, severity, title, target, description, remediation) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (run_id, f["severity"], f["title"], f["target"], f.get("description", ""), f.get("remediation"))
                    for f in findings
                ],
            )
        return run_id
    finally:
        conn.close()


def fetch_history(db_path: str, limit: int = 20) -> list[RunSummary]:
    """Most recent runs first."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, timestamp, label, pod_count, policy_count, critical, high, medium, low, info "
            "FROM runs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    finally:
        conn.close()

    return [
        RunSummary(
            id=row[0],
            timestamp=row[1],
            label=row[2],
            pod_count=row[3],
            policy_count=row[4],
            severity_counts={
                "CRITICAL": row[5], "HIGH": row[6], "MEDIUM": row[7], "LOW": row[8], "INFO": row[9],
            },
        )
        for row in rows
    ]


def fetch_run_findings(db_path: str, run_id: int) -> list[dict]:
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT severity, title, target, description, remediation FROM findings WHERE run_id = ?",
            (run_id,),
        ).fetchall()
    finally:
        conn.close()

    return [
        {"severity": r[0], "title": r[1], "target": r[2], "description": r[3], "remediation": r[4]}
        for r in rows
    ]
