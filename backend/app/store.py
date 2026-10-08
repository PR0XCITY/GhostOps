"""SQLite storage for certificates and the reviewer audit log.

certificates  latest certificate per plan_id (re-analysing a plan replaces it)
audit_log     every approve/deny decision, append-only: triggers reject UPDATE
              and DELETE, so recorded decisions cannot be rewritten.
Decisions are records only; nothing here applies anything to any system.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    plan_id      TEXT PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    verdict      TEXT NOT NULL,
    generated_by TEXT NOT NULL,
    signature    TEXT NOT NULL,
    body         TEXT NOT NULL,
    stored_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id               TEXT NOT NULL,
    decision              TEXT NOT NULL CHECK (decision IN ('approve', 'deny')),
    reviewer              TEXT NOT NULL,
    comment               TEXT,
    certificate_signature TEXT NOT NULL,
    verdict_at_decision   TEXT NOT NULL,
    decided_at            TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:  # commit on success, roll back on error
                yield db
        finally:
            db.close()

    def save_certificate(self, cert: dict[str, Any]) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO certificates VALUES (?, ?, ?, ?, ?, ?, ?)",
                (cert["plan_id"], cert["timestamp"], cert["verdict"], cert["generated_by"],
                 cert["signature"], json.dumps(cert), _now()),  # keeps the certificate's field order
            )

    def get_certificate(self, plan_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT body FROM certificates WHERE plan_id = ?", (plan_id,)).fetchone()
        return json.loads(row["body"]) if row else None

    def list_certificates(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT body FROM certificates ORDER BY timestamp DESC, plan_id").fetchall()
            # Latest decision on the CURRENT version of each certificate (same signature);
            # decisions on an earlier analysis of the plan stay in the log but are not "the" decision.
            latest = {
                r["plan_id"]: dict(r) for r in db.execute(
                    "SELECT a.plan_id, a.decision, a.reviewer, a.decided_at FROM audit_log a "
                    "JOIN certificates c ON c.plan_id = a.plan_id AND c.signature = a.certificate_signature "
                    "WHERE a.id = (SELECT MAX(b.id) FROM audit_log b WHERE b.plan_id = a.plan_id "
                    "AND b.certificate_signature = c.signature)")
            }
        out = []
        for row in rows:
            cert = json.loads(row["body"])
            flags = cert["blast_radius"]["risk_flags"]
            decision = latest.get(cert["plan_id"])
            out.append({
                "plan_id": cert["plan_id"],
                "timestamp": cert["timestamp"],
                "verdict": cert["verdict"],
                "generated_by": cert["generated_by"],
                "resource_change_count": len(cert["resource_changes"]),
                "risk_flag_counts": {s: sum(f["severity"] == s for f in flags)
                                     for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
                "monthly_usd": cert["cost_delta"]["monthly_usd"],
                "shadow_applied": cert["shadow_run"]["applied"],
                "latest_decision": {k: decision[k] for k in ("decision", "reviewer", "decided_at")} if decision else None,
            })
        return out

    def add_decision(self, cert: dict[str, Any], decision: str, reviewer: str, comment: str | None) -> dict[str, Any]:
        decided_at = _now()
        with self._connect() as db:
            cur = db.execute(
                "INSERT INTO audit_log (plan_id, decision, reviewer, comment, certificate_signature, "
                "verdict_at_decision, decided_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (cert["plan_id"], decision, reviewer, comment, cert["signature"], cert["verdict"], decided_at),
            )
            row_id = cur.lastrowid
        return {"id": row_id, "plan_id": cert["plan_id"], "decision": decision, "reviewer": reviewer,
                "comment": comment, "certificate_signature": cert["signature"],
                "verdict_at_decision": cert["verdict"], "decided_at": decided_at}

    def decisions(self, plan_id: str) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM audit_log WHERE plan_id = ? ORDER BY id", (plan_id,)).fetchall()
        return [dict(r) for r in rows]
