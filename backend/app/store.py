from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional

from .models import Finding, FindingStatus, RemediationAction


@dataclass(frozen=True)
class StoreConfig:
    sqlite_path: Path


class SqliteFindingsStore:
    def __init__(self, config: StoreConfig) -> None:
        self._path = config.sqlite_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                  finding_id TEXT PRIMARY KEY,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  status TEXT NOT NULL,
                  severity TEXT NOT NULL,
                  title TEXT NOT NULL,
                  description TEXT NOT NULL,
                  risk TEXT NOT NULL,
                  recommendation TEXT NOT NULL,
                  account_id TEXT NOT NULL,
                  region TEXT NOT NULL,
                  resource_id TEXT NOT NULL,
                  event_json TEXT NOT NULL,
                  ai_summary TEXT,
                  tags_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS remediations (
                  action_id TEXT PRIMARY KEY,
                  finding_id TEXT NOT NULL,
                  executed_at TEXT NOT NULL,
                  actor TEXT NOT NULL,
                  status TEXT NOT NULL,
                  details_json TEXT NOT NULL
                )
                """
            )

    def upsert_finding(self, finding: Finding) -> None:
        payload = finding.model_dump()
        event_json = json.dumps(payload["event"], default=str)
        tags_json = json.dumps(payload.get("tags", []))
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO findings (
                  finding_id, created_at, updated_at, status, severity,
                  title, description, risk, recommendation,
                  account_id, region, resource_id,
                  event_json, ai_summary, tags_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                  updated_at=excluded.updated_at,
                  status=excluded.status,
                  severity=excluded.severity,
                  title=excluded.title,
                  description=excluded.description,
                  risk=excluded.risk,
                  recommendation=excluded.recommendation,
                  account_id=excluded.account_id,
                  region=excluded.region,
                  resource_id=excluded.resource_id,
                  event_json=excluded.event_json,
                  ai_summary=excluded.ai_summary,
                  tags_json=excluded.tags_json
                """,
                (
                    payload["finding_id"],
                    payload["created_at"].isoformat(),
                    payload["updated_at"].isoformat(),
                    payload["status"],
                    payload["severity"],
                    payload["title"],
                    payload["description"],
                    payload["risk"],
                    payload["recommendation"],
                    payload["account_id"],
                    payload["region"],
                    payload["resource_id"],
                    event_json,
                    payload.get("ai_summary"),
                    tags_json,
                ),
            )

    def list_findings(
        self,
        status: Optional[FindingStatus] = None,
        limit: int = 200,
    ) -> List[Finding]:
        q = "SELECT * FROM findings"
        params: list = []
        if status is not None:
            q += " WHERE status=?"
            params.append(status.value)
        q += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(q, params).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE finding_id=?",
                (finding_id,),
            ).fetchone()
        return self._row_to_finding(row) if row else None

    def set_ai_summary(self, finding_id: str, summary: str) -> None:
        now = datetime.utcnow().isoformat()
        with self._connect() as conn:
            conn.execute(
                "UPDATE findings SET ai_summary=?, updated_at=? WHERE finding_id=?",
                (summary, now, finding_id),
            )

    def update_status(self, finding_id: str, status: FindingStatus) -> None:
        now = datetime.utcnow().isoformat()
        with self._connect() as conn:
            conn.execute(
                "UPDATE findings SET status=?, updated_at=? WHERE finding_id=?",
                (status.value, now, finding_id),
            )

    def add_remediation(self, action: RemediationAction) -> None:
        payload = action.model_dump()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO remediations (
                  action_id, finding_id, executed_at, actor, status, details_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["action_id"],
                    payload["finding_id"],
                    payload["executed_at"].isoformat(),
                    payload["actor"],
                    payload["status"],
                    json.dumps(payload["details"], default=str),
                ),
            )

    def list_remediations(self, finding_id: str) -> List[RemediationAction]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM remediations WHERE finding_id=? ORDER BY executed_at DESC",
                (finding_id,),
            ).fetchall()
        out: List[RemediationAction] = []
        for r in rows:
            out.append(
                RemediationAction(
                    action_id=r["action_id"],
                    finding_id=r["finding_id"],
                    executed_at=datetime.fromisoformat(r["executed_at"]),
                    actor=r["actor"],
                    status=r["status"],
                    details=json.loads(r["details_json"] or "{}"),
                )
            )
        return out

    def upsert_many(self, findings: Iterable[Finding]) -> None:
        for f in findings:
            self.upsert_finding(f)

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        data = dict(row)
        event = json.loads(data["event_json"])
        tags = json.loads(data["tags_json"] or "[]")
        return Finding(
            finding_id=data["finding_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            status=FindingStatus(data["status"]),
            severity=data["severity"],
            title=data["title"],
            description=data["description"],
            risk=data["risk"],
            recommendation=data["recommendation"],
            account_id=data["account_id"],
            region=data["region"],
            resource_id=data["resource_id"],
            event=event,
            ai_summary=data["ai_summary"],
            tags=tags,
        )

