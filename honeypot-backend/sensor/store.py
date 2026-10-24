"""Local SQLite store for telemetry, findings, blocks and decoy actions.

The sensor keeps its own store so it keeps recording even when the
FastAPI/PostgreSQL backend is offline. All access goes through one lock
because listeners write from asyncio tasks and from SSH worker threads.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .events import Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_port INTEGER,
    service TEXT,
    detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_src ON events (src_ip, ts);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events (ts);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    classification TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    rule_points INTEGER NOT NULL,
    ml_points INTEGER NOT NULL,
    reasons TEXT NOT NULL,
    evidence TEXT NOT NULL,
    decision TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_findings_ts ON findings (ts);

CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    status TEXT NOT NULL,
    mode TEXT NOT NULL,
    source TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_ts REAL NOT NULL,
    expires_ts REAL,
    released_ts REAL,
    error TEXT
);
CREATE INDEX IF NOT EXISTS ix_blocks_ip ON blocks (ip);

CREATE TABLE IF NOT EXISTS decoy_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    persona TEXT NOT NULL,
    level INTEGER NOT NULL,
    reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_decoy_ip ON decoy_actions (src_ip, ts);

CREATE TABLE IF NOT EXISTS honeytokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    token_kind TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE
);
"""


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(path), check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def insert_event(self, event: Event) -> int:
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO events (ts, kind, src_ip, dst_port, service, detail)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    event.ts,
                    event.kind,
                    event.src_ip,
                    event.dst_port,
                    event.service,
                    json.dumps(event.detail, default=str),
                ),
            )
            return int(cursor.lastrowid)

    def recent_events(
        self,
        limit: int = 100,
        src_ip: str | None = None,
        kind: str | None = None,
    ) -> list[dict]:
        clauses, params = [], []
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM events {where} ORDER BY ts DESC, id DESC LIMIT ?",
                (*params, limit),
            ).fetchall()
        return [self._event_row(row) for row in rows]

    def _event_row(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "time": _iso(row["ts"]),
            "kind": row["kind"],
            "src_ip": row["src_ip"],
            "dst_port": row["dst_port"],
            "service": row["service"],
            "detail": json.loads(row["detail"]),
        }

    def intel_rows(self, since_ts: float, limit: int = 50000) -> list[dict]:
        """Events since a timestamp, with details decoded, for threat-intel views."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, kind, src_ip, dst_port, service, detail FROM events"
                " WHERE ts >= ? ORDER BY ts ASC LIMIT ?",
                (since_ts, limit),
            ).fetchall()
        return [
            {
                "ts": row["ts"],
                "kind": row["kind"],
                "src_ip": row["src_ip"],
                "dst_port": row["dst_port"],
                "service": row["service"],
                "detail": json.loads(row["detail"]),
            }
            for row in rows
        ]

    def findings_since(self, since_ts: float, limit: int = 5000) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, src_ip, classification, severity, score FROM findings"
                " WHERE ts >= ? ORDER BY ts ASC LIMIT ?",
                (since_ts, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def count_events_since(self, since_ts: float) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= ?", (since_ts,)
            ).fetchone()
        return int(row[0])

    # ------------------------------------------------------------------
    # Sources (one row per attacker IP)
    # ------------------------------------------------------------------

    def source_summary(self, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT src_ip,
                       COUNT(*) AS events,
                       COUNT(DISTINCT dst_port) AS ports,
                       MIN(ts) AS first_seen,
                       MAX(ts) AS last_seen
                FROM events
                WHERE src_ip != ''
                GROUP BY src_ip
                ORDER BY last_seen DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            sources = []
            for row in rows:
                worst = self._conn.execute(
                    """
                    SELECT classification, severity, score FROM findings
                    WHERE src_ip = ? ORDER BY score DESC, id DESC LIMIT 1
                    """,
                    (row["src_ip"],),
                ).fetchone()
                sources.append({
                    "src_ip": row["src_ip"],
                    "events": row["events"],
                    "ports_touched": row["ports"],
                    "first_seen": _iso(row["first_seen"]),
                    "last_seen": _iso(row["last_seen"]),
                    "top_classification": worst["classification"] if worst else None,
                    "top_severity": worst["severity"] if worst else None,
                    "top_score": worst["score"] if worst else 0,
                })
        return sources

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def insert_finding(self, finding: dict) -> int:
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO findings
                (ts, src_ip, classification, severity, score, rule_points,
                 ml_points, reasons, evidence, decision)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding["ts"],
                    finding["src_ip"],
                    finding["classification"],
                    finding["severity"],
                    finding["score"],
                    finding["rule_points"],
                    finding["ml_points"],
                    json.dumps(finding["reasons"]),
                    json.dumps(finding["evidence"], default=str),
                    json.dumps(finding.get("decision", {}), default=str),
                ),
            )
            return int(cursor.lastrowid)

    def update_finding_decision(self, finding_id: int, decision: dict) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE findings SET decision = ? WHERE id = ?",
                (json.dumps(decision, default=str), finding_id),
            )

    def recent_findings(
        self,
        limit: int = 100,
        severity: str | None = None,
        src_ip: str | None = None,
    ) -> list[dict]:
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM findings {where} ORDER BY ts DESC, id DESC LIMIT ?",
                (*params, limit),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "time": _iso(row["ts"]),
                "src_ip": row["src_ip"],
                "classification": row["classification"],
                "severity": row["severity"],
                "score": row["score"],
                "rule_points": row["rule_points"],
                "ml_points": row["ml_points"],
                "reasons": json.loads(row["reasons"]),
                "evidence": json.loads(row["evidence"]),
                "decision": json.loads(row["decision"]),
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Blocks
    # ------------------------------------------------------------------

    def insert_block(
        self,
        ip: str,
        status: str,
        mode: str,
        source: str,
        reason: str,
        expires_ts: float | None,
    ) -> int:
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO blocks
                (ip, status, mode, source, reason, created_ts, expires_ts)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (ip, status, mode, source, reason, time.time(), expires_ts),
            )
            return int(cursor.lastrowid)

    def set_block_status(
        self,
        block_id: int,
        status: str,
        error: str | None = None,
        released: bool = False,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE blocks
                SET status = ?, error = ?,
                    released_ts = CASE WHEN ? THEN ? ELSE released_ts END
                WHERE id = ?
                """,
                (status, error, released, time.time() if released else None, block_id),
            )

    def active_block_for_ip(self, ip: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM blocks
                WHERE ip = ? AND released_ts IS NULL
                  AND status IN ('PENDING', 'ACTIVE', 'DRY_RUN', 'REMOVING')
                ORDER BY id DESC LIMIT 1
                """,
                (ip,),
            ).fetchone()
        return self._block_row(row) if row else None

    def active_blocks(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM blocks
                WHERE released_ts IS NULL
                  AND status IN ('PENDING', 'ACTIVE', 'DRY_RUN', 'REMOVING')
                ORDER BY id DESC
                """
            ).fetchall()
        return [self._block_row(row) for row in rows]

    def blocks_due_for_expiry(self, now: float) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM blocks
                WHERE released_ts IS NULL
                  AND status IN ('PENDING', 'ACTIVE', 'DRY_RUN')
                  AND expires_ts IS NOT NULL AND expires_ts <= ?
                """,
                (now,),
            ).fetchall()
        return [self._block_row(row) for row in rows]

    def block_history(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM blocks ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._block_row(row) for row in rows]

    def get_block(self, block_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM blocks WHERE id = ?", (block_id,)
            ).fetchone()
        return self._block_row(row) if row else None

    def _block_row(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "ip": row["ip"],
            "status": row["status"],
            "mode": row["mode"],
            "source": row["source"],
            "reason": row["reason"],
            "created": _iso(row["created_ts"]),
            "expires": _iso(row["expires_ts"]),
            "released": _iso(row["released_ts"]),
            "error": row["error"],
        }

    # ------------------------------------------------------------------
    # Decoy actions and honeytokens
    # ------------------------------------------------------------------

    def insert_decoy_action(
        self, src_ip: str, persona: str, level: int, reason: str
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO decoy_actions (ts, src_ip, persona, level, reason)"
                " VALUES (?, ?, ?, ?, ?)",
                (time.time(), src_ip, persona, level, reason),
            )

    def latest_decoy_action(self, src_ip: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM decoy_actions WHERE src_ip = ?"
                " ORDER BY ts DESC, id DESC LIMIT 1",
                (src_ip,),
            ).fetchone()
        if row is None:
            return None
        return {
            "ts": row["ts"],
            "time": _iso(row["ts"]),
            "src_ip": row["src_ip"],
            "persona": row["persona"],
            "level": row["level"],
            "reason": row["reason"],
        }

    def recent_decoy_actions(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM decoy_actions ORDER BY ts DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "time": _iso(row["ts"]),
                "src_ip": row["src_ip"],
                "persona": row["persona"],
                "level": row["level"],
                "reason": row["reason"],
            }
            for row in rows
        ]

    def add_honeytoken(self, src_ip: str, token_kind: str, token: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO honeytokens (ts, src_ip, token_kind, token)"
                " VALUES (?, ?, ?, ?)",
                (time.time(), src_ip, token_kind, token),
            )

    def all_honeytokens(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT src_ip, token_kind, token FROM honeytokens"
            ).fetchall()
        return [dict(row) for row in rows]

    def honeytoken_for_ip(self, src_ip: str, token_kind: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT token FROM honeytokens WHERE src_ip = ? AND token_kind = ?"
                " ORDER BY id DESC LIMIT 1",
                (src_ip, token_kind),
            ).fetchone()
        return row["token"] if row else None
