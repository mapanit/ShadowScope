"""
Хранилище результатов сканирования.
Одна БД: data/shadowscope.db
"""
import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "shadowscope.db"
DB_PATH.parent.mkdir(exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    started_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP,
    log_file    TEXT,
    config_json TEXT,
    status      TEXT DEFAULT 'running',
    summary_json TEXT
);

CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_root TEXT NOT NULL,
    kind        TEXT NOT NULL,       -- host | url | port | tech
    value       TEXT NOT NULL,
    first_seen  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(target_root, kind, value)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER REFERENCES scans(id),
    asset_id    INTEGER REFERENCES assets(id),
    kind        TEXT NOT NULL,       -- vuln | info | takeover | ...
    severity    TEXT,                -- critical/high/medium/low/info
    title       TEXT,
    data_json   TEXT,
    fingerprint TEXT UNIQUE,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target_root);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


def _fp(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:32]


class Storage:
    def __init__(self, db_path: Path = DB_PATH):
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        scan_columns = {
            row["name"] for row in self.conn.execute("PRAGMA table_info(scans)")
        }
        if "status" not in scan_columns:
            self.conn.execute(
                "ALTER TABLE scans ADD COLUMN status TEXT DEFAULT 'running'"
            )
        if "summary_json" not in scan_columns:
            self.conn.execute("ALTER TABLE scans ADD COLUMN summary_json TEXT")
        self.conn.execute(
            "UPDATE scans SET status = 'completed' "
            "WHERE status = 'running' AND finished_at IS NOT NULL"
        )
        self.conn.commit()

    # ---- scans ----
    def start_scan(self, target: str, log_file: str, config: dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (target, log_file, config_json) VALUES (?, ?, ?)",
            (target, log_file, json.dumps(config, ensure_ascii=False)),
        )
        self.conn.commit()
        return cur.lastrowid

    def finish_scan(self, scan_id: int, status: str = "completed",
                    summary: dict | None = None):
        self.conn.execute(
            "UPDATE scans SET finished_at = ?, status = ?, summary_json = ? "
            "WHERE id = ?",
            (
                datetime.utcnow().isoformat(),
                status,
                json.dumps(summary, ensure_ascii=False) if summary is not None else None,
                scan_id,
            ),
        )
        self.conn.commit()

    def list_scans(self, limit: int = 50):
        return [
            dict(row) for row in self.conn.execute(
                """
                SELECT s.id, s.target, s.started_at, s.finished_at, s.status,
                       s.log_file, s.summary_json,
                       (SELECT COUNT(*) FROM assets a
                        WHERE a.target_root = s.target) AS asset_count,
                       (SELECT COUNT(*) FROM findings f
                        WHERE f.scan_id = s.id) AS finding_count
                FROM scans s
                ORDER BY s.id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        ]

    def scan_by_id(self, scan_id: int):
        row = self.conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        return dict(row) if row else None

    def previous_scan_id(self, target: str, current_scan_id: int):
        row = self.conn.execute(
            "SELECT id FROM scans WHERE target = ? AND id < ? "
            "ORDER BY id DESC LIMIT 1",
            (target, current_scan_id),
        ).fetchone()
        return row["id"] if row else None

    # ---- assets ----
    def add_asset(self, target_root: str, kind: str, value: str) -> int | None:
        """Возвращает asset_id. None — если уже существовал."""
        try:
            cur = self.conn.execute(
                "INSERT INTO assets (target_root, kind, value) VALUES (?, ?, ?)",
                (target_root, kind, value),
            )
            self.conn.commit()
            return cur.lastrowid
        except sqlite3.IntegrityError:
            self.conn.execute(
                "UPDATE assets SET last_seen = ? WHERE target_root = ? AND kind = ? AND value = ?",
                (datetime.utcnow().isoformat(), target_root, kind, value),
            )
            self.conn.commit()
            return None

    def assets_for(self, target_root: str, kind: str | None = None):
        q = "SELECT * FROM assets WHERE target_root = ?"
        args = [target_root]
        if kind:
            q += " AND kind = ?"
            args.append(kind)
        return [dict(r) for r in self.conn.execute(q, args).fetchall()]

    # ---- findings ----
    def add_finding(self, scan_id, asset_id, kind, severity, title, data: Any):
        fingerprint = _fp(scan_id, kind, title, json.dumps(data, sort_keys=True))
        try:
            self.conn.execute(
                "INSERT INTO findings (scan_id, asset_id, kind, severity, title, "
                "data_json, fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, asset_id, kind, severity, title,
                 json.dumps(data, ensure_ascii=False), fingerprint),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def findings_for_scan(self, scan_id: int):
        return [
            dict(r) for r in self.conn.execute(
                "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        ]

    def close(self):
        self.conn.close()