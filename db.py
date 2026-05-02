"""
BugHunter - SQLite Storage Layer
Persists findings, assets, and scan history.
"""

import json
import sqlite3
import time
from pathlib import Path
from typing import Optional


class Database:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            target    TEXT NOT NULL,
            mode      TEXT NOT NULL,
            started   REAL NOT NULL,
            finished  REAL,
            status    TEXT DEFAULT 'running'
        );

        CREATE TABLE IF NOT EXISTS assets (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id   INTEGER,
            asset     TEXT NOT NULL,
            type      TEXT,  -- subdomain | ip | endpoint
            alive     INTEGER DEFAULT 0,
            tech      TEXT,  -- JSON list
            UNIQUE(scan_id, asset)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id    INTEGER,
            title      TEXT NOT NULL,
            severity   TEXT,
            asset      TEXT,
            detail     TEXT,
            curl_poc   TEXT,
            confirmed  INTEGER DEFAULT 0,
            report     TEXT,  -- JSON report dict
            created    REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_assets_scan   ON assets(scan_id);
        """)
        self.conn.commit()

    # ── Scans ──────────────────────────────────────────────────────────────────

    def new_scan(self, target: str, mode: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (target, mode, started) VALUES (?,?,?)",
            (target, mode, time.time())
        )
        self.conn.commit()
        return cur.lastrowid

    def finish_scan(self, scan_id: int, status: str = "done"):
        self.conn.execute(
            "UPDATE scans SET finished=?, status=? WHERE id=?",
            (time.time(), status, scan_id)
        )
        self.conn.commit()

    # ── Assets ────────────────────────────────────────────────────────────────

    def add_asset(self, scan_id: int, asset: str, type_: str,
                  alive: bool = False, tech: list = None):
        self.conn.execute(
            "INSERT OR IGNORE INTO assets (scan_id, asset, type, alive, tech) VALUES (?,?,?,?,?)",
            (scan_id, asset, type_, int(alive), json.dumps(tech or []))
        )
        self.conn.commit()

    def get_assets(self, scan_id: int, alive_only: bool = False) -> list:
        q = "SELECT * FROM assets WHERE scan_id=?"
        if alive_only:
            q += " AND alive=1"
        return [dict(r) for r in self.conn.execute(q, (scan_id,))]

    # ── Findings ──────────────────────────────────────────────────────────────

    def add_finding(self, scan_id: int, title: str, severity: str,
                    asset: str, detail: str, curl_poc: str = "",
                    confirmed: bool = False, report: dict = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO findings (scan_id,title,severity,asset,detail,curl_poc,confirmed,report,created)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (scan_id, title, severity, asset, detail, curl_poc,
             int(confirmed), json.dumps(report) if report else None, time.time())
        )
        self.conn.commit()
        return cur.lastrowid

    def confirm_finding(self, finding_id: int, report: dict = None):
        self.conn.execute(
            "UPDATE findings SET confirmed=1, report=? WHERE id=?",
            (json.dumps(report) if report else None, finding_id)
        )
        self.conn.commit()

    def get_findings(self, scan_id: int, confirmed_only: bool = False) -> list:
        q = "SELECT * FROM findings WHERE scan_id=?"
        if confirmed_only:
            q += " AND confirmed=1"
        q += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
        return [dict(r) for r in self.conn.execute(q, (scan_id,))]

    def list_scans(self) -> list:
        return [dict(r) for r in self.conn.execute(
            "SELECT s.*, COUNT(f.id) as findings_count FROM scans s "
            "LEFT JOIN findings f ON f.scan_id=s.id GROUP BY s.id ORDER BY s.started DESC"
        )]

    def close(self):
        self.conn.close()
