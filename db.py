"""
EVHunter — SQLite Storage Layer  v2.0
Persists findings, assets, and scan history.

Improvements vs original:
  - Schema versioning + automatic migration
  - scan_notes table for per-scan metadata
  - export_json / export_csv helpers
  - Index on findings.severity for faster reporting
  - Soft-delete for assets
"""

import csv
import io
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

DB_VERSION = 2


class Database:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")  # better concurrency
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    # ── Schema / Migration ────────────────────────────────────────────────────

    def _migrate(self):
        """Apply schema migrations idempotently."""
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS _meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS scans (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            target    TEXT NOT NULL,
            mode      TEXT NOT NULL DEFAULT 'recon',
            started   REAL NOT NULL,
            finished  REAL,
            status    TEXT DEFAULT 'running',
            options   TEXT DEFAULT '{}'   -- JSON of CLI flags used
        );

        CREATE TABLE IF NOT EXISTS assets (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id   INTEGER REFERENCES scans(id),
            asset     TEXT NOT NULL,
            type      TEXT,              -- subdomain | ip | endpoint | js_file
            alive     INTEGER DEFAULT 0,
            tech      TEXT DEFAULT '[]', -- JSON list
            deleted   INTEGER DEFAULT 0,
            UNIQUE(scan_id, asset)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id    INTEGER REFERENCES scans(id),
            title      TEXT NOT NULL,
            severity   TEXT DEFAULT 'info',
            asset      TEXT,
            detail     TEXT,
            curl_poc   TEXT,
            confirmed  INTEGER DEFAULT 0,
            module     TEXT DEFAULT 'ai', -- which module found this
            report     TEXT,              -- JSON report dict
            tags       TEXT DEFAULT '[]', -- JSON list of tags
            created    REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_notes (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id  INTEGER REFERENCES scans(id),
            key      TEXT NOT NULL,       -- e.g. 'dns_records', 'ssl_info'
            value    TEXT,               -- JSON blob
            created  REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan     ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_assets_scan       ON assets(scan_id);
        CREATE INDEX IF NOT EXISTS idx_notes_scan        ON scan_notes(scan_id);
        """)
        self.conn.commit()

        ver = self._meta_get("db_version")
        if ver is None:
            self._meta_set("db_version", str(DB_VERSION))
        elif int(ver) < DB_VERSION:
            self._apply_migrations(int(ver))

    def _apply_migrations(self, from_ver: int):
        """Run incremental migrations from from_ver → DB_VERSION."""
        if from_ver < 2:
            # Add columns that might not exist in v1 databases
            for stmt in [
                "ALTER TABLE scans    ADD COLUMN options TEXT DEFAULT '{}'",
                "ALTER TABLE assets   ADD COLUMN deleted INTEGER DEFAULT 0",
                "ALTER TABLE findings ADD COLUMN module TEXT DEFAULT 'ai'",
                "ALTER TABLE findings ADD COLUMN tags TEXT DEFAULT '[]'",
            ]:
                try:
                    self.conn.execute(stmt)
                except Exception:
                    pass  # column already exists
            self.conn.commit()
        self._meta_set("db_version", str(DB_VERSION))

    def _meta_get(self, key: str) -> Optional[str]:
        row = self.conn.execute("SELECT value FROM _meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def _meta_set(self, key: str, value: str):
        self.conn.execute(
            "INSERT OR REPLACE INTO _meta (key, value) VALUES (?,?)", (key, value)
        )
        self.conn.commit()

    # ── Scans ─────────────────────────────────────────────────────────────────

    def new_scan(self, target: str, mode: str = "recon", options: dict = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (target, mode, started, options) VALUES (?,?,?,?)",
            (target, mode, time.time(), json.dumps(options or {}))
        )
        self.conn.commit()
        return cur.lastrowid

    def finish_scan(self, scan_id: int, status: str = "done"):
        self.conn.execute(
            "UPDATE scans SET finished=?, status=? WHERE id=?",
            (time.time(), status, scan_id)
        )
        self.conn.commit()

    def get_scan(self, scan_id: int) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

    # ── Assets ────────────────────────────────────────────────────────────────

    def add_asset(self, scan_id: int, asset: str, type_: str,
                  alive: bool = False, tech: list = None):
        self.conn.execute(
            "INSERT OR IGNORE INTO assets (scan_id, asset, type, alive, tech) VALUES (?,?,?,?,?)",
            (scan_id, asset, type_, int(alive), json.dumps(tech or []))
        )
        self.conn.commit()

    def get_assets(self, scan_id: int, alive_only: bool = False, type_: str = None) -> list:
        q   = "SELECT * FROM assets WHERE scan_id=? AND deleted=0"
        args: list = [scan_id]
        if alive_only:
            q += " AND alive=1"
        if type_:
            q += " AND type=?"
            args.append(type_)
        return [dict(r) for r in self.conn.execute(q, args)]

    # ── Findings ──────────────────────────────────────────────────────────────

    def add_finding(self, scan_id: int, title: str, severity: str,
                    asset: str, detail: str, curl_poc: str = "",
                    confirmed: bool = False, report: dict = None,
                    module: str = "ai", tags: list = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO findings "
            "(scan_id,title,severity,asset,detail,curl_poc,confirmed,report,module,tags,created)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (scan_id, title, severity, asset, detail, curl_poc,
             int(confirmed),
             json.dumps(report) if report else None,
             module,
             json.dumps(tags or []),
             time.time())
        )
        self.conn.commit()
        return cur.lastrowid

    def confirm_finding(self, finding_id: int, report: dict = None):
        self.conn.execute(
            "UPDATE findings SET confirmed=1, report=? WHERE id=?",
            (json.dumps(report) if report else None, finding_id)
        )
        self.conn.commit()

    def get_findings(self, scan_id: int, confirmed_only: bool = False,
                     min_severity: str = None) -> list:
        sev_order = "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 " \
                    "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
        q    = f"SELECT * FROM findings WHERE scan_id=?"
        args: list = [scan_id]
        if confirmed_only:
            q += " AND confirmed=1"
        if min_severity:
            sev_map = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
            max_n   = sev_map.get(min_severity.lower(), 5)
            q += f" AND ({sev_order}) <= {max_n}"
        q += f" ORDER BY {sev_order}, created DESC"
        return [dict(r) for r in self.conn.execute(q, args)]

    def list_scans(self) -> list:
        return [dict(r) for r in self.conn.execute(
            "SELECT s.*, COUNT(f.id) as findings_count FROM scans s "
            "LEFT JOIN findings f ON f.scan_id=s.id GROUP BY s.id ORDER BY s.started DESC"
        )]

    # ── Scan Notes ────────────────────────────────────────────────────────────

    def set_note(self, scan_id: int, key: str, value: Any):
        self.conn.execute(
            "INSERT OR REPLACE INTO scan_notes (scan_id, key, value, created) VALUES (?,?,?,?)",
            (scan_id, key, json.dumps(value), time.time())
        )
        self.conn.commit()

    def get_note(self, scan_id: int, key: str) -> Optional[Any]:
        row = self.conn.execute(
            "SELECT value FROM scan_notes WHERE scan_id=? AND key=?", (scan_id, key)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def get_all_notes(self, scan_id: int) -> dict:
        rows = self.conn.execute(
            "SELECT key, value FROM scan_notes WHERE scan_id=?", (scan_id,)
        ).fetchall()
        return {r[0]: json.loads(r[1]) for r in rows}

    # ── Export ────────────────────────────────────────────────────────────────

    def export_json(self, scan_id: int) -> str:
        scan     = self.get_scan(scan_id)
        findings = self.get_findings(scan_id)
        assets   = self.get_assets(scan_id)
        notes    = self.get_all_notes(scan_id)
        return json.dumps(
            {"scan": scan, "findings": findings, "assets": assets, "notes": notes},
            indent=2, default=str
        )

    def export_csv(self, scan_id: int) -> str:
        findings = self.get_findings(scan_id)
        out = io.StringIO()
        w   = csv.DictWriter(out, fieldnames=[
            "id","title","severity","asset","detail","confirmed","module","created"
        ])
        w.writeheader()
        for f in findings:
            w.writerow({k: f.get(k,"") for k in w.fieldnames})
        return out.getvalue()

    def close(self):
        self.conn.close()
