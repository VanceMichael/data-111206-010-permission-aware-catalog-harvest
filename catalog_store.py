"""本地目录服务的持久状态：正式快照、证据、删除与查询时间线。

原始字节仍由 raw_store.py 保存；这里只保存可复查的目录结论及其
证据引用（来源、状态码、SHA-256 摘要）。每条正式结论都能回到
一次来源响应，未解析的依赖边和账号不可见的对象不会被折叠掉。
"""

import hashlib
import json
import sqlite3
from pathlib import Path


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


class CatalogStore:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, timeout=10)
        self.connection.execute('PRAGMA journal_mode=WAL')
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS evidence (
                key TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                subject TEXT,
                generation TEXT,
                scope_version TEXT,
                payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                generation TEXT NOT NULL,
                scope_version TEXT NOT NULL,
                signature TEXT NOT NULL,
                payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS deletions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                object_id TEXT NOT NULL,
                generation TEXT NOT NULL,
                scope_version TEXT NOT NULL,
                payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan INTEGER NOT NULL,
                object_id TEXT NOT NULL,
                observation TEXT NOT NULL,
                payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                number INTEGER NOT NULL,
                payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL);
        """)

    def close(self):
        self.connection.close()

    # -- evidence ---------------------------------------------------------
    def add_evidence(self, summary):
        key = hashlib.sha256(_canonical({
            'kind': summary.get('kind'),
            'subject': summary.get('subject'),
            'generation': summary.get('generation'),
            'scope_version': summary.get('scope_version'),
            'sources': [
                [page.get('source'), page.get('digest')]
                for page in summary.get('pages') or []
            ],
        }).encode()).hexdigest()
        with self.connection:
            self.connection.execute("""
                INSERT OR IGNORE INTO evidence
                (key, kind, subject, generation, scope_version, payload)
                VALUES (?,?,?,?,?,?)
            """, (key, summary.get('kind'), summary.get('subject'),
                  summary.get('generation'), summary.get('scope_version'),
                  _canonical(summary)))
        return key

    def evidence(self):
        rows = self.connection.execute('SELECT payload FROM evidence ORDER BY rowid')
        return [json.loads(row[0]) for row in rows]

    # -- accepted snapshots ----------------------------------------------
    def add_snapshot(self, snapshot, signature):
        with self.connection:
            self.connection.execute("""
                INSERT INTO snapshots (generation, scope_version, signature, payload)
                VALUES (?,?,?,?)
            """, (snapshot['generation'], snapshot['scope_version'],
                  _canonical(signature), _canonical(snapshot)))

    def snapshots(self):
        rows = self.connection.execute(
            'SELECT payload, signature FROM snapshots ORDER BY id')
        return [(json.loads(payload), json.loads(signature)) for payload, signature in rows]

    # -- deletion / timeline ---------------------------------------------
    def add_deletion(self, entry):
        with self.connection:
            self.connection.execute("""
                INSERT INTO deletions (object_id, generation, scope_version, payload)
                VALUES (?,?,?,?)
            """, (entry['object_id'], entry['generation'],
                  entry['scope_version'], _canonical(entry)))

    def deletions(self):
        rows = self.connection.execute('SELECT payload FROM deletions ORDER BY id')
        return [json.loads(row[0]) for row in rows]

    def add_timeline(self, entry):
        with self.connection:
            self.connection.execute("""
                INSERT INTO timeline (scan, object_id, observation, payload)
                VALUES (?,?,?,?)
            """, (entry['scan'], entry['object_id'],
                  entry['observation'], _canonical(entry)))

    def timeline(self):
        rows = self.connection.execute('SELECT payload FROM timeline ORDER BY id')
        return [json.loads(row[0]) for row in rows]

    # -- scan records ----------------------------------------------------
    def add_scan(self, record):
        with self.connection:
            self.connection.execute(
                'INSERT INTO scans (number, payload) VALUES (?,?)',
                (record['number'], _canonical(record)))

    def scans(self):
        rows = self.connection.execute('SELECT payload FROM scans ORDER BY id')
        return [json.loads(row[0]) for row in rows]

    # -- state -----------------------------------------------------------
    def set_state(self, key, value):
        with self.connection:
            self.connection.execute("""
                INSERT INTO state VALUES(?,?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """, (key, value))

    def get_state(self, key):
        row = self.connection.execute(
            'SELECT value FROM state WHERE key=?', (key,)).fetchone()
        return row[0] if row else None
