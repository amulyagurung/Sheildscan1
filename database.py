"""
ShieldScan Database Layer
SQLite for scan records, quarantine metadata, and signature store.
Sensitive fields are AES-256-GCM encrypted using the cryptography library.
"""
import sqlite3
import os
import json
import base64
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "shieldscan.db")
_KEY_PATH = os.path.join(os.path.dirname(__file__), "..", "data", ".dbkey")


# ── Key management ────────────────────────────────────────────────────────────

def _get_or_create_key() -> bytes:
    os.makedirs(os.path.dirname(_KEY_PATH), exist_ok=True)
    if os.path.exists(_KEY_PATH):
        with open(_KEY_PATH, "rb") as f:
            return f.read()
    key = os.urandom(32)
    with open(_KEY_PATH, "wb") as f:
        f.write(key)
    return key


_DB_KEY = None

def _db_key() -> bytes:
    global _DB_KEY
    if _DB_KEY is None:
        _DB_KEY = _get_or_create_key()
    return _DB_KEY


def encrypt_field(plaintext: str) -> str:
    aesgcm = AESGCM(_db_key())
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_field(blob: str) -> str:
    raw = base64.b64decode(blob)
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(_db_key())
    return aesgcm.decrypt(nonce, ct, None).decode()


# ── Connection ────────────────────────────────────────────────────────────────

def get_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS signatures (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256_hash TEXT    NOT NULL UNIQUE,
            threat_name TEXT    NOT NULL,
            severity    INTEGER NOT NULL DEFAULT 5,
            category    TEXT    NOT NULL DEFAULT 'malware',
            added_at    TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_results (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      TEXT    NOT NULL,
            file_path    TEXT    NOT NULL,
            file_hash    TEXT,
            status       TEXT    NOT NULL,
            threat_name  TEXT,
            severity     INTEGER DEFAULT 0,
            scan_type    TEXT    NOT NULL DEFAULT 'quick',
            scanned_at   TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS quarantine_records (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path   TEXT NOT NULL,
            quarantine_path TEXT NOT NULL,
            file_hash       TEXT NOT NULL,
            threat_name     TEXT NOT NULL,
            severity        INTEGER NOT NULL,
            quarantined_at  TEXT NOT NULL,
            restored        INTEGER NOT NULL DEFAULT 0,
            encrypted_meta  TEXT
        );

        CREATE TABLE IF NOT EXISTS system_baseline (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path  TEXT NOT NULL UNIQUE,
            file_hash  TEXT NOT NULL,
            file_size  INTEGER,
            recorded_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_signatures_hash
            ON signatures(sha256_hash);
        CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id
            ON scan_results(scan_id);
        CREATE INDEX IF NOT EXISTS idx_quarantine_hash
            ON quarantine_records(file_hash);
        """)
        # Seed demo signatures
        _seed_signatures(conn)


def _seed_signatures(conn: sqlite3.Connection) -> None:
    demo = [
        # (sha256_hash, name, severity, category)
        ("44d88612fea8a8f36de82e1278abb02f", "EICAR-Test-File",         10, "test"),
        ("275a021bbfb6489e54d471899f7db9d1", "Trojan.GenericKD.48",     9,  "trojan"),
        ("e3b0c44298fc1c149afbf4c8996fb924", "Worm.AutoRun.Gen",        8,  "worm"),
        ("d41d8cd98f00b204e9800998ecf8427e", "Ransomware.WannaCry.B",   10, "ransomware"),
        ("aabbccddeeff00112233445566778899", "Spyware.AgentTesla",      7,  "spyware"),
        ("112233445566778899aabbccddeeff00", "Adware.InstallCore",      4,  "adware"),
        ("cafebabe00112233445566778899aabb", "Rootkit.Necurs",          9,  "rootkit"),
        ("deadbeef112233445566778899aabbcc", "Backdoor.Poison.Ivy",     9,  "backdoor"),
        ("feedface00aabbcc112233445566778",  "Exploit.CVE-2021-44228",  8,  "exploit"),
        ("0102030405060708090a0b0c0d0e0f10", "Trojan.Emotet.Gen",       9,  "trojan"),
    ]
    now = datetime.now().isoformat()
    for h, name, sev, cat in demo:
        conn.execute(
            "INSERT OR IGNORE INTO signatures (sha256_hash, threat_name, severity, category, added_at)"
            " VALUES (?,?,?,?,?)",
            (h, name, sev, cat, now)
        )
    conn.commit()


# ── CRUD helpers ──────────────────────────────────────────────────────────────

def get_all_signatures() -> list:
    with get_connection() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM signatures ORDER BY severity DESC"
        ).fetchall()]


def lookup_hash(sha256: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM signatures WHERE sha256_hash = ?", (sha256,)
        ).fetchone()
        return dict(row) if row else None


def insert_scan_result(scan_id, file_path, file_hash, status,
                       threat_name=None, severity=0, scan_type="quick") -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO scan_results "
            "(scan_id, file_path, file_hash, status, threat_name, severity, scan_type, scanned_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, file_path, file_hash, status,
             threat_name, severity, scan_type, datetime.now().isoformat())
        )


def get_scan_results(scan_id: str) -> list:
    with get_connection() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM scan_results WHERE scan_id = ? ORDER BY severity DESC",
            (scan_id,)
        ).fetchall()]


def get_recent_scans(limit=20) -> list:
    with get_connection() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT scan_id, scan_type, COUNT(*) as total,"
            " SUM(CASE WHEN status='threat' THEN 1 ELSE 0 END) as threats,"
            " MAX(scanned_at) as finished_at"
            " FROM scan_results GROUP BY scan_id ORDER BY finished_at DESC LIMIT ?",
            (limit,)
        ).fetchall()]


def add_quarantine_record(original_path, quarantine_path, file_hash,
                          threat_name, severity) -> int:
    meta = encrypt_field(json.dumps({"original": original_path, "hash": file_hash}))
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO quarantine_records "
            "(original_path, quarantine_path, file_hash, threat_name, severity, quarantined_at, encrypted_meta)"
            " VALUES (?,?,?,?,?,?,?)",
            (original_path, quarantine_path, file_hash,
             threat_name, severity, datetime.now().isoformat(), meta)
        )
        return cur.lastrowid


def get_quarantine_records() -> list:
    with get_connection() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM quarantine_records WHERE restored=0 ORDER BY quarantined_at DESC"
        ).fetchall()]


def mark_restored(record_id: int) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE quarantine_records SET restored=1 WHERE id=?", (record_id,))


def get_stats() -> dict:
    with get_connection() as conn:
        total_scans = conn.execute(
            "SELECT COUNT(DISTINCT scan_id) FROM scan_results"
        ).fetchone()[0]
        total_files = conn.execute(
            "SELECT COUNT(*) FROM scan_results"
        ).fetchone()[0]
        threats_found = conn.execute(
            "SELECT COUNT(*) FROM scan_results WHERE status='threat'"
        ).fetchone()[0]
        quarantined = conn.execute(
            "SELECT COUNT(*) FROM quarantine_records WHERE restored=0"
        ).fetchone()[0]
        sig_count = conn.execute(
            "SELECT COUNT(*) FROM signatures"
        ).fetchone()[0]
    return {
        "total_scans": total_scans,
        "total_files": total_files,
        "threats_found": threats_found,
        "quarantined": quarantined,
        "sig_count": sig_count,
    }
