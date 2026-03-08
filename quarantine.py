"""
ShieldScan Quarantine Manager
Encrypts detected malware files using AES-256-GCM before storing in
the quarantine vault.  Original files are securely deleted.
"""
import os
import shutil
import uuid
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from . import database as db

QUARANTINE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "data", "quarantine"
)


def _q_key() -> bytes:
    return db._db_key()   # reuse the database key for simplicity


class QuarantineManager:

    def __init__(self):
        os.makedirs(QUARANTINE_DIR, exist_ok=True)

    def quarantine(self, file_path: str, file_hash: str,
                   threat_name: str, severity: int) -> int | None:
        """
        Encrypt and move file to quarantine vault.
        Returns DB record id, or None on failure.
        """
        try:
            with open(file_path, "rb") as f:
                plaintext = f.read()
        except (PermissionError, OSError) as e:
            return None

        aesgcm = AESGCM(_q_key())
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        q_name = f"{uuid.uuid4().hex}.qvault"
        q_path = os.path.join(QUARANTINE_DIR, q_name)

        with open(q_path, "wb") as f:
            f.write(nonce + ciphertext)

        # Secure-delete original (overwrite with zeros first)
        try:
            with open(file_path, "r+b") as f:
                f.write(b"\x00" * len(plaintext))
            os.remove(file_path)
        except Exception:
            pass  # best-effort

        record_id = db.add_quarantine_record(
            file_path, q_path, file_hash, threat_name, severity
        )
        return record_id

    def restore(self, record_id: int) -> bool:
        """Decrypt quarantined file and restore to original path."""
        records = db.get_quarantine_records()
        rec = next((r for r in records if r["id"] == record_id), None)
        if not rec:
            return False

        q_path = rec["quarantine_path"]
        orig_path = rec["original_path"]

        try:
            with open(q_path, "rb") as f:
                raw = f.read()
            nonce, ct = raw[:12], raw[12:]
            aesgcm = AESGCM(_q_key())
            plaintext = aesgcm.decrypt(nonce, ct, None)
        except Exception:
            return False

        try:
            os.makedirs(os.path.dirname(orig_path), exist_ok=True)
            with open(orig_path, "wb") as f:
                f.write(plaintext)
            os.remove(q_path)
            db.mark_restored(record_id)
            return True
        except Exception:
            return False

    def delete_permanently(self, record_id: int) -> bool:
        """Delete quarantined file permanently (no restore)."""
        records = db.get_quarantine_records()
        rec = next((r for r in records if r["id"] == record_id), None)
        if not rec:
            return False
        try:
            os.remove(rec["quarantine_path"])
        except FileNotFoundError:
            pass
        db.mark_restored(record_id)   # marks as "handled"
        return True

    def list_quarantined(self) -> list:
        return db.get_quarantine_records()
