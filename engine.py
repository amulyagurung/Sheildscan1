"""
ShieldScan Engine
Multi-layer malware detection:
  1. SHA-256 hash lookup against signature database
  2. Pattern-based (Aho-Corasick Trie) string matching
  3. Heuristic analysis (entropy, PE imports, packer detection)
  4. Behavioural scoring (static indicators)
"""
import os
import hashlib
import math
import struct
import uuid
import time
from dataclasses import dataclass, field
from typing import Callable

from .hash_table import HashTable
from .pattern_trie import PatternTrie
from .priority_queue import PriorityQueue
from . import database as db


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    file_path: str
    file_hash: str = ""
    status: str = "clean"       # clean | threat | suspicious | error
    threat_name: str = ""
    severity: int = 0           # 0-10
    detection_method: str = ""
    details: list = field(default_factory=list)
    scan_time_ms: float = 0.0


# ── Suspicious byte patterns ──────────────────────────────────────────────────

_SUSPICIOUS_PATTERNS = [
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "NtSetThreadContext", "RtlCreateUserThread",
    "cmd.exe /c", "powershell -enc", "powershell -w hidden",
    "WScript.Shell", "Shell.Application",
    "socket", "WSAStartup", "connect", "recv", "send",
    "RegOpenKey", "RegSetValue", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "UPX!", "FSG!", ".packed", "PECompact",
    "eval(", "exec(", "base64_decode",
    "wget http", "curl http", "bitsadmin",
    "/bin/sh", "/bin/bash", "chmod 777",
]

_RANSOMWARE_PATTERNS = [
    "CryptEncrypt", "CryptGenKey", "BCryptEncrypt",
    ".encrypted", ".locked", "YOUR_FILES_ARE_ENCRYPTED",
    "bitcoin", "ransom", "decrypt_instruction",
]

_ALL_PATTERNS = _SUSPICIOUS_PATTERNS + _RANSOMWARE_PATTERNS


# ── Heuristic thresholds ──────────────────────────────────────────────────────

ENTROPY_HIGH = 7.2          # packed / encrypted binary
ENTROPY_SUSPICIOUS = 6.5
MAX_SAFE_FILE_SIZE = 100 * 1024 * 1024   # 100 MB


class ScanEngine:
    """
    Thread-safe scan engine. Maintains its own HashTable cache of
    recently scanned hashes to avoid redundant DB lookups.
    """

    def __init__(self):
        self._hash_cache = HashTable()           # sha256 -> ScanResult
        self._pattern_trie = PatternTrie()
        self._threat_queue = PriorityQueue()     # threats ordered by severity
        self._sig_count = 0
        self._load_signatures()

    # ── Init ──────────────────────────────────────────────────────────────────

    def _load_signatures(self):
        for pat in _ALL_PATTERNS:
            self._pattern_trie.insert(pat)
        self._pattern_trie.build()
        self._sig_count = len(db.get_all_signatures())

    @property
    def signature_count(self) -> int:
        return self._sig_count

    # ── Public scan API ───────────────────────────────────────────────────────

    def scan_file(self, path: str,
                  progress_cb: Callable[[str], None] = None) -> ScanResult:
        t0 = time.perf_counter()
        result = ScanResult(file_path=path)

        if not os.path.isfile(path):
            result.status = "error"
            result.details.append("File not found or not accessible")
            return result

        # 1. Hash
        try:
            result.file_hash = self._sha256(path)
        except (PermissionError, OSError) as e:
            result.status = "error"
            result.details.append(f"Read error: {e}")
            return result

        if progress_cb:
            progress_cb(f"Hashing: {os.path.basename(path)}")

        # 2. Cache check
        cached = self._hash_cache.lookup(result.file_hash)
        if cached:
            cached.scan_time_ms = (time.perf_counter() - t0) * 1000
            return cached

        # 3. Signature DB lookup
        sig = db.lookup_hash(result.file_hash)
        if sig:
            result.status = "threat"
            result.threat_name = sig["threat_name"]
            result.severity = sig["severity"]
            result.detection_method = "signature"
            result.details.append(f"Matched: {sig['threat_name']} (category: {sig['category']})")
            self._threat_queue.push(result.severity, result)
            self._cache(result)
            result.scan_time_ms = (time.perf_counter() - t0) * 1000
            return result

        if progress_cb:
            progress_cb(f"Pattern scan: {os.path.basename(path)}")

        # 4. Pattern trie scan (first 2 MB only for performance)
        try:
            content = self._read_sample(path, 2 * 1024 * 1024)
            matches = self._pattern_trie.search(content.decode("utf-8", errors="replace"))
            if matches:
                hit_patterns = list({m[1] for m in matches})
                score = min(len(hit_patterns) * 2, 8)
                result.severity = max(result.severity, score)
                result.details.append(f"Suspicious patterns: {', '.join(hit_patterns[:5])}")
                result.detection_method = "pattern"
                if score >= 6:
                    result.status = "threat"
                    result.threat_name = "Suspicious.Pattern.Match"
                else:
                    result.status = "suspicious"
                    result.threat_name = "Heuristic.Suspicious"
        except Exception as e:
            result.details.append(f"Pattern scan error: {e}")

        if progress_cb:
            progress_cb(f"Heuristic analysis: {os.path.basename(path)}")

        # 5. Heuristic analysis
        h_result = self._heuristic_scan(path, result)
        if h_result.severity > result.severity:
            result.severity = h_result.severity
            result.details += h_result.details
            if result.status == "clean":
                result.status = h_result.status
                result.threat_name = h_result.threat_name
                result.detection_method = "heuristic"

        if result.status in ("threat", "suspicious"):
            self._threat_queue.push(result.severity, result)

        self._cache(result)
        result.scan_time_ms = (time.perf_counter() - t0) * 1000
        return result

    def scan_directory(self, path: str,
                       progress_cb: Callable[[str], None] = None,
                       stop_flag=None) -> tuple[str, list]:
        """
        Recursively scan a directory.
        Returns (scan_id, [ScanResult]).
        """
        scan_id = str(uuid.uuid4())
        results = []

        for root, dirs, files in os.walk(path):
            # Skip hidden/system directories
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if stop_flag and stop_flag():
                    break
                fpath = os.path.join(root, fname)
                if os.path.getsize(fpath) > MAX_SAFE_FILE_SIZE:
                    continue
                r = self.scan_file(fpath, progress_cb)
                results.append(r)
                db.insert_scan_result(
                    scan_id, fpath, r.file_hash,
                    r.status, r.threat_name, r.severity
                )
            if stop_flag and stop_flag():
                break

        return scan_id, results

    def get_pending_threats(self) -> list:
        """Drain the priority queue and return threats highest-severity first."""
        out = []
        while self._threat_queue:
            out.append(self._threat_queue.pop())
        return out

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _cache(self, result: ScanResult):
        if result.file_hash:
            self._hash_cache.insert(result.file_hash, result)

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _read_sample(path: str, limit: int) -> bytes:
        with open(path, "rb") as f:
            return f.read(limit)

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        ent = 0.0
        for f in freq:
            if f:
                p = f / n
                ent -= p * math.log2(p)
        return ent

    def _heuristic_scan(self, path: str, result: ScanResult) -> ScanResult:
        hr = ScanResult(file_path=path)
        try:
            sample = self._read_sample(path, 512 * 1024)
        except Exception:
            return hr

        # Entropy check
        ent = self._entropy(sample)
        if ent >= ENTROPY_HIGH:
            hr.severity = max(hr.severity, 6)
            hr.details.append(f"High entropy ({ent:.2f}) — possible packing/encryption")
            hr.status = "suspicious"
            hr.threat_name = "Heuristic.HighEntropy"

        # PE header check
        if sample[:2] == b"MZ":
            hr.details.append("Executable (PE) file detected")
            # Check for suspicious section names
            sus_sections = [b".upx", b"UPX", b"FSG"]
            for s in sus_sections:
                if s in sample:
                    hr.severity = max(hr.severity, 5)
                    hr.details.append(f"Packer signature: {s.decode(errors='replace')}")
                    hr.status = "suspicious"
                    hr.threat_name = "Heuristic.PackedExecutable"

        # Script file checks
        ext = os.path.splitext(path)[1].lower()
        if ext in (".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta"):
            if b"powershell" in sample.lower() or b"wscript" in sample.lower():
                hr.severity = max(hr.severity, 4)
                hr.details.append("Scripting interpreter invocation detected")
                if hr.status == "clean":
                    hr.status = "suspicious"
                    hr.threat_name = "Heuristic.SuspiciousScript"

        # Ransomware strings
        lower = sample.lower()
        ransom_hits = [p for p in _RANSOMWARE_PATTERNS
                       if p.lower().encode() in lower]
        if ransom_hits:
            hr.severity = max(hr.severity, 8)
            hr.details.append(f"Ransomware indicators: {', '.join(ransom_hits[:3])}")
            hr.status = "threat"
            hr.threat_name = "Heuristic.Ransomware"

        return hr
