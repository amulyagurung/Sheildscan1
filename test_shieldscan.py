"""
ShieldScan Unit Tests
Run with: pytest tests/ -v
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from src.hash_table import HashTable
from src.pattern_trie import PatternTrie
from src.priority_queue import PriorityQueue


# ── HashTable tests ────────────────────────────────────────────────────────────

class TestHashTable:

    def test_insert_and_lookup(self):
        ht = HashTable()
        ht.insert("abc123", "trojan")
        assert ht.lookup("abc123") == "trojan"

    def test_missing_key_returns_none(self):
        ht = HashTable()
        assert ht.lookup("deadbeef") is None

    def test_update_existing_key(self):
        ht = HashTable()
        ht.insert("key", "v1")
        ht.insert("key", "v2")
        assert ht.lookup("key") == "v2"
        assert len(ht) == 1

    def test_delete(self):
        ht = HashTable()
        ht.insert("x", 1)
        assert ht.delete("x") is True
        assert ht.lookup("x") is None
        assert ht.delete("x") is False

    def test_contains(self):
        ht = HashTable()
        ht.insert("a", 1)
        assert ht.contains("a") is True
        assert ht.contains("b") is False

    def test_resize_preserves_data(self):
        ht = HashTable()
        keys = [f"hash_{i:04d}" for i in range(800)]
        for k in keys:
            ht.insert(k, k)
        for k in keys:
            assert ht.lookup(k) == k

    def test_len(self):
        ht = HashTable()
        for i in range(10):
            ht.insert(str(i), i)
        assert len(ht) == 10

    def test_fnv1a_distribution(self):
        """Different keys should hash to different buckets (no trivial collision)."""
        ht = HashTable()
        hashes = {HashTable._fnv1a(str(i)) for i in range(100)}
        assert len(hashes) == 100  # all unique for small sequential ints


# ── PatternTrie tests ──────────────────────────────────────────────────────────

class TestPatternTrie:

    def test_single_pattern(self):
        t = PatternTrie()
        t.insert("malware")
        t.build()
        m = t.search("this file contains malware bytes")
        assert any(p == "malware" for _, p in m)

    def test_no_match(self):
        t = PatternTrie()
        t.insert("evil")
        t.build()
        assert t.search("completely benign text") == []

    def test_multiple_patterns(self):
        t = PatternTrie()
        for pat in ["CreateRemoteThread", "VirtualAllocEx", "socket"]:
            t.insert(pat)
        t.build()
        text = "Uses CreateRemoteThread and socket calls"
        matches = {p for _, p in t.search(text)}
        assert "createremotethread" in matches or "CreateRemoteThread".lower() in matches
        assert "socket" in matches

    def test_case_insensitive(self):
        t = PatternTrie()
        t.insert("EICAR")
        t.build()
        assert t.search("eicar test file") != []

    def test_overlapping_patterns(self):
        t = PatternTrie()
        t.insert("abc")
        t.insert("bc")
        t.build()
        matches = [p for _, p in t.search("abcdef")]
        assert "abc" in matches
        assert "bc" in matches

    def test_empty_text(self):
        t = PatternTrie()
        t.insert("test")
        t.build()
        assert t.search("") == []

    def test_len(self):
        t = PatternTrie()
        for p in ["a", "b", "c"]:
            t.insert(p)
        assert len(t) == 3


# ── PriorityQueue tests ────────────────────────────────────────────────────────

class TestPriorityQueue:

    def test_max_heap_order(self):
        pq = PriorityQueue()
        pq.push(3, "medium")
        pq.push(9, "critical")
        pq.push(1, "low")
        assert pq.pop() == "critical"
        assert pq.pop() == "medium"
        assert pq.pop() == "low"

    def test_peek(self):
        pq = PriorityQueue()
        pq.push(5, "item")
        assert pq.peek() == "item"
        assert len(pq) == 1  # peek doesn't remove

    def test_peek_priority(self):
        pq = PriorityQueue()
        pq.push(7, "x")
        assert pq.peek_priority() == 7

    def test_pop_empty_raises(self):
        pq = PriorityQueue()
        with pytest.raises(IndexError):
            pq.pop()

    def test_len(self):
        pq = PriorityQueue()
        for i in range(5):
            pq.push(i, i)
        assert len(pq) == 5
        pq.pop()
        assert len(pq) == 4

    def test_bool(self):
        pq = PriorityQueue()
        assert not pq
        pq.push(1, "x")
        assert pq

    def test_equal_priorities(self):
        """Equal priorities should still be poppable without error."""
        pq = PriorityQueue()
        for _ in range(5):
            pq.push(5, "same")
        items = [pq.pop() for _ in range(5)]
        assert items == ["same"] * 5

    def test_large_dataset(self):
        pq = PriorityQueue()
        import random
        vals = list(range(200))
        random.shuffle(vals)
        for v in vals:
            pq.push(v, v)
        result = [pq.pop() for _ in range(200)]
        assert result == list(range(199, -1, -1))


# ── Integration smoke test ─────────────────────────────────────────────────────

class TestEngineSmoke:

    def test_scan_nonexistent_file(self):
        from src.engine import ScanEngine
        from src import database as db
        db.init_db()
        engine = ScanEngine()
        r = engine.scan_file("/this/does/not/exist.exe")
        assert r.status == "error"

    def test_scan_clean_text_file(self, tmp_path):
        from src.engine import ScanEngine
        from src import database as db
        db.init_db()
        engine = ScanEngine()
        f = tmp_path / "clean.txt"
        f.write_text("Hello, world! This is a completely harmless file.")
        r = engine.scan_file(str(f))
        assert r.status in ("clean", "suspicious")  # small txt = clean
        assert r.file_hash != ""

    def test_scan_suspicious_script(self, tmp_path):
        from src.engine import ScanEngine
        from src import database as db
        db.init_db()
        engine = ScanEngine()
        f = tmp_path / "bad.ps1"
        f.write_text("powershell -w hidden -enc base64string; CreateRemoteThread")
        r = engine.scan_file(str(f))
        assert r.status in ("suspicious", "threat")
        assert r.severity > 0
