"""
ShieldScan Custom Hash Table
Uses FNV-1a hashing with open addressing (quadratic probing).
No built-in dict used for core storage.
"""

_DELETED = object()  # tombstone sentinel


class HashTable:
    """Open-addressing hash table with FNV-1a and quadratic probing."""

    INITIAL_CAPACITY = 1024
    LOAD_FACTOR = 0.70

    def __init__(self):
        self._cap = self.INITIAL_CAPACITY
        self._buckets = [None] * self._cap
        self._size = 0

    # ── FNV-1a 64-bit ────────────────────────────────────────────────────────
    @staticmethod
    def _fnv1a(key: str) -> int:
        h = 0xCBF29CE484222325
        for b in key.encode("utf-8"):
            h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
        return h

    def _slot(self, key: str, i: int) -> int:
        return (self._fnv1a(key) + i * i) % self._cap

    # ── Public API ────────────────────────────────────────────────────────────
    def insert(self, key: str, value) -> None:
        if self._size / self._cap >= self.LOAD_FACTOR:
            self._resize()
        i = 0
        while True:
            idx = self._slot(key, i)
            b = self._buckets[idx]
            if b is None or b is _DELETED:
                self._buckets[idx] = (key, value)
                self._size += 1
                return
            if b[0] == key:
                self._buckets[idx] = (key, value)  # update
                return
            i += 1

    def lookup(self, key: str):
        i = 0
        while True:
            idx = self._slot(key, i)
            b = self._buckets[idx]
            if b is None:
                return None
            if b is not _DELETED and b[0] == key:
                return b[1]
            i += 1
            if i >= self._cap:
                return None

    def delete(self, key: str) -> bool:
        i = 0
        while True:
            idx = self._slot(key, i)
            b = self._buckets[idx]
            if b is None:
                return False
            if b is not _DELETED and b[0] == key:
                self._buckets[idx] = _DELETED
                self._size -= 1
                return True
            i += 1
            if i >= self._cap:
                return False

    def contains(self, key: str) -> bool:
        return self.lookup(key) is not None

    def __len__(self) -> int:
        return self._size

    def _resize(self):
        old = self._buckets
        self._cap *= 2
        self._buckets = [None] * self._cap
        self._size = 0
        for b in old:
            if b and b is not _DELETED:
                self.insert(b[0], b[1])
