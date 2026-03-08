"""
ShieldScan Pattern Trie — Aho-Corasick multi-pattern search.
Used for fast YARA-style byte-pattern matching in file content.
"""
from collections import deque


class _TrieNode:
    __slots__ = ("children", "fail", "output", "is_end", "pattern")

    def __init__(self):
        self.children = {}   # char -> _TrieNode
        self.fail = None     # failure link (Aho-Corasick)
        self.output = []     # patterns that end here or via fail links
        self.is_end = False
        self.pattern = None


class PatternTrie:
    """
    Insert string patterns then call build() to construct failure links.
    search(text) returns list of (start_pos, pattern) for all matches.
    O(n + m + z) where n=text len, m=total pattern len, z=match count.
    """

    def __init__(self):
        self._root = _TrieNode()
        self._built = False

    def insert(self, pattern: str) -> None:
        node = self._root
        for ch in pattern.lower():
            if ch not in node.children:
                node.children[ch] = _TrieNode()
            node = node.children[ch]
        node.is_end = True
        node.pattern = pattern
        node.output.append(pattern)
        self._built = False

    def build(self) -> None:
        """Build failure links (BFS)."""
        q = deque()
        for ch, child in self._root.children.items():
            child.fail = self._root
            q.append(child)

        while q:
            cur = q.popleft()
            for ch, child in cur.children.items():
                fail = cur.fail
                while fail and ch not in fail.children:
                    fail = fail.fail
                child.fail = fail.children[ch] if fail and ch in fail.children else self._root
                if child.fail is child:
                    child.fail = self._root
                child.output = child.output + child.fail.output
                q.append(child)

        self._built = True

    def search(self, text: str) -> list:
        if not self._built:
            self.build()
        matches = []
        node = self._root
        text_lower = text.lower()
        for i, ch in enumerate(text_lower):
            while node is not self._root and ch not in node.children:
                node = node.fail
            if ch in node.children:
                node = node.children[ch]
            for pat in node.output:
                start = i - len(pat) + 1
                matches.append((start, pat))
        return matches

    def __len__(self) -> int:
        """Count total inserted patterns."""
        count = 0
        stack = [self._root]
        while stack:
            n = stack.pop()
            if n.is_end:
                count += 1
            stack.extend(n.children.values())
        return count
