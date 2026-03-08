"""
ShieldScan Priority Queue — max-heap for threat severity ordering.
Higher severity threats bubble to the top.
"""


class PriorityQueue:
    """Max-heap. Push (priority, item); pop() returns highest priority item."""

    def __init__(self):
        self._heap = []   # list of (priority, seq, item)
        self._seq = 0     # tie-breaker

    # ── Heap helpers ──────────────────────────────────────────────────────────
    def _parent(self, i): return (i - 1) // 2
    def _left(self, i):   return 2 * i + 1
    def _right(self, i):  return 2 * i + 2

    def _swap(self, i, j):
        self._heap[i], self._heap[j] = self._heap[j], self._heap[i]

    def _sift_up(self, i):
        while i > 0:
            p = self._parent(i)
            if self._heap[i][0] > self._heap[p][0]:
                self._swap(i, p)
                i = p
            else:
                break

    def _sift_down(self, i):
        n = len(self._heap)
        while True:
            largest = i
            l, r = self._left(i), self._right(i)
            if l < n and self._heap[l][0] > self._heap[largest][0]:
                largest = l
            if r < n and self._heap[r][0] > self._heap[largest][0]:
                largest = r
            if largest == i:
                break
            self._swap(i, largest)
            i = largest

    # ── Public API ────────────────────────────────────────────────────────────
    def push(self, priority: float, item) -> None:
        self._heap.append((priority, self._seq, item))
        self._seq += 1
        self._sift_up(len(self._heap) - 1)

    def pop(self):
        if not self._heap:
            raise IndexError("pop from empty priority queue")
        self._swap(0, len(self._heap) - 1)
        _, _, item = self._heap.pop()
        if self._heap:
            self._sift_down(0)
        return item

    def peek(self):
        if not self._heap:
            return None
        return self._heap[0][2]

    def peek_priority(self):
        if not self._heap:
            return None
        return self._heap[0][0]

    def __len__(self): return len(self._heap)
    def __bool__(self): return bool(self._heap)
