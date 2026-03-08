"""
ShieldScan Real-Time File Monitor
Uses watchdog to watch directories and scan new/modified files automatically.
"""
import os
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .engine import ScanEngine


class _ShieldHandler(FileSystemEventHandler):

    def __init__(self, engine: ScanEngine, alert_cb):
        super().__init__()
        self._engine = engine
        self._alert_cb = alert_cb
        self._lock = threading.Lock()
        self._recently_scanned = set()   # avoid double-scans

    def _should_scan(self, path: str) -> bool:
        # Skip quarantine vault files, temp files, hidden files
        basename = os.path.basename(path)
        if basename.endswith(".qvault"):
            return False
        if basename.startswith("."):
            return False
        if not os.path.isfile(path):
            return False
        return True

    def _scan(self, path: str):
        with self._lock:
            if path in self._recently_scanned:
                return
            self._recently_scanned.add(path)

        try:
            result = self._engine.scan_file(path)
            if result.status in ("threat", "suspicious"):
                self._alert_cb(result)
        finally:
            with self._lock:
                self._recently_scanned.discard(path)

    def on_created(self, event):
        if not event.is_directory and self._should_scan(event.src_path):
            t = threading.Thread(target=self._scan, args=(event.src_path,), daemon=True)
            t.start()

    def on_modified(self, event):
        if not event.is_directory and self._should_scan(event.src_path):
            t = threading.Thread(target=self._scan, args=(event.src_path,), daemon=True)
            t.start()


class FileMonitor:
    """Watch directories for new/modified files and auto-scan them."""

    def __init__(self, engine: ScanEngine, alert_cb):
        self._engine = engine
        self._alert_cb = alert_cb
        self._observer = None
        self._watched = set()
        self._running = False

    def start(self, directories: list[str]) -> None:
        if self._running:
            return
        self._observer = Observer()
        handler = _ShieldHandler(self._engine, self._alert_cb)
        for d in directories:
            if os.path.isdir(d):
                self._observer.schedule(handler, d, recursive=True)
                self._watched.add(d)
        self._observer.start()
        self._running = True

    def stop(self) -> None:
        if self._observer and self._running:
            self._observer.stop()
            self._observer.join()
            self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def watched_dirs(self) -> set:
        return set(self._watched)
