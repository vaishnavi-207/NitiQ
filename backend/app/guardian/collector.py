"""Steps 1-3: data collection (file events + program I/O) and the 20 features per second."""
import os
import threading
import time
from collections import OrderedDict
from typing import Dict, List, Optional, Set, Tuple, Any

import numpy as np
import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .backup import BackupManager
from .schema import N_FEATURES

SUSPICIOUS_EXT = {".locked", ".crypto", ".encrypted", ".ransom", ".enc", ".crypted", ".locky", ".crypt",
                  ".pay", ".wnry", ".ryuk", ".cerber", ".lockbit", ".akira"}
LOW_ENTROPY_EXT = {".txt", ".csv", ".log", ".md", ".py", ".json", ".html", ".xml", ".c", ".cpp", ".java", ".js",
                   ".ini", ".rtf", ".sql", ".tex", ".yml", ".yaml", ".docx_text"}
MAX_ENTROPY_SAMPLES = 40
MAX_PER_TICK = 4000


def shannon_entropy(path: str, nbytes: int = 4096) -> Optional[float]:
    """Entropy (0-8) of the first few KB; bytes are discarded immediately."""
    try:
        if os.path.islink(path):
            return None
        with open(path, "rb") as f:
            chunk = f.read(nbytes)
        if not chunk:
            return 0.0
        counts = np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
        p = counts[counts > 0] / len(chunk)
        return float(-(p * np.log2(p)).sum())
    except Exception:
        return None


class _Handler(FileSystemEventHandler):
    def __init__(self):
        self.events: List[Tuple[str, str, str]] = []
        self.lock = threading.Lock()

    def _add(self, kind, src, dst=""):
        with self.lock:
            if len(self.events) < 200000:
                self.events.append((kind, src, dst))

    def on_created(self, e):
        if not e.is_directory:
            self._add("created", e.src_path)

    def on_modified(self, e):
        if not e.is_directory:
            self._add("modified", e.src_path)

    def on_deleted(self, e):
        if not e.is_directory:
            self._add("deleted", e.src_path)

    def on_moved(self, e):
        if not e.is_directory:
            self._add("moved", e.src_path, getattr(e, "dest_path", ""))

    def pop(self):
        with self.lock:
            ev, self.events = self.events, []
        return ev


class Collector:
    def __init__(self, root: str, backup: BackupManager, canary_paths: Set[str]):
        self.root = os.path.realpath(root)
        self.backup = backup
        self.canaries = {os.path.realpath(p) for p in canary_paths}
        self.canary_names = {os.path.basename(p) for p in canary_paths}
        self.handler = _Handler()
        self.observer: Optional[Observer] = None
        self.last_entropy: "OrderedDict[str, float]" = OrderedDict()
        self._io_prev: Dict[int, Tuple[int, int]] = {}
        self._io_t = time.time()
        self.own_pid = os.getpid()
        self.last_writers: List[Dict[str, Any]] = []

    def start(self):
        self.observer = Observer()
        self.observer.schedule(self.handler, self.root, recursive=True)
        self.observer.start()
        self._snapshot_io()        # prime the per-program counters

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=3)
            self.observer = None

    def ignore_paths(self, paths):
        """Mark paths created by NitiQ itself (e.g. canaries at setup) so they are not counted."""
        pass

    # ---------- per-program I/O (psutil) ----------
    def _snapshot_io(self) -> Dict[int, Tuple[int, int, str]]:
        snap = {}
        for p in psutil.process_iter(["pid", "name", "io_counters"]):
            try:
                io = p.info.get("io_counters")
                if io is None:
                    continue
                snap[p.info["pid"]] = (io.read_bytes, io.write_bytes, p.info.get("name") or "?")
            except Exception:
                continue
        return snap

    def _proc_deltas(self, dt: float):
        snap = self._snapshot_io()
        out = []
        for pid, (r, w, name) in snap.items():
            if pid == self.own_pid:
                continue
            pr, pw = self._io_prev.get(pid, (r, w))
            dr, dw = max(r - pr, 0), max(w - pw, 0)
            if dw > 0 or dr > 0:
                out.append({"pid": pid, "name": name, "read": dr / dt, "write": dw / dt})
        self._io_prev = {pid: (v[0], v[1]) for pid, v in snap.items()}
        out.sort(key=lambda d: d["write"], reverse=True)
        return out

    def _confirm_in_folder(self, pid: int) -> bool:
        try:
            for f in psutil.Process(pid).open_files():
                if os.path.realpath(f.path).startswith(self.root):
                    return True
        except Exception:
            pass
        return False

    # ---------- the tick ----------
    def tick(self, dt: float = 1.0) -> Tuple[np.ndarray, Dict[str, Any]]:
        events = self.handler.pop()[:MAX_PER_TICK]
        created, modified, deleted, moved = set(), OrderedDict(), set(), []
        for kind, src, dst in events:
            if kind == "created":
                created.add(src)
            elif kind == "modified":
                modified[src] = True
            elif kind == "deleted":
                deleted.add(src)
            else:
                moved.append((src, dst))
        # a file created and modified in the same second counts as created
        for p in list(modified):
            if p in created or p in deleted:
                modified.pop(p)

        touched, dirs = set(), set()
        canary_hits = 0
        canary_destructive = 0
        unbacked_damaged = 0
        ext_changes = 0
        entropies: List[float] = []
        jumps = 0
        bytes_written = 0.0
        n_sampled = 0

        def is_canary(p):
            return os.path.basename(p) in self.canary_names or os.path.realpath(p) in self.canaries

        for p in created:
            touched.add(p); dirs.add(os.path.dirname(p))
            self.backup.note_created(p)
            self.backup.note_activity(p)
            try:
                bytes_written += os.path.getsize(p)
            except OSError:
                pass
        for p in modified:
            touched.add(p); dirs.add(os.path.dirname(p))
            self.backup.note_activity(p)
            if is_canary(p):
                canary_hits += 1
                ce = shannon_entropy(p)
                if ce is not None and ce >= 7.2:      # decoy content turned into random-looking bytes
                    canary_destructive += 1
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            bytes_written += size
            if n_sampled < MAX_ENTROPY_SAMPLES:
                e = shannon_entropy(p)
                if e is not None:
                    n_sampled += 1
                    entropies.append(e)
                    prev = self.last_entropy.get(p)
                    ext = os.path.splitext(p)[1].lower()
                    jumped = e >= 7.2 and ((prev is not None and prev < 6.8) or (prev is None and ext in LOW_ENTROPY_EXT))
                    self.last_entropy[p] = e
                    if len(self.last_entropy) > 20000:
                        self.last_entropy.popitem(last=False)
                    if jumped:
                        jumps += 1
                        self.backup.damaged.add(p)
                        if self.backup.is_unbacked(p):
                            unbacked_damaged += 1
        for p in deleted:
            touched.add(p); dirs.add(os.path.dirname(p))
            self.backup.note_activity(p)
            if is_canary(p):
                canary_hits += 1
                canary_destructive += 1
            if self.backup.is_unbacked(p):
                unbacked_damaged += 1
            self.backup.note_deleted(p)
        for src, dst in moved:
            touched.add(src); touched.add(dst); dirs.add(os.path.dirname(dst))
            self.backup.note_activity(dst)
            se, de = os.path.splitext(src)[1].lower(), os.path.splitext(dst)[1].lower()
            if is_canary(src) or is_canary(dst):
                canary_hits += 1
                if se != de or de in SUSPICIOUS_EXT:
                    canary_destructive += 1
            if se != de or de in SUSPICIOUS_EXT:
                ext_changes += 1
                if self.backup.is_unbacked(src):
                    unbacked_damaged += 1
                    self.backup.damaged.add(dst)
            self.backup.note_moved(src, dst)

        n_events = len(created) + len(modified) + len(deleted) + len(moved)
        # ---- program-level I/O (only meaningful while files are changing) ----
        writers = self._proc_deltas(dt)
        self.last_writers = writers[:5]
        top_w = top_r = rw = 0.0
        n_writers = 0
        if n_events > 0 and writers:
            n_writers = sum(1 for w in writers if w["write"] > 4096)
            top_w, top_r = writers[0]["write"], writers[0]["read"]
            rw = min(4.0, top_r / max(top_w, 1.0))

        hi = [e for e in entropies if e >= 7.2]
        vec = np.zeros(N_FEATURES)
        vec[0] = len(created)
        vec[1] = len(modified)
        vec[2] = len(deleted)
        vec[3] = len(moved)
        vec[4] = ext_changes
        vec[5] = bytes_written
        vec[6] = len(touched)
        vec[7] = len(dirs)
        vec[8] = float(np.mean(entropies)) if entropies else 0.0
        vec[9] = float(np.max(entropies)) if entropies else 0.0
        vec[10] = len(hi) / len(entropies) if entropies else 0.0
        vec[11] = jumps
        vec[12] = canary_hits
        vec[13] = self.backup.coverage()
        vec[14] = unbacked_damaged
        vec[15], vec[16], vec[17], vec[18] = top_w, top_r, rw, n_writers
        vec[19] = n_events
        self.backup.decay_activity()
        return vec, {"events": n_events, "writers": self.last_writers, "canary_destructive": canary_destructive}

    def suspect(self) -> Optional[Dict[str, Any]]:
        """Best guess at the program responsible: prefer one that has files open in the folder."""
        for w in self.last_writers[:5]:
            if w["write"] < 4096:
                continue
            if self._confirm_in_folder(w["pid"]):
                return {**w, "confidence": "confirmed (has files open in the monitored folder)"}
        if self.last_writers and self.last_writers[0]["write"] >= 4096:
            return {**self.last_writers[0], "confidence": "likely (busiest writer on the machine)"}
        return None
