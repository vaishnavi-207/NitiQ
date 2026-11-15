"""Backup manager: tracks which monitored files have a backup and copies at-risk files (SHIELD)."""
import os
import shutil
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set

MAX_BACKUP_FILE_BYTES = 50 * 1024 * 1024
MAX_TRACKED = 50000


class BackupManager:
    def __init__(self, monitored: Path, backup_root: Path):
        self.root = Path(monitored).resolve()
        self.backup_root = Path(backup_root).resolve()
        if self.backup_root == self.root or self.root in self.backup_root.parents:
            raise ValueError("Backup folder must be OUTSIDE the monitored folder.")
        self.backup_root.mkdir(parents=True, exist_ok=True)
        self.tracked: Dict[str, bool] = {}          # absolute path -> has backup
        self.damaged: Set[str] = set()              # paths we saw damaged (never back these up)
        self.dir_activity: Counter = Counter()
        self._lock = threading.RLock()
        self.total_backed_up = 0
        self.last_backup_rate = 100.0

    # -------- bookkeeping --------
    def scan(self):
        """Step 1 (setup): walk the folder and note which files already have a backup."""
        with self._lock:
            self.tracked.clear()
            n = 0
            for dp, _, fns in os.walk(self.root):
                for fn in fns:
                    p = os.path.join(dp, fn)
                    self.tracked[p] = self._backup_exists(p)
                    n += 1
                    if n >= MAX_TRACKED:
                        return n
            return n

    def _bpath(self, path: str) -> Path:
        rel = os.path.relpath(path, self.root)
        return self.backup_root / rel

    def _backup_exists(self, path: str) -> bool:
        return self._bpath(path).exists()

    def coverage(self) -> float:
        with self._lock:
            if not self.tracked:
                return 1.0
            return sum(1 for v in self.tracked.values() if v) / len(self.tracked)

    def is_unbacked(self, path: str) -> bool:
        with self._lock:
            return path in self.tracked and not self.tracked[path]

    def note_created(self, path):
        with self._lock:
            if len(self.tracked) < MAX_TRACKED:
                self.tracked.setdefault(path, False)

    def note_deleted(self, path):
        with self._lock:
            self.tracked.pop(path, None)

    def note_moved(self, src, dst):
        with self._lock:
            had = self.tracked.pop(src, None)
            if had is not None:
                self.tracked[dst] = had

    def note_activity(self, path):
        self.dir_activity[os.path.dirname(path)] += 1

    def decay_activity(self):
        for k in list(self.dir_activity):
            self.dir_activity[k] = int(self.dir_activity[k] * 0.8)
            if self.dir_activity[k] <= 0:
                del self.dir_activity[k]

    def unbacked_count(self) -> int:
        with self._lock:
            return sum(1 for v in self.tracked.values() if not v)

    # -------- SHIELD --------
    def at_risk(self, limit: int) -> List[str]:
        """Un-backed-up files, busiest folders first (ransomware tends to sweep folder by folder),
        skipping files already seen damaged."""
        with self._lock:
            cand = [p for p, v in self.tracked.items() if not v and p not in self.damaged]
        cand.sort(key=lambda p: (-self.dir_activity.get(os.path.dirname(p), 0), p))
        return cand[:limit]

    def backup_files(self, paths: List[str], deadline: Optional[float] = None) -> int:
        done = 0
        t0 = time.time()
        for p in paths:
            if deadline is not None and time.time() > deadline:
                break
            try:
                if not os.path.isfile(p) or os.path.islink(p):
                    continue
                if os.path.getsize(p) > MAX_BACKUP_FILE_BYTES:
                    continue
                dst = self._bpath(p)
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, dst)
                with self._lock:
                    if p in self.tracked:
                        self.tracked[p] = True
                done += 1
            except Exception:
                continue
        el = max(time.time() - t0, 1e-3)
        if done >= 5:
            self.last_backup_rate = 0.5 * self.last_backup_rate + 0.5 * (done / el)
        self.total_backed_up += done
        return done

    def seed_backup(self, fraction: float, rng):
        """Demo helper: pretend a nightly backup already covered `fraction` of the files."""
        with self._lock:
            paths = [p for p, v in self.tracked.items() if not v]
        rng.shuffle(paths)
        self.backup_files(paths[: int(len(paths) * fraction)])
