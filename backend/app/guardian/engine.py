"""The 8-step real-time loop. One tick per second:
collect -> 20 features -> Isolation Forest -> GRU -> survival -> policy -> act -> dashboard/log."""
import json
import os
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import psutil

from backend.app.db.database import get_db_connection, init_db
from backend.app.telemetry.recorder import validate_monitored_directory
from .attack_emulator import HEADER, MARKER
from .backup import BackupManager
from .collector import Collector
from .policy import ResponsePolicy
from .schema import FEATURE_NAMES, N_FEATURES, WINDOW_SECONDS, LOSS_THRESHOLD_FILES
from .survival import seconds_remaining
from .training import ModelStack, SAVED_DIR

BACKUP_ROOT = Path("backend/data/backups")
SANDBOX_ROOT = Path("backend/data/sandbox")
PROTECTED_NAMES = {"system", "system idle process", "registry", "smss.exe", "csrss.exe", "wininit.exe",
                   "services.exe", "lsass.exe", "winlogon.exe", "svchost.exe", "explorer.exe", "dwm.exe",
                   "init", "systemd", "launchd", "kernel_task", "sshd", "bash", "zsh", "cmd.exe",
                   "powershell.exe", "conhost.exe", "taskmgr.exe"}
CANARY_NAMES = ["0000_Passwords_backup.docx", "0001_Tax_records_final.xlsx", "0002_Family_photos_index.pdf"]


def _ensure_tables():
    init_db()
    with get_db_connection() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS guardian_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, tick INTEGER, action TEXT, risk REAL,
            p5 REAL, p10 REAL, p30 REAL, seconds_remaining REAL, if_score REAL, coverage REAL,
            lost_files INTEGER, reasons_json TEXT, suspect_pid INTEGER, suspect_name TEXT, detail_json TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS guardian_features (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, session TEXT, vec_json TEXT)""")
        c.commit()


class GuardianEngine:
    def __init__(self):
        self.lock = threading.RLock()
        self.running = False
        self.mode = "idle"            # idle | guard | learn
        self.thread: Optional[threading.Thread] = None
        self.stop_evt = threading.Event()
        self.models: Optional[ModelStack] = None
        self.collector: Optional[Collector] = None
        self.backup: Optional[BackupManager] = None
        self.policy = ResponsePolicy()
        self.root: Optional[str] = None
        self.canary_paths: List[str] = []
        self.auto_suspend = True
        self.tick_n = 0
        self.started_at = 0.0
        self.history: deque = deque(maxlen=240)
        self.decisions: deque = deque(maxlen=400)
        self.window: deque = deque(maxlen=WINDOW_SECONDS)
        self.latest: Dict[str, Any] = {}
        self.lost_files = 0
        self.last_damage_t = 0
        self.canary_total = 0
        self.canary_recent: deque = deque(maxlen=4)
        self.canary_destr: deque = deque(maxlen=4)
        self.suspended: Dict[int, Dict[str, Any]] = {}
        self.pending_suspend: Optional[Dict[str, Any]] = None
        self._shield_busy = False
        self._shield_last: Dict[str, Any] = {"files": 0, "t": 0}
        self.learn_rows: List[np.ndarray] = []
        self.demo_proc: Optional[subprocess.Popen] = None
        self.train_job: Dict[str, Any] = {"state": "idle", "log": []}
        self.session = ""

    # ------------------------------------------------------------ setup (step 1)
    def start(self, directory: str, consent: bool, mode: str = "guard", auto_suspend: bool = True,
              backup_dir: Optional[str] = None) -> Dict[str, Any]:
        if not consent:
            raise ValueError("Explicit consent is required before monitoring a folder.")
        with self.lock:
            if self.running:
                raise RuntimeError("Guardian is already running.")
            _ensure_tables()
            root = validate_monitored_directory(directory)
            if mode == "guard":
                if not ModelStack.available():
                    raise FileNotFoundError("No trained models yet. Click 'Train models' first.")
                self.models = ModelStack()
            bdir = Path(backup_dir) if backup_dir else BACKUP_ROOT / root.name
            self.backup = BackupManager(root, bdir)
            self.backup.scan()
            self.root = str(root)
            self.canary_paths = self._place_canaries(root)
            for c in self.canary_paths:               # canaries are bait, not user data
                self.backup.tracked.pop(c, None)
            self.collector = Collector(str(root), self.backup, set(self.canary_paths))
            self.policy = ResponsePolicy()
            self.auto_suspend = auto_suspend
            self.mode = mode
            self.tick_n = 0
            self.history.clear(); self.decisions.clear(); self.window.clear()
            self.latest = {}
            self.lost_files = 0; self.canary_total = 0; self.canary_recent.clear(); self.canary_destr.clear()
            self.pending_suspend = None
            self.learn_rows = []
            self.session = f"g_{int(time.time())}"
            self.started_at = time.time()
            self.collector.start()
            self.stop_evt.clear()
            self.running = True
            self.thread = threading.Thread(target=self._loop, daemon=True)
            self.thread.start()
        return {"status": "running", "mode": mode, "monitored_directory": self.root,
                "files_tracked": len(self.backup.tracked), "backup_coverage": self.backup.coverage(),
                "canaries": len(self.canary_paths), "backup_dir": str(self.backup.backup_root)}

    def _place_canaries(self, root: Path) -> List[str]:
        out = []
        dirs = [root] + sorted([d for d in root.iterdir() if d.is_dir()])[:2]
        rng = np.random.default_rng()
        words = "invoice account quarterly report budget password summary client contract notes".split()
        for i, d in enumerate(dirs[:3]):
            p = d / CANARY_NAMES[i % len(CANARY_NAMES)]
            try:
                body = HEADER + b" canary\n" + " ".join(rng.choice(words, 400)).encode()
                p.write_bytes(body)
                out.append(str(p))
            except OSError:
                continue
        return out

    def stop(self) -> Dict[str, Any]:
        with self.lock:
            if not self.running:
                return {"status": "not_running"}
            self.stop_evt.set()
        if self.thread:
            self.thread.join(timeout=5)
        with self.lock:
            self.running = False
            if self.collector:
                self.collector.stop()
            for c in self.canary_paths:
                try:
                    os.remove(c)
                except OSError:
                    pass
            n_learn = len(self.learn_rows)
            return {"status": "stopped", "ticks": self.tick_n, "learn_rows": n_learn,
                    "suspended_programs": list(self.suspended.keys())}

    # ------------------------------------------------------------ the loop
    def _loop(self):
        nxt = time.time() + 1.0
        while not self.stop_evt.is_set():
            time.sleep(max(0.0, nxt - time.time()))
            nxt += 1.0
            if nxt < time.time():
                nxt = time.time() + 1.0
            try:
                self._tick()
            except Exception as e:                      # never let the loop die silently
                self.latest["error"] = f"{type(e).__name__}: {e}"

    def _tick(self):
        now = time.time()
        vec, info = self.collector.tick(1.0)                      # steps 2-3
        self.tick_n += 1
        lost_now = int(vec[14])
        if lost_now > 0:
            self.lost_files += lost_now
            self.last_damage_t = self.tick_n
        elif self.tick_n - self.last_damage_t > 60:
            self.lost_files = 0
        self.canary_total += int(vec[12])
        self.canary_recent.append(int(vec[12]))
        self.canary_destr.append(int(info.get("canary_destructive", 0)))

        if self.mode == "learn":
            self.learn_rows.append(vec)
            self._append_history(now, vec, 0.0, [0, 0, 0], None, "LEARN", 0.0)
            return

        u = self.models.if_score(vec)                              # step 4
        self.window.append(np.concatenate([vec, [u]]))
        probs, summary = self.models.infer(np.array(self.window))  # steps 5-6
        rem = seconds_remaining(probs)
        suspect = self.collector.suspect() if (probs[2] >= 0.1 or vec[12] > 0 or u >= 0.5) else None
        unbacked = self.backup.unbacked_count()
        dec = self.policy.decide(probs, rem, u, sum(self.canary_recent), unbacked, suspect is not None,
                                 self.lost_files, self.backup.last_backup_rate, self.tick_n,
                                 canary_destructive=sum(self.canary_destr))   # step 7
        action, reasons = dec["action"], dec["reasons"]
        detail: Dict[str, Any] = {}
        if action == "SHIELD":
            detail.update(self._do_shield(unbacked))
        elif action == "SUSPEND":
            detail.update(self._do_suspend(suspect))
            detail.update(self._do_shield(unbacked, force=True))
        risk = float(max(probs[0], probs[1], 0.8 * probs[2], 0.5 * u))
        self._append_history(now, vec, u, probs, rem, action, risk, reasons, suspect, detail, summary)

    def _append_history(self, now, vec, u, probs, rem, action, risk, reasons=None, suspect=None, detail=None,
                        summary=None):
        reasons = reasons or []
        entry = {
            "t": now, "tick": self.tick_n, "action": action, "risk": round(risk, 4),
            "p5": round(float(probs[0]), 4), "p10": round(float(probs[1]), 4), "p30": round(float(probs[2]), 4),
            "seconds_remaining": None if rem is None else round(rem, 1),
            "if_score": round(float(u), 4), "coverage": round(float(vec[13]), 4),
            "events": int(vec[19]), "lost_files": self.lost_files, "canary_hits": int(vec[12]),
            "reasons": reasons, "detail": detail or {},
            "suspect": None if not suspect else {"pid": suspect["pid"], "name": suspect["name"],
                                                 "confidence": suspect.get("confidence")},
        }
        self.history.append(entry)
        self.decisions.appendleft(entry)
        self.latest = {**entry, "features": {n: round(float(v), 4) for n, v in zip(FEATURE_NAMES, vec)},
                       "summary_64": [] if summary is None else [round(float(x), 3) for x in summary[:64]]}
        try:                                                     # step 8: log every decision
            with get_db_connection() as c:
                c.execute("INSERT INTO guardian_decisions (ts,tick,action,risk,p5,p10,p30,seconds_remaining,"
                          "if_score,coverage,lost_files,reasons_json,suspect_pid,suspect_name,detail_json) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (now, self.tick_n, action, entry["risk"], entry["p5"], entry["p10"], entry["p30"],
                           rem, entry["if_score"], entry["coverage"], self.lost_files, json.dumps(reasons),
                           entry["suspect"]["pid"] if entry["suspect"] else None,
                           entry["suspect"]["name"] if entry["suspect"] else None, json.dumps(detail or {})))
                if self.mode == "learn":
                    c.execute("INSERT INTO guardian_features (ts,session,vec_json) VALUES (?,?,?)",
                              (now, self.session, json.dumps([float(x) for x in vec])))
                c.commit()
        except Exception:
            pass

    # ------------------------------------------------------------ actions (step 7)
    def _do_shield(self, unbacked: int, force: bool = False) -> Dict[str, Any]:
        if unbacked <= 0:
            return {}
        if self._shield_busy:
            return {"shield": "backup still running", **self._shield_last}
        budget = int(min(3000, max(60, self.backup.last_backup_rate * 1.2)))
        paths = self.backup.at_risk(budget)
        if not paths:
            return {}
        self._shield_busy = True

        def work():
            try:
                n = self.backup.backup_files(paths, deadline=time.time() + 0.9)
                self._shield_last = {"files": n, "t": time.time()}
            finally:
                self._shield_busy = False

        threading.Thread(target=work, daemon=True).start()
        return {"shield": f"backing up up to {len(paths)} at-risk files"}

    def _safe_to_suspend(self, pid: int) -> Optional[str]:
        """Returns None if OK, else the reason it is refused."""
        if pid in (os.getpid(), os.getppid()) or pid <= 4:
            return "refused: protected system/NitiQ process"
        try:
            p = psutil.Process(pid)
            if p.name().lower() in PROTECTED_NAMES:
                return f"refused: {p.name()} is on the protected list"
            me = psutil.Process(os.getpid())
            if pid in [a.pid for a in me.parents()]:
                return "refused: parent of NitiQ"
        except psutil.Error:
            return "refused: process not accessible"
        return None

    def _do_suspend(self, suspect) -> Dict[str, Any]:
        if not suspect:
            return {"suspend": "no program identified"}
        pid = suspect["pid"]
        if pid in self.suspended:
            return {"suspend": f"{suspect['name']} ({pid}) already suspended"}
        refusal = self._safe_to_suspend(pid)
        if refusal:
            return {"suspend": refusal}
        if not self.auto_suspend:
            self.pending_suspend = {"pid": pid, "name": suspect["name"], "confidence": suspect.get("confidence")}
            return {"suspend": f"waiting for your confirmation to pause {suspect['name']} ({pid})"}
        return self._suspend_pid(pid, suspect["name"])

    def _suspend_pid(self, pid: int, name: str) -> Dict[str, Any]:
        try:
            p = psutil.Process(pid)
            kids = p.children(recursive=True)
            p.suspend()
            for k in kids:
                try:
                    k.suspend()
                except psutil.Error:
                    pass
            self.suspended[pid] = {"name": name, "t": time.time(), "children": [k.pid for k in kids]}
            self.pending_suspend = None
            return {"suspend": f"paused {name} (pid {pid})"}
        except psutil.Error as e:
            return {"suspend": f"could not pause pid {pid}: {e}"}

    # user controls
    def confirm_suspend(self):
        if not self.pending_suspend:
            raise RuntimeError("Nothing waiting for confirmation.")
        ps = self.pending_suspend
        refusal = self._safe_to_suspend(ps["pid"])
        if refusal:
            raise RuntimeError(refusal)
        return self._suspend_pid(ps["pid"], ps["name"])

    def resume(self, pid: int):
        info = self.suspended.pop(pid, None)
        try:
            p = psutil.Process(pid)
            p.resume()
            for k in (info or {}).get("children", []):
                try:
                    psutil.Process(k).resume()
                except psutil.Error:
                    pass
        except psutil.Error as e:
            raise RuntimeError(str(e))
        return {"resumed": pid}

    def terminate(self, pid: int):
        if pid not in self.suspended:
            raise RuntimeError("Only programs NitiQ suspended can be terminated from here.")
        info = self.suspended.pop(pid)
        try:
            p = psutil.Process(pid)
            p.resume()
            p.kill()
        except psutil.Error as e:
            raise RuntimeError(str(e))
        return {"terminated": pid, "name": info["name"]}

    # ------------------------------------------------------------ dashboard (step 8)
    def state(self) -> Dict[str, Any]:
        b = self.backup
        return {
            "running": self.running, "mode": self.mode, "tick": self.tick_n,
            "uptime_s": round(time.time() - self.started_at, 1) if self.running else 0,
            "monitored_directory": self.root, "files_tracked": len(b.tracked) if b else 0,
            "unbacked_files": b.unbacked_count() if b else 0,
            "backup_coverage": round(b.coverage(), 4) if b else 0,
            "backup_dir": str(b.backup_root) if b else None,
            "canaries": [os.path.basename(c) for c in self.canary_paths],
            "canary_hits_total": self.canary_total,
            "lost_files": self.lost_files, "loss_threshold": LOSS_THRESHOLD_FILES,
            "auto_suspend": self.auto_suspend,
            "pending_suspend": self.pending_suspend,
            "suspended": [{"pid": k, **v} for k, v in self.suspended.items()],
            "models_ready": ModelStack.available(),
            "model_meta": json.loads((SAVED_DIR / "meta.json").read_text()) if (SAVED_DIR / "meta.json").exists() else None,
            "learn_rows": len(self.learn_rows),
            "demo_running": bool(self.demo_proc and self.demo_proc.poll() is None),
            "latest": self.latest,
            "history": list(self.history)[-120:],
        }

    def recent_decisions(self, limit=100, only_actions=False):
        out = [d for d in self.decisions if not only_actions or d["action"] in ("SHIELD", "SUSPEND")]
        return out[:limit]

    # ------------------------------------------------------------ demo sandbox
    def prepare_sandbox(self, n_files: int = 400, seed_backup: float = 0.4, path: Optional[str] = None):
        if self.running:
            raise RuntimeError("Stop the Guardian before re-creating the sandbox.")
        root = Path(path) if path else SANDBOX_ROOT
        if root.exists():
            if not (root / MARKER).exists():
                raise ValueError(f"{root} exists and is not a NitiQ sandbox; refusing to overwrite.")
            import shutil
            shutil.rmtree(root)
            bk = BACKUP_ROOT / root.name
            if bk.exists():
                shutil.rmtree(bk)
        rng = np.random.default_rng(1)
        root.mkdir(parents=True, exist_ok=True)
        (root / MARKER).write_text("NITIQ-SANDBOX\n")
        folders = ["Documents", "Projects", "Finance", "Pictures", "Notes"]
        words = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike".split()
        for i in range(n_files):
            d = root / folders[i % len(folders)]
            d.mkdir(exist_ok=True)
            ext = [".txt", ".csv", ".md", ".log"][i % 4]
            body = HEADER + b"\n" + " ".join(rng.choice(words, 150)).encode()
            (d / f"file_{i:04d}{ext}").write_bytes(body)
        if seed_backup > 0:
            bm = BackupManager(root, BACKUP_ROOT / root.name)
            bm.scan()
            bm.seed_backup(seed_backup, rng)
        return {"sandbox": str(root), "files": n_files, "pre_backed_up_fraction": seed_backup}

    def demo_attack(self, style: str = "rename", rate: float = 15.0, delay: float = 2.0):
        if not self.running or not self.root:
            raise RuntimeError("Start the Guardian on the sandbox folder first.")
        if not (Path(self.root) / MARKER).exists():
            raise ValueError("Demo activity only runs inside a NitiQ sandbox folder.")
        if self.demo_proc and self.demo_proc.poll() is None:
            raise RuntimeError("A demo is already running.")
        self.demo_proc = subprocess.Popen(
            [sys.executable, "-m", "backend.app.guardian.attack_emulator", "--dir", self.root, "--style", style,
             "--rate", str(rate), "--delay", str(delay)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"pid": self.demo_proc.pid, "style": style, "rate": rate}

    def demo_stop(self):
        if self.demo_proc and self.demo_proc.poll() is None:
            pid = self.demo_proc.pid
            try:
                psutil.Process(pid).resume()
            except psutil.Error:
                pass
            self.demo_proc.kill()
            self.suspended.pop(pid, None)
        return {"stopped": True}

    # ------------------------------------------------------------ training job
    def start_training(self, use_baseline: bool = True, n_normal: int = 500, n_attack: int = 500, epochs: int = 12):
        if self.train_job.get("state") == "running":
            raise RuntimeError("Training already running.")
        from .training import train_all
        _ensure_tables()
        rows = None
        if use_baseline:
            with get_db_connection() as c:
                rows = [json.loads(r[0]) for r in c.execute("SELECT vec_json FROM guardian_features").fetchall()]
            rows = np.array(rows) if rows else None
        self.train_job = {"state": "running", "log": [], "started": time.time()}

        def run():
            try:
                meta = train_all(rows, n_normal=n_normal, n_attack=n_attack, epochs=epochs,
                                 log=lambda s: self.train_job["log"].append(s))
                self.train_job.update({"state": "done", "meta": meta})
            except Exception as e:
                self.train_job.update({"state": "error", "error": str(e)})

        threading.Thread(target=run, daemon=True).start()
        return {"state": "running"}


GUARDIAN = GuardianEngine()
