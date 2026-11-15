"""
NitiQ - Local Baseline Recorder Engine
Monitors user-consented directory using Watchdog and psutil.
Aggregates file system events into 5-second numerical feature windows.
"""

import os
import time
import uuid
import datetime
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from backend.app.telemetry.features import (
    calculate_entropy_from_filepath,
    aggregate_raw_events_to_window,
    FEATURE_SCHEMA_VERSION,
)
from backend.app.db.database import save_baseline_session, save_telemetry_windows


RESTRICTED_DIRECTORIES = {
    Path("C:/"), Path("C:/Windows"), Path("C:/Program Files"), Path("C:/Program Files (x86)"),
    Path("/"), Path("/usr"), Path("/bin"), Path("/etc"), Path("/var"), Path("/sys"), Path("/proc"),
}


def validate_monitored_directory(directory_path: str) -> Path:
    """
    Validates target directory path.
    Enforces that path exists, is a directory, and is NOT a restricted system/home root directory.
    """
    path = Path(directory_path).resolve()
    if not path.exists():
        raise ValueError(f"Directory '{directory_path}' does not exist.")
    if not path.is_dir():
        raise ValueError(f"Path '{directory_path}' is not a directory.")

    # Check root system paths
    if path in RESTRICTED_DIRECTORIES or path.parent == path:
        raise ValueError(f"Monitoring root directory '{path}' is strictly disallowed for safety.")

    # Check home directory root (e.g. C:\Users\HP or /home/username directly)
    home_dir = Path.home().resolve()
    if path == home_dir:
        raise ValueError(
            f"Monitoring the entire home directory '{path}' is disallowed. "
            "Please select a specific project subfolder (e.g. {path / 'test_sandbox'})."
        )

    return path


class TelemetryEventHandler(FileSystemEventHandler):
    """Watchdog event handler collecting in-memory event metadata without file contents."""

    def __init__(self, target_directory: str):
        super().__init__()
        self.target_directory = target_directory
        self.raw_events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def _get_process_name(self) -> str:
        try:
            current_pid = os.getpid()
            p = psutil.Process(current_pid)
            return p.name()
        except Exception:
            return "unknown"

    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        with self._lock:
            self.raw_events.append({
                "timestamp": time.time(),
                "event_type": "created",
                "src_path": event.src_path,
                "process_name": self._get_process_name(),
            })

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        entropy = calculate_entropy_from_filepath(event.src_path)
        try:
            size_delta = float(os.path.getsize(event.src_path)) if os.path.exists(event.src_path) else 0.0
        except Exception:
            size_delta = 0.0

        with self._lock:
            self.raw_events.append({
                "timestamp": time.time(),
                "event_type": "modified",
                "src_path": event.src_path,
                "size_delta": size_delta,
                "entropy": entropy,
                "process_name": self._get_process_name(),
            })

    def on_deleted(self, event: FileSystemEvent):
        if event.is_directory:
            return
        with self._lock:
            self.raw_events.append({
                "timestamp": time.time(),
                "event_type": "deleted",
                "src_path": event.src_path,
                "process_name": self._get_process_name(),
            })

    def on_moved(self, event: FileSystemEvent):
        if event.is_directory:
            return
        with self._lock:
            self.raw_events.append({
                "timestamp": time.time(),
                "event_type": "moved",
                "src_path": event.src_path,
                "dest_path": getattr(event, "dest_path", ""),
                "process_name": self._get_process_name(),
            })

    def pop_events(self) -> List[Dict[str, Any]]:
        with self._lock:
            evs = self.raw_events
            self.raw_events = []
            return evs


class BaselineRecorder:
    """Singleton background recorder for real-host telemetry."""

    def __init__(self):
        self.session_id: Optional[str] = None
        self.monitored_directory: Optional[str] = None
        self.consent_given: bool = False
        self.is_recording: bool = False
        self.start_time: float = 0.0
        self.observer: Optional[Observer] = None
        self.handler: Optional[TelemetryEventHandler] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.windows_collected: List[Dict[str, Any]] = []
        self.total_raw_events_count: int = 0

    def start_recording(self, directory_path: str, consent_given: bool) -> Dict[str, Any]:
        if not consent_given:
            raise ValueError("Explicit user consent is required before starting telemetry collection.")
        if self.is_recording:
            raise RuntimeError(f"Recording session '{self.session_id}' is already running.")

        target_path = validate_monitored_directory(directory_path)
        self.session_id = f"sess_{uuid.uuid4().hex[:8]}"
        self.monitored_directory = str(target_path)
        self.consent_given = True
        self.is_recording = True
        self.start_time = time.time()
        self.windows_collected = []
        self.total_raw_events_count = 0
        self._stop_event.clear()

        # Set up Watchdog listener
        self.handler = TelemetryEventHandler(str(target_path))
        self.observer = Observer()
        self.observer.schedule(self.handler, str(target_path), recursive=True)
        self.observer.start()

        # Start 5-second window aggregation thread
        self._thread = threading.Thread(target=self._window_aggregation_loop, daemon=True)
        self._thread.start()

        return {
            "session_id": self.session_id,
            "status": "recording",
            "monitored_directory": self.monitored_directory,
            "started_at": datetime.datetime.fromtimestamp(self.start_time).isoformat(),
            "schema_version": FEATURE_SCHEMA_VERSION,
        }

    def _window_aggregation_loop(self):
        last_window_time = time.time()
        while not self._stop_event.is_set():
            time.sleep(1.0)
            now = time.time()
            if now - last_window_time >= 5.0:
                evs = self.handler.pop_events() if self.handler else []
                self.total_raw_events_count += len(evs)
                window = aggregate_raw_events_to_window(evs, last_window_time, now)
                self.windows_collected.append(window)
                last_window_time = now

    def stop_recording(self) -> Dict[str, Any]:
        if not self.is_recording or not self.session_id:
            raise RuntimeError("No active telemetry recording session to stop.")

        self._stop_event.set()
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=3.0)
            self.observer = None

        if self._thread:
            self._thread.join(timeout=3.0)
            self._thread = None

        end_time = time.time()
        duration_seconds = round(end_time - self.start_time, 2)
        self.is_recording = False

        # Pop any remaining events
        if self.handler:
            final_evs = self.handler.pop_events()
            if final_evs:
                self.total_raw_events_count += len(final_evs)
                final_window = aggregate_raw_events_to_window(
                    final_evs, end_time - 5.0, end_time
                )
                self.windows_collected.append(final_window)
            self.handler = None

        # Persist session and windows to SQLite
        created_at_str = datetime.datetime.fromtimestamp(self.start_time).isoformat()
        save_baseline_session(
            session_id=self.session_id,
            created_at=created_at_str,
            monitored_directory=self.monitored_directory or "",
            consent_given=self.consent_given,
            duration_seconds=duration_seconds,
            window_count=len(self.windows_collected),
            event_count=self.total_raw_events_count,
            source_type="real_host",
        )
        save_telemetry_windows(self.session_id, self.windows_collected)

        res = {
            "session_id": self.session_id,
            "status": "stopped",
            "duration_seconds": duration_seconds,
            "window_count": len(self.windows_collected),
            "total_event_count": self.total_raw_events_count,
            "monitored_directory": self.monitored_directory,
        }

        # Warning for short recording duration (<30 mins)
        if duration_seconds < 1800.0:
            res["duration_warning"] = (
                f"Recording duration ({duration_seconds}s) is below recommended 30 minutes (1800s). "
                "Models trained on short baselines may produce higher false positive rates."
            )

        return res

    def get_status(self) -> Dict[str, Any]:
        if not self.is_recording:
            return {
                "is_recording": False,
                "session_id": self.session_id,
                "monitored_directory": self.monitored_directory,
            }
        now = time.time()
        duration = round(now - self.start_time, 2)
        return {
            "is_recording": True,
            "session_id": self.session_id,
            "monitored_directory": self.monitored_directory,
            "duration_seconds": duration,
            "window_count": len(self.windows_collected),
            "event_count": self.total_raw_events_count,
        }


GLOBAL_RECORDER = BaselineRecorder()
