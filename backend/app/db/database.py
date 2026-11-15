"""
NitiQ - Database & Local Telemetry Persistence Engine (SQLite)
Provides idempotent schema creation, baseline telemetry persistence,
training metadata storage, and confirmed baseline deletion.
"""

import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Any

DB_PATH = Path("backend/nitiq_telemetry.db")


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """Initializes SQLite tables idempotently."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Sessions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS baseline_sessions (
                session_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                monitored_directory TEXT NOT NULL,
                consent_given INTEGER NOT NULL DEFAULT 1,
                duration_seconds REAL NOT NULL DEFAULT 0.0,
                window_count INTEGER NOT NULL DEFAULT 0,
                event_count INTEGER NOT NULL DEFAULT 0,
                source_type TEXT NOT NULL DEFAULT 'real_host'
            );
        """)

        # Telemetry Windows
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_windows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                window_start REAL NOT NULL,
                window_end REAL NOT NULL,
                event_count INTEGER NOT NULL,
                create_count INTEGER NOT NULL,
                modify_count INTEGER NOT NULL,
                delete_count INTEGER NOT NULL,
                move_rename_count INTEGER NOT NULL,
                extension_change_count INTEGER NOT NULL,
                file_size_delta_bytes REAL NOT NULL,
                write_throughput_bytes_per_sec REAL NOT NULL,
                distinct_files_count INTEGER NOT NULL,
                distinct_dirs_count INTEGER NOT NULL,
                high_entropy_ratio REAL NOT NULL,
                decoy_touches_count INTEGER NOT NULL,
                top_process_name TEXT NOT NULL DEFAULT 'unknown',
                is_malicious INTEGER NOT NULL DEFAULT 0,
                stage_tag TEXT NOT NULL DEFAULT 'normal',
                FOREIGN KEY(session_id) REFERENCES baseline_sessions(session_id) ON DELETE CASCADE
            );
        """)

        # Trained Models Metadata
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ml_models (
                model_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                feature_names_json TEXT NOT NULL,
                training_row_count INTEGER NOT NULL,
                training_session_ids_json TEXT NOT NULL,
                training_start_time REAL NOT NULL,
                training_end_time REAL NOT NULL,
                random_seed INTEGER NOT NULL,
                threshold_value REAL NOT NULL,
                sensitivity REAL NOT NULL,
                artifact_filename TEXT NOT NULL
            );
        """)

        # Safe Evaluation Results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evaluation_results (
                eval_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                model_id TEXT NOT NULL,
                detector_type TEXT NOT NULL,
                test_window_count INTEGER NOT NULL,
                heldout_normal_count INTEGER NOT NULL,
                emulator_window_count INTEGER NOT NULL,
                detection_rate REAL NOT NULL,
                false_positive_rate REAL NOT NULL,
                precision REAL NOT NULL,
                recall REAL NOT NULL,
                f1_score REAL NOT NULL,
                tp INTEGER NOT NULL,
                fp INTEGER NOT NULL,
                tn INTEGER NOT NULL,
                fn INTEGER NOT NULL,
                per_stage_json TEXT NOT NULL,
                ttd_hours REAL NOT NULL
            );
        """)

        # Live Detector Alerts
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS live_alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                session_id TEXT NOT NULL,
                anomaly_score REAL NOT NULL,
                threshold_value REAL NOT NULL,
                explanations_json TEXT NOT NULL,
                stage_tag TEXT NOT NULL DEFAULT 'live'
            );
        """)

        conn.commit()


def save_baseline_session(
    session_id: str,
    created_at: str,
    monitored_directory: str,
    consent_given: bool,
    duration_seconds: float,
    window_count: int,
    event_count: int,
    source_type: str = "real_host",
):
    """Saves a baseline session entry."""
    init_db()
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO baseline_sessions
            (session_id, created_at, monitored_directory, consent_given, duration_seconds, window_count, event_count, source_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                created_at,
                monitored_directory,
                1 if consent_given else 0,
                duration_seconds,
                window_count,
                event_count,
                source_type,
            ),
        )
        conn.commit()


def save_telemetry_windows(session_id: str, windows: List[Dict[str, Any]]):
    """Bulk inserts telemetry feature windows into database."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        for w in windows:
            cursor.execute(
                """
                INSERT INTO telemetry_windows
                (session_id, window_start, window_end, event_count, create_count, modify_count, delete_count,
                 move_rename_count, extension_change_count, file_size_delta_bytes, write_throughput_bytes_per_sec,
                 distinct_files_count, distinct_dirs_count, high_entropy_ratio, decoy_touches_count, top_process_name,
                 is_malicious, stage_tag)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    w.get("window_start", 0.0),
                    w.get("window_end", 0.0),
                    w.get("event_count", 0),
                    w.get("create_count", 0),
                    w.get("modify_count", 0),
                    w.get("delete_count", 0),
                    w.get("move_rename_count", 0),
                    w.get("extension_change_count", 0),
                    w.get("file_size_delta_bytes", 0.0),
                    w.get("write_throughput_bytes_per_sec", 0.0),
                    w.get("distinct_files_count", 0),
                    w.get("distinct_dirs_count", 0),
                    w.get("high_entropy_ratio", 0.0),
                    w.get("decoy_touches_count", 0),
                    w.get("top_process_name", "unknown"),
                    1 if w.get("is_malicious", False) else 0,
                    w.get("stage_tag", "normal"),
                ),
            )
        conn.commit()


def get_all_baseline_windows() -> List[Dict[str, Any]]:
    """Retrieves all baseline telemetry feature windows sorted by timestamp."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM telemetry_windows
            ORDER BY window_start ASC
        """)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]


def get_baseline_sessions() -> List[Dict[str, Any]]:
    """Retrieves all baseline session records."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM baseline_sessions ORDER BY created_at DESC")
        return [dict(r) for r in cursor.fetchall()]


def delete_all_baselines() -> Dict[str, int]:
    """
    Confirmed deletion of all baseline sessions, feature windows, ML models,
    and evaluation results. Preserves non-baseline application state.
    """
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM baseline_sessions")
        session_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM telemetry_windows")
        window_count = cursor.fetchone()[0]

        cursor.execute("DELETE FROM telemetry_windows")
        cursor.execute("DELETE FROM baseline_sessions")
        cursor.execute("DELETE FROM ml_models")
        cursor.execute("DELETE FROM evaluation_results")
        cursor.execute("DELETE FROM live_alerts")
        conn.commit()

        return {
            "sessions_deleted": session_count,
            "windows_deleted": window_count,
        }
