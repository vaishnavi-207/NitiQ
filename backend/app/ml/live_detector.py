"""
NitiQ - Live Detector Engine
Monitors real-time feature windows, computes ML anomaly scores,
and emits timestamped alert logs with grounded heuristic explanations.
"""

import uuid
import time
import json
import datetime
import threading
from typing import Dict, List, Optional, Any

import numpy as np

from backend.app.db.database import get_db_connection
from backend.app.ml.trainer import load_model_bundle, FEATURE_COLUMNS
from backend.app.ml.explainability import explain_anomaly_window


class LiveDetectorEngine:
    """Manages real-time live scoring loop on active telemetry stream."""

    def __init__(self):
        self.is_active: bool = False
        self.model_id: Optional[str] = None
        self.model: Any = None
        self.scaler: Any = None
        self.threshold: float = 0.0
        self.alerts_count: int = 0
        self.active_session_id: Optional[str] = None

    def start_live_detector(self, session_id: str, model_id: Optional[str] = None) -> Dict[str, Any]:
        if self.is_active:
            return {"status": "already_active", "session_id": self.active_session_id}

        model, scaler, info = load_model_bundle(model_id)
        self.model = model
        self.scaler = scaler
        self.threshold = info["threshold_value"]
        self.model_id = info["model_id"]
        self.active_session_id = session_id
        self.is_active = True
        self.alerts_count = 0

        return {
            "status": "active",
            "model_id": self.model_id,
            "threshold_value": self.threshold,
            "session_id": self.active_session_id,
            "started_at": datetime.datetime.now().isoformat(),
        }

    def stop_live_detector(self) -> Dict[str, Any]:
        self.is_active = False
        res = {
            "status": "stopped",
            "model_id": self.model_id,
            "alerts_count": self.alerts_count,
            "session_id": self.active_session_id,
        }
        self.active_session_id = None
        return res

    def score_window(self, window: Dict[str, Any]) -> Dict[str, Any]:
        """Scores a single 5-second telemetry window against loaded ML model."""
        if not self.is_active or self.model is None:
            return {"is_anomaly": False, "score": 0.0, "explanations": []}

        x_raw = np.array([[window[col] for col in FEATURE_COLUMNS]], dtype=np.float64)
        x_scaled = self.scaler.transform(x_raw)
        score = float(self.model.decision_function(x_scaled)[0])

        is_anomaly = score < self.threshold
        explanations = []

        if is_anomaly:
            self.alerts_count += 1
            explanations = explain_anomaly_window(window)
            alert_id = f"alt_{uuid.uuid4().hex[:8]}"
            timestamp = window.get("window_end", time.time())

            with get_db_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO live_alerts
                    (alert_id, timestamp, session_id, anomaly_score, threshold_value, explanations_json, stage_tag)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert_id,
                        timestamp,
                        self.active_session_id or "live_stream",
                        score,
                        self.threshold,
                        json.dumps(explanations),
                        window.get("stage_tag", "live"),
                    ),
                )
                conn.commit()

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": score,
            "threshold_value": self.threshold,
            "explanations": explanations,
            "window": window,
        }

    def get_live_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent live alerts from SQLite."""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM live_alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            rows = cursor.fetchall()

        results = []
        for r in rows:
            item = dict(r)
            item["explanations"] = json.loads(item["explanations_json"])
            results.append(item)
        return results


GLOBAL_LIVE_DETECTOR = LiveDetectorEngine()
