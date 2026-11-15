"""
NitiQ - ML Model Trainer Module
Trains scikit-learn IsolationForest strictly on chronological normal baseline windows.
Applies leakage-free temporal splitting, scaler fitting, and decision threshold calibration.
"""

import json
import uuid
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from backend.app.db.database import get_all_baseline_windows, get_db_connection
from backend.app.telemetry.features import FEATURE_SCHEMA_VERSION

SAVED_MODELS_DIR = Path("backend/app/ml/saved_models")

FEATURE_COLUMNS = [
    "create_count",
    "modify_count",
    "delete_count",
    "move_rename_count",
    "extension_change_count",
    "file_size_delta_bytes",
    "write_throughput_bytes_per_sec",
    "distinct_files_count",
    "distinct_dirs_count",
    "high_entropy_ratio",
    "decoy_touches_count",
]


def train_isolation_forest_model(
    sensitivity: float = 3.0,
    random_seed: int = 42,
    train_split_ratio: float = 0.8,
) -> Dict[str, Any]:
    """
    Trains an IsolationForest model on recorded normal baseline windows.
    Enforces strict chronological train/eval splitting to prevent temporal leakage.
    Fits StandardScaler ONLY on the training subset.
    """
    SAVED_MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Fetch all normal baseline windows
    all_windows = get_all_baseline_windows()
    normal_windows = [w for w in all_windows if w.get("stage_tag") == "normal" and not w.get("is_malicious")]

    if len(normal_windows) < 10:
        raise ValueError(
            f"Insufficient baseline telemetry windows for model training (found {len(normal_windows)}, minimum 10 required). "
            "Please record at least 5-10 minutes of normal host baseline telemetry first."
        )

    # 2. Chronological sort by window_start timestamp (strictly NO random shuffling)
    normal_windows.sort(key=lambda x: x["window_start"])

    # 3. Chronological split: reserve early contiguous portion for training fit
    split_index = int(len(normal_windows) * train_split_ratio)
    split_index = max(8, split_index)  # At least 8 samples for training
    train_windows = normal_windows[:split_index]
    heldout_windows = normal_windows[split_index:]

    # Extract feature matrix X_train
    X_train_raw = np.array([[w[col] for col in FEATURE_COLUMNS] for w in train_windows], dtype=np.float64)

    # 4. Fit StandardScaler ONLY on chronological training subset
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_raw)

    # 5. Fit IsolationForest with fixed random seed
    # Contamination mapping based on sensitivity setting (1.0 to 5.0)
    # Sensitivity 1: contamination 0.01 (conservative), Sensitivity 5: contamination 0.10 (sensitive)
    contamination_val = float(np.clip(0.01 + (sensitivity - 1.0) * 0.0225, 0.005, 0.15))

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination_val,
        random_state=random_seed,
    )
    model.fit(X_train_scaled)

    # 6. Threshold calibration on training decision scores
    train_decision_scores = model.decision_function(X_train_scaled)
    # Lower decision_function score indicates higher anomaly severity.
    # Calibrate decision threshold at lower percentile of training scores
    percentile_q = max(0.5, (1.0 - contamination_val) * 100)
    calibrated_threshold = float(np.percentile(train_decision_scores, 100 - percentile_q))

    model_id = f"mod_{uuid.uuid4().hex[:8]}"
    created_at = datetime.datetime.now().isoformat()
    artifact_filename = f"{model_id}.joblib"
    artifact_path = SAVED_MODELS_DIR / artifact_filename

    # 7. Persist model & scaler bundle to controlled backend directory
    model_bundle = {
        "model": model,
        "scaler": scaler,
        "feature_columns": FEATURE_COLUMNS,
        "schema_version": FEATURE_SCHEMA_VERSION,
        "threshold_value": calibrated_threshold,
        "sensitivity": sensitivity,
        "random_seed": random_seed,
    }
    joblib.dump(model_bundle, artifact_path)

    # 8. Save metadata to SQLite
    session_ids = list({w["session_id"] for w in train_windows})
    train_start_time = train_windows[0]["window_start"]
    train_end_time = train_windows[-1]["window_end"]

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO ml_models
            (model_id, created_at, schema_version, feature_names_json, training_row_count,
             training_session_ids_json, training_start_time, training_end_time, random_seed,
             threshold_value, sensitivity, artifact_filename)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                model_id,
                created_at,
                FEATURE_SCHEMA_VERSION,
                json.dumps(FEATURE_COLUMNS),
                len(train_windows),
                json.dumps(session_ids),
                train_start_time,
                train_end_time,
                random_seed,
                calibrated_threshold,
                sensitivity,
                artifact_filename,
            ),
        )
        conn.commit()

    return {
        "model_id": model_id,
        "created_at": created_at,
        "schema_version": FEATURE_SCHEMA_VERSION,
        "training_row_count": len(train_windows),
        "heldout_row_count": len(heldout_windows),
        "total_baseline_windows": len(normal_windows),
        "feature_columns": FEATURE_COLUMNS,
        "threshold_value": calibrated_threshold,
        "sensitivity": sensitivity,
        "random_seed": random_seed,
        "contamination": contamination_val,
        "artifact_filename": artifact_filename,
    }


def load_model_bundle(model_id: Optional[str] = None) -> Tuple[Any, Any, Dict[str, Any]]:
    """
    Loads model and scaler artifact safely from controlled backend directory only.
    Rejects arbitrary joblib loading from user-supplied paths.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if model_id:
            cursor.execute("SELECT * FROM ml_models WHERE model_id = ?", (model_id,))
        else:
            cursor.execute("SELECT * FROM ml_models ORDER BY created_at DESC LIMIT 1")
        row = cursor.fetchone()

    if not row:
        raise FileNotFoundError("No trained ML model found. Please train a model first.")

    model_info = dict(row)
    artifact_path = SAVED_MODELS_DIR / model_info["artifact_filename"]
    if not artifact_path.exists():
        raise FileNotFoundError(f"Model artifact file '{artifact_path}' not found on disk.")

    # Load from controlled local path ONLY
    bundle = joblib.load(artifact_path)
    return bundle["model"], bundle["scaler"], model_info
