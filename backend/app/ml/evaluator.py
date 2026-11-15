"""
NitiQ - Safe Evaluation Engine
Evaluates fixed threshold detector vs trained IsolationForest model on identical
test datasets (held-out normal baseline + SAFE sandbox emulator attack stages).
Calculates detection rate, false positive rate, precision, recall, F1-score,
confusion matrix, and per-stage TTD.
"""

import json
import uuid
import datetime
from typing import Dict, List, Any, Optional, Tuple

import numpy as np

from backend.app.db.database import get_all_baseline_windows, get_db_connection
from backend.app.ml.trainer import load_model_bundle, FEATURE_COLUMNS
from backend.app.simulation.safe_emulator import SafeSandboxEmulator
from backend.app.telemetry.features import FEATURE_SCHEMA_VERSION


def evaluate_threshold_detector(window: Dict[str, Any]) -> bool:
    """
    Documented fixed threshold rule detector:
    Alerts if extension changes >= 5 OR decoy touches >= 1 OR write throughput >= 50 KB/s.
    """
    ext_changes = window.get("extension_change_count", 0)
    decoy_touches = window.get("decoy_touches_count", 0)
    throughput = window.get("write_throughput_bytes_per_sec", 0.0)

    return ext_changes >= 5 or decoy_touches >= 1 or throughput >= 50000.0


def run_safe_evaluation(model_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Runs comprehensive safe evaluation comparing threshold rule detector vs ML IsolationForest.
    Does NOT execute real attack commands.
    """
    # 1. Load trained ML model bundle
    try:
        model, scaler, model_info = load_model_bundle(model_id)
        calibrated_threshold = model_info["threshold_value"]
    except Exception as e:
        return {
            "status": "error",
            "message": f"Unable to run evaluation: {str(e)}",
            "insufficient_data": True,
        }

    # 2. Get held-out normal windows
    all_normal = [w for w in get_all_baseline_windows() if w.get("stage_tag") == "normal" and not w.get("is_malicious")]
    all_normal.sort(key=lambda x: x["window_start"])

    if len(all_normal) < 10:
        return {
            "status": "error",
            "message": f"Insufficient baseline windows for safe evaluation (found {len(all_normal)}, minimum 10 required).",
            "insufficient_data": True,
        }

    # Reserve last 25% of normal windows as held-out normal evaluation dataset
    heldout_cutoff = int(len(all_normal) * 0.75)
    heldout_normal = all_normal[heldout_cutoff:]

    # 3. Generate SAFE emulator attack stage windows
    emulator = SafeSandboxEmulator()
    emulator_windows = emulator.generate_emulator_telemetry_windows()

    # Combine test dataset
    test_windows = heldout_normal + emulator_windows

    # 4. Evaluate Threshold Detector
    thresh_results = _compute_detector_metrics(test_windows, use_ml=False)

    # 5. Evaluate IsolationForest ML Detector
    ml_results = _compute_detector_metrics(
        test_windows, use_ml=True, model=model, scaler=scaler, threshold=calibrated_threshold
    )

    eval_id = f"eval_{uuid.uuid4().hex[:8]}"
    created_at = datetime.datetime.now().isoformat()

    # Save ML evaluation results to DB
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO evaluation_results
            (eval_id, created_at, model_id, detector_type, test_window_count, heldout_normal_count,
             emulator_window_count, detection_rate, false_positive_rate, precision, recall, f1_score,
             tp, fp, tn, fn, per_stage_json, ttd_hours)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                eval_id,
                created_at,
                model_info["model_id"],
                "isolation_forest",
                len(test_windows),
                len(heldout_normal),
                len(emulator_windows),
                ml_results["detection_rate"],
                ml_results["false_positive_rate"],
                ml_results["precision"],
                ml_results["recall"],
                ml_results["f1_score"],
                ml_results["confusion_matrix"]["tp"],
                ml_results["confusion_matrix"]["fp"],
                ml_results["confusion_matrix"]["tn"],
                ml_results["confusion_matrix"]["fn"],
                json.dumps(ml_results["per_stage"]),
                ml_results["ttd_hours"],
            ),
        )
        conn.commit()

    return {
        "eval_id": eval_id,
        "created_at": created_at,
        "model_id": model_info["model_id"],
        "schema_version": FEATURE_SCHEMA_VERSION,
        "total_test_windows": len(test_windows),
        "heldout_normal_count": len(heldout_normal),
        "emulator_window_count": len(emulator_windows),
        "threshold_detector": thresh_results,
        "isolation_forest_ml": ml_results,
    }


def _compute_detector_metrics(
    windows: List[Dict[str, Any]],
    use_ml: bool = False,
    model: Any = None,
    scaler: Any = None,
    threshold: float = 0.0,
) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    per_stage: Dict[str, Dict[str, Any]] = {}
    first_alert_time: Optional[float] = None
    first_malicious_time: Optional[float] = None

    for w in windows:
        is_malicious = bool(w.get("is_malicious", False))
        stage_tag = w.get("stage_tag", "normal")

        if is_malicious and first_malicious_time is None:
            first_malicious_time = w["window_start"]

        if is_malicious and stage_tag not in per_stage:
            per_stage[stage_tag] = {"detected": False, "alert_time": None}

        # Predict
        if use_ml:
            x_raw = np.array([[w[col] for col in FEATURE_COLUMNS]], dtype=np.float64)
            x_scaled = scaler.transform(x_raw)
            score = model.decision_function(x_scaled)[0]
            is_alert = bool(score < threshold)
        else:
            is_alert = evaluate_threshold_detector(w)

        if is_alert and is_malicious and first_alert_time is None:
            first_alert_time = w["window_start"]

        if is_malicious and is_alert:
            per_stage[stage_tag]["detected"] = True
            if per_stage[stage_tag]["alert_time"] is None:
                per_stage[stage_tag]["alert_time"] = w["window_start"]

        if is_malicious and is_alert:
            tp += 1
        elif not is_malicious and is_alert:
            fp += 1
        elif not is_malicious and not is_alert:
            tn += 1
        elif is_malicious and not is_alert:
            fn += 1

    total_malicious = tp + fn
    total_normal = tn + fp

    detection_rate = round(tp / total_malicious, 4) if total_malicious > 0 else 0.0
    false_positive_rate = round(fp / total_normal, 4) if total_normal > 0 else 0.0
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = detection_rate
    f1_score = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0

    # Calculate TTD in hours
    if first_malicious_time is not None and first_alert_time is not None:
        ttd_seconds = max(0.0, first_alert_time - first_malicious_time)
        ttd_hours = round(ttd_seconds / 3600.0, 4)
    else:
        ttd_hours = 24.0  # Default max latency if missed

    return {
        "detection_rate": detection_rate,
        "false_positive_rate": false_positive_rate,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "per_stage": per_stage,
        "ttd_hours": ttd_hours,
    }
