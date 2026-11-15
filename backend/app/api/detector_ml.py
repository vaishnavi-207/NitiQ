"""
NitiQ - ML Early-Warning Ransomware Detector API Router
Provides endpoints for consented telemetry recording, SQLite baseline storage,
IsolationForest model training, safe sandbox evaluation, live scoring, and alert feeds.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.app.telemetry.recorder import GLOBAL_RECORDER
from backend.app.db.database import (
    get_baseline_sessions,
    get_all_baseline_windows,
    delete_all_baselines,
)
from backend.app.ml.trainer import train_isolation_forest_model, load_model_bundle
from backend.app.ml.evaluator import run_safe_evaluation
from backend.app.ml.live_detector import GLOBAL_LIVE_DETECTOR

router = APIRouter(prefix="/ml", tags=["ML Ransomware Detector"])


class StartBaselineRequest(BaseModel):
    monitored_directory: str = Field(..., description="Target directory path to record telemetry")
    consent_given: bool = Field(..., description="Must explicitly give consent to record file event metadata")


class TrainModelRequest(BaseModel):
    sensitivity: float = Field(default=3.0, ge=1.0, le=5.0, description="Sensitivity slider from 1.0 (conservative) to 5.0 (sensitive)")
    random_seed: int = Field(default=42, description="Documented random seed for reproducibility")


class LiveControlRequest(BaseModel):
    session_id: str = Field(default="live_session", description="Session ID for live detection")
    model_id: Optional[str] = Field(default=None, description="Optional model ID")


@router.post("/baseline/start")
def start_baseline_recording(req: StartBaselineRequest):
    """Starts local baseline telemetry recording on user-consented directory."""
    if not req.consent_given:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Explicit user consent is required before telemetry recording can begin.",
        )
    try:
        res = GLOBAL_RECORDER.start_recording(req.monitored_directory, req.consent_given)
        return res
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/baseline/stop")
def stop_baseline_recording():
    """Stops current baseline telemetry recording session and saves windows to SQLite."""
    try:
        res = GLOBAL_RECORDER.stop_recording()
        return res
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/baseline/status")
def get_baseline_status():
    """Returns real-time status of baseline telemetry recorder."""
    return GLOBAL_RECORDER.get_status()


@router.get("/baseline/stats")
def get_baseline_statistics():
    """Returns overview statistics of recorded baseline sessions and windows."""
    sessions = get_baseline_sessions()
    windows = get_all_baseline_windows()

    total_duration = sum(s.get("duration_seconds", 0.0) for s in sessions)
    total_events = sum(w.get("event_count", 0) for w in windows)

    return {
        "total_sessions": len(sessions),
        "total_windows": len(windows),
        "total_duration_seconds": round(total_duration, 2),
        "total_events": total_events,
        "sessions": sessions,
    }


@router.delete("/baseline")
def confirm_delete_baseline():
    """
    Confirmed deletion of all recorded baseline sessions, telemetry windows,
    trained ML model artifacts, and evaluation results.
    """
    try:
        res = delete_all_baselines()
        return {
            "message": "Successfully deleted all baseline telemetry data and dependent model artifacts.",
            "details": res,
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/train")
def train_model(req: TrainModelRequest):
    """
    Trains scikit-learn IsolationForest model strictly on chronological normal baseline windows.
    Fits StandardScaler on training subset only.
    """
    try:
        res = train_isolation_forest_model(
            sensitivity=req.sensitivity,
            random_seed=req.random_seed,
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/model/info")
def get_model_info(model_id: Optional[str] = None):
    """Retrieves metadata for latest or specified trained model."""
    try:
        _, _, info = load_model_bundle(model_id)
        return info
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/evaluate")
def execute_safe_evaluation(model_id: Optional[str] = None):
    """
    Executes safe evaluation comparing fixed threshold detector vs IsolationForest model
    on held-out normal baseline windows and SAFE emulator attack stages.
    """
    try:
        res = run_safe_evaluation(model_id)
        if res.get("insufficient_data"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=res["message"])
        return res
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/live/start")
def start_live_detector_api(req: LiveControlRequest):
    """Starts live anomaly detector scoring on active stream."""
    try:
        res = GLOBAL_LIVE_DETECTOR.start_live_detector(req.session_id, req.model_id)
        return res
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/live/stop")
def stop_live_detector_api():
    """Stops live anomaly detector."""
    return GLOBAL_LIVE_DETECTOR.stop_live_detector()


@router.get("/live/alerts")
def get_live_alerts_feed(limit: int = Query(default=50, ge=1, le=200)):
    """Retrieves recent live alerts log with heuristic explanations."""
    return GLOBAL_LIVE_DETECTOR.get_live_alerts(limit=limit)
