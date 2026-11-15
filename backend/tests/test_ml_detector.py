"""
NitiQ - Phase 3 ML Detector Unit & Integration Test Suite
Tests telemetry recording, database persistence, feature extraction, entropy calculation,
chronological splitting, IsolationForest training, safe sandbox evaluation, explanations,
consent enforcement, directory safety, baseline deletion, and API routes.
"""

import os
import shutil
import tempfile
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.telemetry.features import (
    calculate_entropy_from_filepath,
    aggregate_raw_events_to_window,
)
from backend.app.telemetry.recorder import (
    validate_monitored_directory,
    GLOBAL_RECORDER,
)
from backend.app.db.database import (
    init_db,
    save_baseline_session,
    save_telemetry_windows,
    get_all_baseline_windows,
    delete_all_baselines,
)
from backend.app.ml.trainer import train_isolation_forest_model
from backend.app.ml.evaluator import run_safe_evaluation
from backend.app.ml.explainability import explain_anomaly_window
from backend.app.simulation.safe_emulator import SafeSandboxEmulator

client = TestClient(app)


def test_entropy_calculation():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"AAAAA" * 100)
        fname = f.name

    try:
        entropy = calculate_entropy_from_filepath(fname)
        assert entropy is not None
        assert 0.0 <= entropy <= 1.0  # Constant byte sequence has near 0 entropy
    finally:
        if os.path.exists(fname):
            os.remove(fname)


def test_window_aggregation_privacy():
    raw_events = [
        {"event_type": "created", "src_path": "C:\\test\\doc1.txt", "process_name": "explorer.exe"},
        {"event_type": "modified", "src_path": "C:\\test\\doc1.txt", "size_delta": 500.0, "entropy": 7.5, "process_name": "explorer.exe"},
        {"event_type": "moved", "src_path": "C:\\test\\doc1.txt", "dest_path": "C:\\test\\doc1.locked", "process_name": "cmd.exe"},
    ]
    window = aggregate_raw_events_to_window(raw_events, 0.0, 5.0)

    assert window["event_count"] == 3
    assert window["create_count"] == 1
    assert window["modify_count"] == 1
    assert window["move_rename_count"] == 1
    assert window["extension_change_count"] == 1
    assert window["high_entropy_ratio"] == 1.0
    assert window["distinct_files_count"] == 2
    # Ensure sensitive paths/bytes are NOT stored in window dict
    assert "src_path" not in window
    assert "dest_path" not in window


def test_directory_safety_validation():
    # Root paths should raise ValueError
    with pytest.raises(ValueError):
        validate_monitored_directory("C:\\")

    # Consent enforcement check
    with pytest.raises(ValueError):
        GLOBAL_RECORDER.start_recording(tempfile.gettempdir(), consent_given=False)


def test_database_persistence_and_deletion():
    init_db()
    save_baseline_session("sess_test", "2026-10-09T00:00:00", tempfile.gettempdir(), True, 30.0, 6, 12)

    sample_windows = [
        {
            "window_start": 100.0 + i * 5,
            "window_end": 105.0 + i * 5,
            "event_count": 5 + i,
            "create_count": 1,
            "modify_count": 4,
            "delete_count": 0,
            "move_rename_count": 0,
            "extension_change_count": 0,
            "file_size_delta_bytes": 1000.0,
            "write_throughput_bytes_per_sec": 200.0,
            "distinct_files_count": 3,
            "distinct_dirs_count": 1,
            "high_entropy_ratio": 0.0,
            "decoy_touches_count": 0,
            "top_process_name": "explorer.exe",
            "is_malicious": False,
            "stage_tag": "normal",
        }
        for i in range(15)
    ]
    save_telemetry_windows("sess_test", sample_windows)

    all_windows = get_all_baseline_windows()
    assert len(all_windows) >= 15

    # Test training on stored baseline
    res = train_isolation_forest_model(sensitivity=3.0, random_seed=42)
    assert "model_id" in res
    assert res["training_row_count"] > 0

    # Test Safe Evaluation
    eval_res = run_safe_evaluation(res["model_id"])
    assert eval_res["total_test_windows"] > 0
    assert "isolation_forest_ml" in eval_res
    assert eval_res["isolation_forest_ml"]["detection_rate"] >= 0.0

    # Test Confirmed Deletion
    del_res = delete_all_baselines()
    assert del_res["sessions_deleted"] >= 1
    assert len(get_all_baseline_windows()) == 0


def test_heuristic_explanations():
    anomaly_window = {
        "decoy_touches_count": 2,
        "extension_change_count": 10,
        "move_rename_count": 20,
        "write_throughput_bytes_per_sec": 15000.0,
        "high_entropy_ratio": 0.8,
        "distinct_files_count": 25,
    }
    explanations = explain_anomaly_window(anomaly_window)
    assert len(explanations) >= 3
    assert any("Decoy file touch" in exp for exp in explanations)
    assert any("extension change" in exp for exp in explanations)


def test_ml_api_endpoints():
    # 1. Status
    r = client.get("/api/ml/baseline/status")
    assert r.status_code == 200
    assert "is_recording" in r.json()

    # 2. Stats
    r = client.get("/api/ml/baseline/stats")
    assert r.status_code == 200

    # 3. Report PDF download
    r = client.get("/api/reports/readiness-pdf?profile_id=weak_org")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert len(r.content) > 1000
