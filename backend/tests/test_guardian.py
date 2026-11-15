"""Tests for the Guardian real-time loop (models, survival maths, policy, live pipeline)."""
import time
import numpy as np
import pytest

from backend.app.guardian.gru import GRUSurvival
from backend.app.guardian.policy import ResponsePolicy
from backend.app.guardian.schema import N_FEATURES, GRU_INPUT_DIM, WINDOW_SECONDS
from backend.app.guardian.simulator import simulate_run
from backend.app.guardian.survival import seconds_remaining, monotone, build_labels


def test_gru_gradients_match_numerical():
    m = GRUSurvival(4, 5, 3, seed=1)
    rng = np.random.default_rng(0)
    X = rng.normal(size=(3, 6, 4)); Y = (rng.random((3, 3)) > .5) * 1.0; M = np.ones((3, 3))
    _, g = m.loss_and_grads(X, Y, M)
    for k in ("Wx", "Uh", "Wo"):
        i = (0, 0)
        o = m.p[k][i]
        m.p[k][i] = o + 1e-5; lp, _ = m.loss_and_grads(X, Y, M)
        m.p[k][i] = o - 1e-5; lm, _ = m.loss_and_grads(X, Y, M)
        m.p[k][i] = o
        assert abs((lp - lm) / 2e-5 - g[k][i]) < 1e-5


def test_gru_shapes():
    m = GRUSurvival(GRU_INPUT_DIM, 64, 3)
    p, h = m.predict(np.zeros((2, WINDOW_SECONDS, GRU_INPUT_DIM)))
    assert p.shape == (2, 3) and h.shape == (2, 64)


def test_survival_seconds_remaining():
    assert seconds_remaining([0.9, 0.95, 0.99]) < 5
    assert seconds_remaining([0.0, 0.1, 0.2]) is None
    assert 5 < seconds_remaining([0.1, 0.6, 0.9]) < 10
    assert list(monotone([0.5, 0.2, 0.9])) == [0.5, 0.5, 0.9]


def test_labels_censoring():
    Y, M = build_labels(50, None)
    assert Y.sum() == 0 and M[-1, 2] == 0 and M[0, 2] == 1
    Y, M = build_labels(50, 20)
    assert Y[19, 0] == 1 and Y[10, 0] == 0 and Y[0, 0] == 0 and Y[0, 2] == 1


def test_simulator_shapes_and_loss():
    rng = np.random.default_rng(3)
    X, lt, meta = simulate_run(rng, "inplace")
    assert X.shape[1] == N_FEATURES
    X, lt, meta = simulate_run(rng, "idle")
    assert lt is None


def test_policy_escalation():
    pol = ResponsePolicy()
    kw = dict(canary_recent=0, unbacked_at_risk=100, has_suspect=True, lost_files=0, backup_rate=100.0)
    assert pol.decide([0, 0, 0.01], None, 0.0, now=1, **kw)["action"] == "WATCH"
    assert pol.decide([0.05, 0.3, 0.5], 12.0, 0.4, now=2, **kw)["action"] == "SHIELD"
    assert pol.decide([0.9, 0.95, 0.99], 2.0, 0.9, now=3, **kw)["action"] == "SUSPEND"
    kw2 = dict(kw, has_suspect=False)
    assert pol.decide([0.9, 0.95, 0.99], 2.0, 0.9, now=4, **kw2)["action"] == "SHIELD"
    # nothing left to back up -> no SHIELD
    kw3 = dict(kw, unbacked_at_risk=0)
    assert ResponsePolicy().decide([0.05, 0.3, 0.5], 12.0, 0.4, now=1, **kw3)["action"] == "WATCH"


def test_benign_canary_touch_does_not_suspend():
    d = ResponsePolicy().decide([0, 0, 0.01], None, 0.5, canary_recent=1, unbacked_at_risk=10,
                                has_suspect=True, lost_files=0, backup_rate=100.0, now=1)
    assert d["action"] == "SHIELD"


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    from backend.app.guardian import training
    training.SAVED_DIR = tmp_path_factory.mktemp("saved")
    import backend.app.guardian.engine as eng
    eng.SAVED_DIR = training.SAVED_DIR
    training.train_all(n_normal=120, n_attack=120, epochs=3, log=lambda s: None)
    return training


def test_live_pipeline_detects_and_suspends(trained, tmp_path, monkeypatch):
    import backend.app.guardian.engine as eng
    monkeypatch.setattr(eng, "SANDBOX_ROOT", tmp_path / "sbx")
    monkeypatch.setattr(eng, "BACKUP_ROOT", tmp_path / "bk")
    g = eng.GuardianEngine()
    g.prepare_sandbox(300, 0.3, path=str(tmp_path / "sbx"))
    g.start(str(tmp_path / "sbx"), True, "guard", True)
    try:
        time.sleep(3)
        g.demo_attack("rename", 60, 0)
        acted = False
        for _ in range(20):
            time.sleep(1)
            if g.state()["latest"].get("action") in ("SHIELD", "SUSPEND"):
                acted = True
                break
        assert acted
        assert g.state()["backup_coverage"] > 0.3 or g.state()["suspended"]
    finally:
        g.demo_stop(); g.stop()
        for pid in list(g.suspended):
            try:
                g.terminate(pid)
            except Exception:
                pass


def test_emulator_refuses_non_sandbox(tmp_path):
    import subprocess, sys
    r = subprocess.run([sys.executable, "-m", "backend.app.guardian.attack_emulator", "--dir", str(tmp_path)],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "Refusing" in (r.stderr + r.stdout)
