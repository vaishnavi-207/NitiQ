"""Guardian API - real-time time-to-loss detection loop."""
import json
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.app.guardian.engine import GUARDIAN, SAVED_DIR

router = APIRouter(prefix="/guardian", tags=["Guardian real-time loop"])


class StartReq(BaseModel):
    monitored_directory: str
    consent_given: bool
    mode: str = Field("guard", pattern="^(guard|learn)$")
    auto_suspend: bool = True


class TrainReq(BaseModel):
    use_baseline: bool = True
    n_normal: int = Field(500, ge=100, le=3000)
    n_attack: int = Field(500, ge=100, le=3000)
    epochs: int = Field(12, ge=2, le=40)


class SandboxReq(BaseModel):
    n_files: int = Field(400, ge=50, le=5000)
    pre_backed_up_fraction: float = Field(0.4, ge=0.0, le=1.0)


class DemoReq(BaseModel):
    style: str = Field("rename", pattern="^(inplace|rename|copy_delete|benign_copy|benign_edit)$")
    rate: float = Field(15.0, ge=1.0, le=300.0)
    delay: float = Field(2.0, ge=0.0, le=30.0)


def _wrap(fn, *a, **k):
    try:
        return fn(*a, **k)
    except (ValueError, FileNotFoundError) as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(409, str(e))


@router.post("/start")
def start(req: StartReq):
    return _wrap(GUARDIAN.start, req.monitored_directory, req.consent_given, req.mode, req.auto_suspend)


@router.post("/stop")
def stop():
    return GUARDIAN.stop()


@router.get("/state")
def state():
    return GUARDIAN.state()


@router.get("/decisions")
def decisions(limit: int = 100, only_actions: bool = False):
    return GUARDIAN.recent_decisions(limit, only_actions)


@router.post("/suspend/confirm")
def confirm():
    return _wrap(GUARDIAN.confirm_suspend)


@router.post("/resume/{pid}")
def resume(pid: int):
    return _wrap(GUARDIAN.resume, pid)


@router.post("/terminate/{pid}")
def terminate(pid: int):
    return _wrap(GUARDIAN.terminate, pid)


@router.post("/train")
def train(req: TrainReq):
    return _wrap(GUARDIAN.start_training, req.use_baseline, req.n_normal, req.n_attack, req.epochs)


@router.get("/train/status")
def train_status():
    return GUARDIAN.train_job


@router.post("/evaluate")
def evaluate():
    from backend.app.guardian.training import evaluate as ev
    try:
        res = ev()
    except FileNotFoundError:
        raise HTTPException(400, "Train the models first.")
    (SAVED_DIR / "eval.json").write_text(json.dumps(res, indent=2))
    return res


@router.get("/evaluation")
def last_evaluation():
    p = SAVED_DIR / "eval.json"
    return json.loads(p.read_text()) if p.exists() else None


@router.post("/demo/sandbox")
def sandbox(req: SandboxReq):
    return _wrap(GUARDIAN.prepare_sandbox, req.n_files, req.pre_backed_up_fraction)


@router.post("/demo/attack")
def demo_attack(req: DemoReq):
    return _wrap(GUARDIAN.demo_attack, req.style, req.rate, req.delay)


@router.post("/demo/stop")
def demo_stop():
    return GUARDIAN.demo_stop()
