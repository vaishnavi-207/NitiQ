"""
NitiQ - Health Check API Endpoint
"""

import time
import platform
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["Health"])

START_TIME = time.time()


class HealthResponse(BaseModel):
    product: str = "NitiQ"
    status: str = "healthy"
    version: str = "1.0.0"
    phase: str = "Phase 1 - Backend & Simulation Engine"
    uptime_seconds: float
    python_version: str
    platform: str


@router.get("/health", response_model=HealthResponse)
def get_health():
    return HealthResponse(
        uptime_seconds=round(time.time() - START_TIME, 2),
        python_version=platform.python_version(),
        platform=platform.platform(),
    )
