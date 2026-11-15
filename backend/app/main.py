"""
NitiQ - Defensive Ransomware Readiness Assessment Platform
Phase 1: Backend and Simulation Engine
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.api.health import router as health_router
from backend.app.api.assumptions import router as assumptions_router
from backend.app.api.organizations import router as orgs_router
from backend.app.api.assessment import router as assessment_router
from backend.app.api.simulation import router as simulation_router
from backend.app.api.recovery import router as recovery_router
from backend.app.api.scoring import router as scoring_router
from backend.app.api.whatif import router as whatif_router
from backend.app.api.detector_ml import router as detector_ml_router
from backend.app.api.reports import router as reports_router
from backend.app.api.guardian import router as guardian_router

app = FastAPI(
    title="NitiQ – Real-Time File-Loss Prevention",
    description=(
        "NitiQ monitors file and program activity every second, extracts 20 features, "
        "runs an Isolation Forest anomaly detector and a GRU-based survival model to predict "
        "time remaining before un-backed-up files are permanently lost, then issues one of "
        "three responses: WATCH (safe), SHIELD (back up at-risk files), or SUSPEND (pause "
        "the offending program). All operations are strictly defensive; no file contents are "
        "ever stored."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable CORS for local frontend development (React / Vite)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(health_router, prefix="/api")
app.include_router(assumptions_router, prefix="/api")
app.include_router(orgs_router, prefix="/api")
app.include_router(assessment_router, prefix="/api")
app.include_router(simulation_router, prefix="/api")
app.include_router(recovery_router, prefix="/api")
app.include_router(scoring_router, prefix="/api")
app.include_router(whatif_router, prefix="/api")
app.include_router(detector_ml_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(guardian_router, prefix="/api")


@app.get("/")
def root():
    return {
        "product": "NitiQ",
        "status": "operational",
        "message": "NitiQ Real-Time File-Loss Prevention Engine is running.",
        "documentation": "/docs",
        "guardian": "/api/guardian/state",
    }
