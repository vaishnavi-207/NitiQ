"""
NitiQ - Assumptions API Endpoint
Exposes simulation modeling assumptions, throughput rates, and scoring constants.
"""

from fastapi import APIRouter
from backend.app.simulation.assumptions import SimulationAssumptions, DEFAULT_ASSUMPTIONS

router = APIRouter(tags=["Assumptions"])


@router.get("/assumptions", response_model=SimulationAssumptions)
def get_default_assumptions():
    """Returns the default transparent simulation assumptions used across NitiQ engines."""
    return DEFAULT_ASSUMPTIONS
