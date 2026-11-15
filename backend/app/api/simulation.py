"""
NitiQ - Simulation API Router
Endpoints to execute time-stepped ransomware spread simulations and patient-zero rankings.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from backend.app.models.organization import OrganizationProfile
from backend.app.models.simulation import (
    SimulationRunRequest,
    SimulationResult,
    PatientZeroRankingResponse,
)
from backend.app.simulation.assumptions import SimulationAssumptions
from backend.app.simulation.engine import (
    run_simulation,
    evaluate_patient_zero_rankings,
)
from backend.app.data.loader import load_profile_by_id

router = APIRouter(prefix="/simulation", tags=["Simulation"])


class CustomSimulationRequest(BaseModel):
    profile_id: Optional[str] = Field(default="weak_org", description="Profile ID to simulate")
    custom_profile: Optional[OrganizationProfile] = Field(default=None, description="Optional custom organization profile")
    patient_zero_id: str = Field(..., description="ID of patient zero (User or Host)")
    max_hours: float = Field(default=24.0, gt=0, le=168.0)
    assumptions: Optional[SimulationAssumptions] = None


class RankingRequest(BaseModel):
    profile_id: Optional[str] = Field(default="weak_org", description="Profile ID to evaluate")
    custom_profile: Optional[OrganizationProfile] = Field(default=None, description="Optional custom profile")
    max_candidates: Optional[int] = Field(default=None, description="Optional limit for candidate evaluation")
    assumptions: Optional[SimulationAssumptions] = None


@router.post("/run", response_model=SimulationResult)
def execute_simulation(request: CustomSimulationRequest):
    """
    Executes a deterministic, time-stepped ransomware propagation simulation
    from the designated patient zero.
    """
    # 1. Resolve organization profile
    if request.custom_profile:
        profile = request.custom_profile
    else:
        try:
            profile = load_profile_by_id(request.profile_id or "weak_org")
        except FileNotFoundError as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # 2. Run simulation
    try:
        result = run_simulation(
            profile=profile,
            patient_zero_id=request.patient_zero_id,
            assumptions=request.assumptions,
            max_hours=request.max_hours,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Simulation engine error: {str(e)}",
        )


@router.post("/patient-zero-ranking", response_model=PatientZeroRankingResponse)
def get_patient_zero_rankings(request: RankingRequest):
    """
    Evaluates every user and host in the organization as patient zero and ranks
    them by resulting blast radius risk to uncover worst-case breach points.
    """
    if request.custom_profile:
        profile = request.custom_profile
    else:
        try:
            profile = load_profile_by_id(request.profile_id or "weak_org")
        except FileNotFoundError as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    try:
        return evaluate_patient_zero_rankings(
            profile=profile,
            assumptions=request.assumptions,
            max_candidates=request.max_candidates,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Patient-zero ranking failed: {str(e)}",
        )
