"""
NitiQ - Recovery Estimation API Router
Calculates deterministic recovery time, RTO gap, and identifies top recovery blockers.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from backend.app.models.organization import OrganizationProfile
from backend.app.models.recovery import RecoveryEstimateResponse
from backend.app.recovery.calculator import calculate_recovery_time
from backend.app.data.loader import load_profile_by_id

router = APIRouter(prefix="/recovery", tags=["Recovery"])


class RecoveryCalculationRequest(BaseModel):
    profile_id: Optional[str] = Field(default="weak_org", description="Organization profile ID")
    custom_profile: Optional[OrganizationProfile] = Field(default=None, description="Optional custom profile")
    compromised_data_gb: Optional[float] = Field(default=None, ge=0)
    compromised_hosts_count: Optional[int] = Field(default=None, ge=0)
    backups_compromised: Optional[bool] = Field(default=None)


@router.post("/estimate", response_model=RecoveryEstimateResponse)
def estimate_recovery(request: RecoveryCalculationRequest):
    """
    Computes recovery duration vs required RTO and generates a detailed step breakdown
    with explicit identification of top architectural blockers.
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
        return calculate_recovery_time(
            profile=profile,
            compromised_data_gb=request.compromised_data_gb,
            compromised_hosts_count=request.compromised_hosts_count,
            backups_compromised=request.backups_compromised,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Recovery calculation error: {str(e)}",
        )
