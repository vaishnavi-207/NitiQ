"""
NitiQ - What-If & Remediation Ranking API Router
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from backend.app.models.organization import OrganizationProfile
from backend.app.models.whatif import (
    RemediationControls,
    WhatIfComparisonResponse,
    RemediationRankingResponse,
)
from backend.app.whatif.engine import run_whatif_comparison
from backend.app.whatif.ranking import rank_remediation_candidates
from backend.app.data.loader import load_profile_by_id

router = APIRouter(prefix="/whatif", tags=["What-If"])


class WhatIfRequest(BaseModel):
    profile_id: Optional[str] = Field(default="weak_org", description="Organization profile ID")
    custom_profile: Optional[OrganizationProfile] = Field(default=None, description="Optional custom profile")
    remediations: RemediationControls = Field(default_factory=RemediationControls)
    patient_zero_id: Optional[str] = Field(default=None, description="Optional specific patient zero")


class RankingApiRequest(BaseModel):
    profile_id: Optional[str] = Field(default="weak_org", description="Organization profile ID")
    custom_profile: Optional[OrganizationProfile] = Field(default=None, description="Optional custom profile")
    patient_zero_id: Optional[str] = Field(default=None, description="Optional specific patient zero")


@router.post("/compare", response_model=WhatIfComparisonResponse)
def compare_whatif_scenario(request: WhatIfRequest):
    """
    Applies security remediation overrides without mutating the source organization,
    and returns delta comparisons across all headline metrics and maturity scores.
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
        return run_whatif_comparison(
            profile=profile,
            remediations=request.remediations,
            patient_zero_id=request.patient_zero_id,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"What-If comparison error: {str(e)}",
        )


@router.post("/remediation-ranking", response_model=RemediationRankingResponse)
def get_remediation_rankings(request: RankingApiRequest):
    """
    Ranks individual remediation candidates by composite risk reduction divided by
    implementation effort, documenting formula and assumptions.
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
        return rank_remediation_candidates(
            profile=profile,
            patient_zero_id=request.patient_zero_id,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Remediation ranking error: {str(e)}",
        )
