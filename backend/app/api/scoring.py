"""
NitiQ - NIST CSF Maturity Scoring API Router
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from backend.app.models.organization import OrganizationProfile
from backend.app.models.scoring import MaturityScoreResponse
from backend.app.scoring.nist_csf import evaluate_maturity_score
from backend.app.data.loader import load_profile_by_id

router = APIRouter(prefix="/scoring", tags=["Scoring"])


class ScoringRequest(BaseModel):
    profile_id: Optional[str] = Field(default="weak_org", description="Organization profile ID")
    custom_profile: Optional[OrganizationProfile] = Field(default=None, description="Optional custom profile")


@router.post("/evaluate", response_model=MaturityScoreResponse)
def evaluate_scoring(request: ScoringRequest):
    """
    Evaluates defensive maturity across Identify, Protect, Detect, Respond, and Recover.
    Returns 0-100 overall score, 5 maturity levels, and transparent control itemization.
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
        return evaluate_maturity_score(profile)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scoring evaluation error: {str(e)}",
        )
