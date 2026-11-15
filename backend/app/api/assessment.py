"""
NitiQ - Comprehensive Assessment API Router
Provides an all-in-one assessment endpoint combining simulation, recovery, and maturity scoring.
"""

from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from backend.app.models.organization import OrganizationProfile
from backend.app.models.simulation import SimulationResult, PatientZeroRankingEntry
from backend.app.models.recovery import RecoveryEstimateResponse
from backend.app.models.scoring import MaturityScoreResponse
from backend.app.simulation.engine import (
    run_simulation,
    evaluate_patient_zero_rankings,
)
from backend.app.recovery.calculator import calculate_recovery_time
from backend.app.scoring.nist_csf import evaluate_maturity_score
from backend.app.data.loader import load_profile_by_id

router = APIRouter(prefix="/assessment", tags=["Assessment"])


class AssessmentRequest(BaseModel):
    profile_id: Optional[str] = Field(default="weak_org", description="Organization profile ID")
    custom_profile: Optional[OrganizationProfile] = Field(default=None, description="Optional custom profile")
    patient_zero_id: Optional[str] = Field(default=None, description="Optional specific patient zero")


class HeadlineMetrics(BaseModel):
    blast_radius_composite_pct: float
    time_to_detect_hours: float
    recovery_time_hours: float
    required_rto_hours: float
    rto_gap_hours: float
    rto_status: str
    overall_maturity_score: float
    maturity_tier: str


class AssessmentResponse(BaseModel):
    organization_id: str
    organization_name: str
    industry: str
    headline_metrics: HeadlineMetrics
    worst_case_patient_zero: PatientZeroRankingEntry
    simulation: SimulationResult
    recovery: RecoveryEstimateResponse
    scoring: MaturityScoreResponse


@router.post("", response_model=AssessmentResponse)
def run_comprehensive_assessment(request: AssessmentRequest):
    """
    Executes an end-to-end NitiQ assessment on the specified organization:
    1. Identifies the worst-case entry point (or uses specified patient zero)
    2. Runs deterministic time-stepped ransomware spread model
    3. Calculates recovery time vs RTO and discovers top blockers
    4. Computes NIST CSF maturity breakdown and overall defensive tier
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
        # Determine worst-case patient zero
        rankings = evaluate_patient_zero_rankings(profile)
        worst_case = rankings.worst_case_patient_zero
        target_pz_id = request.patient_zero_id or worst_case.entity_id

        # Run simulation
        sim_res = run_simulation(profile, patient_zero_id=target_pz_id)

        # Run recovery
        rec_res = calculate_recovery_time(
            profile,
            compromised_data_gb=sim_res.blast_radius.encrypted_data_gb,
            compromised_hosts_count=sim_res.blast_radius.compromised_hosts,
            backups_compromised=sim_res.blast_radius.backups_compromised_flag,
        )

        # Run scoring
        mat_res = evaluate_maturity_score(profile)

        # Headline metrics
        headlines = HeadlineMetrics(
            blast_radius_composite_pct=sim_res.blast_radius.composite_blast_radius_pct,
            time_to_detect_hours=sim_res.detection.estimated_ttd_hours,
            recovery_time_hours=rec_res.estimated_recovery_hours,
            required_rto_hours=profile.required_rto_hours,
            rto_gap_hours=rec_res.rto_gap_hours,
            rto_status=rec_res.rto_status,
            overall_maturity_score=mat_res.overall_score,
            maturity_tier=mat_res.maturity_tier,
        )

        return AssessmentResponse(
            organization_id=profile.id,
            organization_name=profile.name,
            industry=profile.industry,
            headline_metrics=headlines,
            worst_case_patient_zero=worst_case,
            simulation=sim_res,
            recovery=rec_res,
            scoring=mat_res,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Comprehensive assessment execution error: {str(e)}",
        )
