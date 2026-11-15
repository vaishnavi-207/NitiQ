"""
NitiQ - Recovery Estimation Request & Response Models
"""

from typing import List, Dict, Optional
from pydantic import BaseModel, Field


class RecoveryStepItem(BaseModel):
    step_name: str
    duration_hours: float
    description: str


class RecoveryEstimateRequest(BaseModel):
    compromised_data_gb: Optional[float] = Field(
        default=None,
        description="Data volume in GB to restore. If None, derived from compromised shares in profile.",
    )
    compromised_hosts_count: Optional[int] = Field(
        default=None,
        description="Number of hosts needing re-imaging/rebuild.",
    )
    backups_compromised: Optional[bool] = Field(
        default=None,
        description="Whether online backups were compromised during the incident.",
    )


class RecoveryEstimateResponse(BaseModel):
    estimated_recovery_hours: float
    required_rto_hours: float
    rto_gap_hours: float
    rto_status: str = Field(..., description="WITHIN_RTO, EXCEEDS_RTO, or CATASTROPHIC_DATA_LOSS")
    is_model_estimate: bool = True
    estimate_disclaimer: str = (
        "Deterministic model estimate based on reported throughput, data volume, and control readiness. "
        "Real incident duration will vary based on forensic scope and unmeasured variables."
    )
    total_data_to_restore_gb: float
    effective_throughput_mb_s: float
    top_blockers: List[str]
    recovery_breakdown: List[RecoveryStepItem]
    backup_status_summary: Dict[str, str]
