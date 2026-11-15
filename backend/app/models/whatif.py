"""
NitiQ - What-If and Remediation Ranking Models
"""

from typing import List, Dict, Optional
from pydantic import BaseModel, Field
from backend.app.models.simulation import BlastRadiusMetrics, DetectionMetrics
from backend.app.models.recovery import RecoveryEstimateResponse
from backend.app.models.scoring import MaturityScoreResponse


class RemediationControls(BaseModel):
    enforce_mfa_admin: bool = Field(default=False, description="Enforce MFA on all privileged admin accounts")
    immutable_backups: bool = Field(default=False, description="Enable object lock / immutability on backup repos")
    finance_segmentation: bool = Field(default=False, description="Isolate Finance segment with strict firewalling")
    remove_local_admin: bool = Field(default=False, description="Revoke local administrator rights from client hosts")
    offline_backup_copy: bool = Field(default=False, description="Deploy secondary air-gapped / offline backup repository")
    edr_on_servers: bool = Field(default=False, description="Deploy and activate EDR on 100% of hosts and servers")


class WhatIfComparisonRequest(BaseModel):
    remediations: RemediationControls
    patient_zero_id: Optional[str] = Field(
        default=None,
        description="Optional patient zero ID. If None, worst-case patient zero is used.",
    )


class MetricComparison(BaseModel):
    metric_name: str
    baseline_value: float
    remediated_value: float
    absolute_change: float
    percentage_change: float
    unit: str
    improved: bool
    interpretation: str


class WhatIfComparisonResponse(BaseModel):
    applied_controls: RemediationControls
    patient_zero_evaluated: str

    baseline_blast_radius: BlastRadiusMetrics
    remediated_blast_radius: BlastRadiusMetrics

    baseline_ttd: DetectionMetrics
    remediated_ttd: DetectionMetrics

    baseline_recovery: RecoveryEstimateResponse
    remediated_recovery: RecoveryEstimateResponse

    baseline_maturity: MaturityScoreResponse
    remediated_maturity: MaturityScoreResponse

    comparison_summary: List[MetricComparison]


class RemediationCandidate(BaseModel):
    control_key: str
    name: str
    description: str
    implementation_effort: int = Field(..., description="1 (Easiest) to 5 (Hardest)")
    blast_radius_reduction_pct: float
    recovery_hours_saved: float
    maturity_score_increase: float
    composite_risk_reduction: float
    roi_score: float = Field(..., description="Risk Reduction / Effort ratio")
    rank: int


class RemediationRankingResponse(BaseModel):
    formula_documentation: str
    candidates: List[RemediationCandidate]
