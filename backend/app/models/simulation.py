"""
NitiQ - Simulation Request and Response Models
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from backend.app.simulation.assumptions import SimulationAssumptions


class SimulationRunRequest(BaseModel):
    patient_zero_id: str = Field(..., description="Entity ID to initiate simulated attack (User or Host ID)")
    max_hours: Optional[float] = Field(default=24.0, gt=0, le=168.0, description="Max simulated duration in hours")
    assumptions: Optional[SimulationAssumptions] = Field(default=None, description="Optional custom assumptions")


class TimelineStep(BaseModel):
    step_index: int
    elapsed_minutes: float
    newly_compromised: List[str]
    total_compromised_count: int
    compromised_hosts_count: int
    compromised_shares_count: int
    compromised_backups_count: int
    encrypted_data_gb: float
    detection_triggered: bool
    event_description: str


class BlastRadiusMetrics(BaseModel):
    total_hosts: int
    compromised_hosts: int
    host_compromise_pct: float
    total_file_shares: int
    compromised_file_shares: int
    file_share_compromise_pct: float
    total_data_gb: float
    encrypted_data_gb: float
    data_encrypted_pct: float
    total_critical_assets: int
    critical_assets_compromised: int
    critical_asset_compromise_pct: float
    domain_controllers_compromised: int
    domain_admin_reached: bool
    total_backup_repositories: int
    backup_repositories_compromised: int
    backups_compromised_flag: bool
    immutable_backups_survived: bool
    composite_blast_radius_pct: float = Field(
        ...,
        description="Weighted composite score: 35% host, 35% data, 20% critical assets, 10% DC/DA",
    )


class DetectionMetrics(BaseModel):
    estimated_ttd_hours: float
    detection_mechanism: str
    detection_step: Optional[int] = None
    telemetry_coverage_pct: float
    is_model_estimate: bool = True
    estimate_note: str = (
        "Simulated model estimate based on telemetry coverage and alerting delays; "
        "not an observed real-world detector measurement."
    )


class SimulationResult(BaseModel):
    patient_zero_id: str
    patient_zero_name: str
    patient_zero_type: str
    department: str
    total_steps: int
    duration_hours: float
    blast_radius: BlastRadiusMetrics
    detection: DetectionMetrics
    timeline: List[TimelineStep]
    privilege_escalation_path: List[str]
    assumptions_used: SimulationAssumptions


class PatientZeroRankingEntry(BaseModel):
    rank: int
    entity_id: str
    entity_name: str
    entity_type: str
    department: str
    host_compromise_pct: float
    data_encrypted_pct: float
    critical_asset_compromise_pct: float
    domain_admin_reached: bool
    backups_compromised: bool
    estimated_ttd_hours: float
    risk_score: float = Field(..., description="0-100 composite risk score for this entry point")


class PatientZeroRankingResponse(BaseModel):
    worst_case_patient_zero: PatientZeroRankingEntry
    rankings: List[PatientZeroRankingEntry]
    total_evaluated: int
