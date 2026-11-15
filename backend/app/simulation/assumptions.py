"""
NitiQ - Simulation Assumptions & Default Parameters
All constants and assumptions are exposed here and can be overridden by users/what-if scenarios.
"""

from pydantic import BaseModel, Field


class SimulationAssumptions(BaseModel):
    # Time and hop delays (in minutes)
    step_duration_minutes: float = Field(
        default=15.0,
        description="Duration of each discrete simulation time-step in minutes",
    )
    hop_delay_same_segment_minutes: float = Field(
        default=10.0,
        description="Average hop time between nodes in the same network segment",
    )
    hop_delay_cross_segment_minutes: float = Field(
        default=30.0,
        description="Hop time between un-isolated cross-segment nodes",
    )
    hop_delay_firewalled_segment_minutes: float = Field(
        default=90.0,
        description="Traversal delay across strictly firewalled segment boundaries",
    )
    hop_delay_mfa_penalty_minutes: float = Field(
        default=180.0,
        description="Delay added when encountering an account protected by MFA (or blocked)",
    )
    hop_delay_edr_penalty_minutes: float = Field(
        default=45.0,
        description="Delay imposed by active host EDR telemetry and sensor friction",
    )
    hop_delay_privilege_escalation_minutes: float = Field(
        default=40.0,
        description="Delay required to elevate privileges when local admin rights are restricted",
    )

    # Encryption performance
    encryption_throughput_mb_s: float = Field(
        default=25.0,
        description="Simulated ransomware file encryption throughput in MB/s per active thread",
    )

    # Detection proxy thresholds
    edr_detection_sensitivity: float = Field(
        default=0.85,
        description="Probability or coverage multiplier for EDR alert generation",
    )
    soc_alert_delay_hours: float = Field(
        default=4.0,
        description="Baseline delay before security operations reviews and triages alerts without 24/7 coverage",
    )
    soc_24_7_alert_delay_hours: float = Field(
        default=0.5,
        description="Delay before triage when 24/7 SOC monitoring is active",
    )

    # Model boundaries
    max_simulation_steps: int = Field(
        default=60,
        description="Maximum discrete steps before terminating simulation run",
    )


DEFAULT_ASSUMPTIONS = SimulationAssumptions()
