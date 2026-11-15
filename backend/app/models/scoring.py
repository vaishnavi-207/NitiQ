"""
NitiQ - NIST CSF Maturity Scoring Models
"""

from typing import List, Dict
from pydantic import BaseModel, Field


class ControlScoreItem(BaseModel):
    control_id: str
    function: str = Field(..., description="Identify, Protect, Detect, Respond, Recover")
    name: str
    max_points: float
    awarded_points: float
    status: str = Field(..., description="IMPLEMENTED, PARTIAL, NOT_IMPLEMENTED")
    rationale: str


class FunctionScore(BaseModel):
    function: str
    score: float
    max_score: float = 20.0
    percentage: float


class MaturityScoreResponse(BaseModel):
    overall_score: float = Field(..., description="Overall maturity score between 0 and 100")
    maturity_level: int = Field(..., description="1 to 5")
    maturity_tier: str = Field(..., description="Initial, Developing, Defined, Managed, Optimized")
    function_scores: Dict[str, FunctionScore]
    controls_breakdown: List[ControlScoreItem]
