"""
NitiQ - Organizations API Router
Handles organization profile listing, retrieval, and schema validation.
"""

from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from backend.app.models.organization import OrganizationProfile
from backend.app.data.loader import (
    get_available_profile_ids,
    load_profile_by_id,
    validate_custom_profile,
)

router = APIRouter(prefix="/organizations", tags=["Organizations"])


class OrganizationSummary(BaseModel):
    id: str
    name: str
    description: str
    industry: str
    users_count: int
    hosts_count: int
    domain_controllers_count: int
    file_shares_count: int
    backup_repositories_count: int
    network_segments_count: int
    edges_count: int
    required_rto_hours: float
    required_rpo_hours: float


class ValidationResponse(BaseModel):
    valid: bool
    message: str
    entity_counts: Dict[str, int]
    profile_id: str


@router.get("", response_model=List[OrganizationSummary])
def list_organizations():
    """Lists all available synthetic organization profiles."""
    results = []
    for pid in get_available_profile_ids():
        try:
            prof = load_profile_by_id(pid)
            results.append(
                OrganizationSummary(
                    id=prof.id,
                    name=prof.name,
                    description=prof.description,
                    industry=prof.industry,
                    users_count=len(prof.users),
                    hosts_count=len(prof.hosts),
                    domain_controllers_count=len(prof.domain_controllers),
                    file_shares_count=len(prof.file_shares),
                    backup_repositories_count=len(prof.backup_repositories),
                    network_segments_count=len(prof.network_segments),
                    edges_count=len(prof.edges),
                    required_rto_hours=prof.required_rto_hours,
                    required_rpo_hours=prof.required_rpo_hours,
                )
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error loading sample profile '{pid}': {str(e)}",
            )
    return results


@router.get("/{profile_id}", response_model=OrganizationProfile)
def get_organization_profile(profile_id: str):
    """Retrieves full profile JSON for a specified organization."""
    try:
        return load_profile_by_id(profile_id)
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse organization profile: {str(e)}",
        )


@router.post("/validate", response_model=ValidationResponse)
def validate_organization(data: Dict[str, Any]):
    """
    Validates a submitted organization JSON against NitiQ strict entity schemas and
    relationship constraints. Returns helpful diagnostic details on errors.
    """
    try:
        prof = validate_custom_profile(data)
        return ValidationResponse(
            valid=True,
            message="Organization schema and relationship edges successfully validated.",
            entity_counts={
                "users": len(prof.users),
                "hosts": len(prof.hosts),
                "domain_controllers": len(prof.domain_controllers),
                "file_shares": len(prof.file_shares),
                "backup_repositories": len(prof.backup_repositories),
                "network_segments": len(prof.network_segments),
                "edges": len(prof.edges),
            },
            profile_id=prof.id,
        )
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail=f"Schema validation error: {str(e)}",
        )
