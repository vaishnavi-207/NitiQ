"""
NitiQ - Organization Profile Loader & Validator
Loads synthetic profiles from disk or validates uploaded custom JSON profiles.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional
from backend.app.models.organization import OrganizationProfile


SAMPLE_DATA_DIR = Path("sample_data")
_PROFILES_CACHE: Dict[str, OrganizationProfile] = {}


def get_available_profile_ids() -> List[str]:
    """Returns list of built-in sample profile IDs."""
    return ["weak_org", "average_org", "strong_org"]


def load_profile_by_id(profile_id: str) -> OrganizationProfile:
    """Loads a profile by its ID (weak_org, average_org, strong_org)."""
    # Clean identifier
    pid = profile_id.replace(".json", "")
    if not pid.endswith("_org"):
        pid = f"{pid}_org"

    if pid in _PROFILES_CACHE:
        return _PROFILES_CACHE[pid]

    file_path = SAMPLE_DATA_DIR / f"{pid}.json"
    if not file_path.exists():
        # Try direct match
        file_path = SAMPLE_DATA_DIR / f"{profile_id}.json"
        if not file_path.exists():
            raise FileNotFoundError(
                f"Organization profile '{profile_id}' not found. Available: {get_available_profile_ids()}"
            )

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    profile = OrganizationProfile.model_validate(data)
    _PROFILES_CACHE[pid] = profile
    return profile


def validate_custom_profile(data: dict) -> OrganizationProfile:
    """Validates raw dictionary into an OrganizationProfile or raises helpful validation error."""
    return OrganizationProfile.model_validate(data)
