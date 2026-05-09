"""
Data structures and types for credential management across all cloud providers.
"""

from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum


class CredentialStatus(Enum):
    """Enumeration of credential statuses."""
    ACTIVE = "active"
    EXPIRED = "expired"
    INACTIVE = "inactive"


@dataclass
class CredentialData:
    """Standardized credential data structure."""
    id: str
    name: str
    detail: str
    is_active: bool
    is_expired: bool
    provider: str
    raw_data: Optional[Dict[str, Any]] = None


@dataclass
class ProviderConfig:
    """Configuration for a credential provider."""
    icon: str
    color: str
    display_name: str


# Provider configurations
PROVIDER_CONFIGS: Dict[str, ProviderConfig] = {
    'entra': ProviderConfig(
        icon='mdi:microsoft',
        color='#0078d4',
        display_name='Entra ID'
    ),
    'aws': ProviderConfig(
        icon='mdi:aws',
        color='#ff9900',
        display_name='AWS'
    ),
    'azure': ProviderConfig(
        icon='mdi:microsoft-azure',
        color='#0078d4',
        display_name='Azure'
    ),
    'gcp': ProviderConfig(
        icon='mdi:google-cloud',
        color='#4285f4',
        display_name='GCP'
    ),
    'm365': ProviderConfig(
        icon='mdi:microsoft-office',
        color='#0078d4',
        display_name='Microsoft 365'
    )
}


# Type aliases for better readability
CredentialList = List[CredentialData]
CredentialTuple = Tuple[CredentialData, str, bool]  # (credential, provider, is_active)
ProviderCredentials = Dict[str, CredentialList]