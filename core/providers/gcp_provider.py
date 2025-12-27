"""
GCP credential provider implementation.
"""

from typing import List, Optional
from .base_provider import BaseCredentialProvider
from ..credential_types import CredentialData
from ..gcp.gcp_access import GCPAccess


class GCPCredentialProvider(BaseCredentialProvider):
    """GCP credential provider."""
    
    @property
    def provider_name(self) -> str:
        return "gcp"
    
    def get_credentials(self) -> List[CredentialData]:
        """Get all GCP credentials."""
        try:
            gcp_access = GCPAccess()
            raw_credentials = gcp_access.list_credentials()
            credentials = []
            
            for cred in raw_credentials:
                credential_data, is_expired, is_active = self.classify_credential(cred)
                if credential_data:
                    credentials.append(credential_data)
            
            return credentials
        except Exception:
            return []
    
    def classify_credential(self, credential_data: dict) -> tuple:
        """Classify GCP credential."""
        try:
            cred_data = CredentialData(
                id=credential_data['name'],
                name=credential_data['name'],
                detail='GCP Service Account',
                is_active=credential_data.get('current', False),
                is_expired=False,
                provider=self.provider_name,
                raw_data=credential_data
            )
            
            return cred_data, False, credential_data.get('current', False)
        except Exception:
            return None, None, None
    
    def delete_credential(self, credential_id: str, credential_data: Optional[CredentialData] = None) -> str:
        """Delete a GCP credential."""
        try:
            gcp_access = GCPAccess()
            gcp_access.delete_credential_by_name(credential_id)
            return f"GCP credential '{credential_id}' deleted successfully!"
        except ValueError as e:
            return f"GCP credential '{credential_id}' not found"
        except Exception as e:
            return f"Failed to delete GCP credential: {str(e)}"
    
    def set_active_credential(self, credential_data: CredentialData) -> str:
        """Set a GCP credential as active."""
        try:
            gcp_access = GCPAccess()
            gcp_access.set_activate_credentials(credential_data.id)
            return f"GCP credential '{credential_data.name}' set as active successfully!"
        except Exception as e:
            return f"Failed to set active GCP credential: {str(e)}"