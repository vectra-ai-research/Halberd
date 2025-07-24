"""
Azure credential provider implementation.
"""

from typing import List, Optional
from .base_provider import BaseCredentialProvider
from ..credential_types import CredentialData
from ..azure.azure_access import AzureAccess


class AzureCredentialProvider(BaseCredentialProvider):
    """Azure credential provider."""
    
    @property
    def provider_name(self) -> str:
        return "azure"
    
    def get_credentials(self) -> List[CredentialData]:
        """Get all Azure credentials."""
        try:
            azure_access = AzureAccess()
            subscription_info = azure_access.get_current_subscription_info()
            
            if subscription_info:
                credential_data, is_expired, is_active = self.classify_credential(subscription_info)
                if credential_data:
                    return [credential_data]
            
            return []
        except Exception:
            return []
    
    def classify_credential(self, credential_data: dict) -> tuple:
        """Classify Azure credential."""
        try:
            cred_data = CredentialData(
                id=credential_data.get('id', 'azure-cli'),
                name=credential_data.get('name', 'Azure CLI'),
                detail=f"Subscription: {credential_data.get('name', 'Unknown')}",
                is_active=True,  # Azure credentials are active when logged in via CLI
                is_expired=False,
                provider=self.provider_name,
                raw_data=credential_data
            )
            
            return cred_data, False, True
        except Exception:
            return None, None, None
    
    def delete_credential(self, credential_id: str, credential_data: Optional[CredentialData] = None) -> str:
        """Delete an Azure credential."""
        try:
            azure_access = AzureAccess()
            azure_access.logout()
            return "Azure credential logged out successfully!"
        except Exception as e:
            return f"Failed to delete Azure credential: {str(e)}"
    
    def set_active_credential(self, credential_data: CredentialData) -> str:
        """Set an Azure credential as active."""
        # Azure credentials are automatically active when logged in via CLI
        return f"Azure credential '{credential_data.name}' is already active"