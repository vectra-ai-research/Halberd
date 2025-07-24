"""
Abstract base class for credential providers.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from ..credential_types import CredentialData


class BaseCredentialProvider(ABC):
    """Abstract base class for all credential providers."""
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name identifier."""
        pass
    
    @abstractmethod
    def get_credentials(self) -> List[CredentialData]:
        """
        Get all credentials for this provider.
        
        Returns:
            List of CredentialData objects
        """
        pass
    
    @abstractmethod
    def delete_credential(self, credential_id: str, credential_data: Optional[CredentialData] = None) -> str:
        """
        Delete a credential.
        
        Args:
            credential_id: The ID of the credential to delete
            credential_data: Optional credential data for additional context
            
        Returns:
            Success/error message
        """
        pass
    
    @abstractmethod
    def set_active_credential(self, credential_data: CredentialData) -> str:
        """
        Set a credential as active.
        
        Args:
            credential_data: The credential to set as active
            
        Returns:
            Success/error message
        """
        pass
    
    @abstractmethod
    def classify_credential(self, credential_data: dict) -> tuple:
        """
        Classify a raw credential as valid or expired.
        
        Args:
            credential_data: Raw credential data from provider
            
        Returns:
            Tuple of (CredentialData, is_expired, is_active)
        """
        pass