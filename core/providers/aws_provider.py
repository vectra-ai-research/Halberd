"""
AWS credential provider implementation.
"""

from typing import List, Optional
from .base_provider import BaseCredentialProvider
from ..credential_types import CredentialData
from ..aws.aws_session_manager import SessionManager as AWSSessionManager


class AWSCredentialProvider(BaseCredentialProvider):
    """AWS credential provider."""

    @property
    def provider_name(self) -> str:
        return "aws"

    def get_credentials(self) -> List[CredentialData]:
        """Get all AWS credentials."""
        try:
            sessions = AWSSessionManager.list_sessions()
            credentials = []

            for session in sessions:
                credential_data, is_expired, is_active = self.classify_credential(session)
                if credential_data:
                    credentials.append(credential_data)

            return credentials
        except Exception:
            return []

    def classify_credential(self, credential_data: dict) -> tuple:
        """Classify AWS credential."""
        try:
            active_session = AWSSessionManager.get_active_session()
            is_active = False

            if active_session:
                try:
                    active_details = AWSSessionManager.get_session_details_as_json()
                    session_details = AWSSessionManager.get_session_details_as_json(credential_data['session_name'])
                    is_active = (active_details.get('access_key') == session_details.get('access_key'))
                except Exception:
                    is_active = False

            cred_data = CredentialData(
                id=credential_data['session_name'],
                name=credential_data['session_name'],
                detail=f"Region: {credential_data.get('region', 'N/A')}",
                is_active=is_active,
                is_expired=False,
                provider=self.provider_name,
                raw_data=credential_data
            )

            return cred_data, False, is_active
        except Exception:
            return None, None, None


    def delete_credential(self, credential_id: str, credential_data: Optional[CredentialData] = None) -> str:
        """Delete an AWS credential."""
        try:
            AWSSessionManager.remove_session(credential_id)
            return f"AWS session '{credential_id}' deleted successfully!"
        except (AttributeError, ValueError):
            return f"AWS session '{credential_id}' not found"
        except Exception as e:
            return f"Failed to delete AWS credential: {str(e)}"

    def set_active_credential(self, credential_data: CredentialData) -> str:
        """Set an AWS credential as active."""
        try:
            AWSSessionManager.set_active_session(credential_data.id)
            return f"AWS credential '{credential_data.name}' set as active successfully!"
        except Exception as e:
            return f"Failed to set active AWS credential: {str(e)}"
