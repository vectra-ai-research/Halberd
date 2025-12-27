"""
Entra ID credential provider implementation.
"""

import datetime
from typing import List, Optional
from .base_provider import BaseCredentialProvider
from ..credential_types import CredentialData
from ..entra.entra_token_manager import EntraTokenManager


class EntraCredentialProvider(BaseCredentialProvider):
    """Entra ID credential provider."""
    
    @property
    def provider_name(self) -> str:
        return "entra"
    
    def get_credentials(self) -> List[CredentialData]:
        """Get all Entra ID credentials."""
        try:
            manager = EntraTokenManager()
            token_data = manager.tokens
            active_token = manager.get_active_token()
            credentials = []

            for token_entry in token_data.get('AllTokens', []):
                # Extract access token from either string or dict format
                access_token = manager._get_token_value(token_entry)
                if not access_token:
                    continue
                
                credential_data, is_expired, is_active = self.classify_credential(access_token)
                if credential_data:
                    credentials.append(credential_data)
            
            return credentials
        except Exception:
            return []
    
    def classify_credential(self, access_token: str) -> tuple:
        """Classify Entra credential as valid or expired."""
        try:
            credential_id = access_token.split('.')[-1] if '.' in access_token else access_token[-16:]
            
            manager = EntraTokenManager()
            active_token = manager.get_active_token()
            is_active = access_token == active_token
            is_expired = False
            
            # Get token info by decoding the JWT
            try:
                token_info = manager.decode_jwt_token(access_token)
                entity_name = token_info.get('Entity', 'Unknown')
                exp_time_str = token_info.get('Access Exp', '')
                
                if exp_time_str:
                    try:
                        exp_time = datetime.datetime.strptime(exp_time_str, '%Y-%m-%dT%H:%M:%SZ')
                        current_time = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                        is_expired = exp_time < current_time
                    except (ValueError, TypeError):
                        is_expired = False
                        
                detail = f"Expires: {exp_time_str[:16].replace('T', ' ')}" if exp_time_str else ''
            except Exception:
                # If token decoding fails, use minimal info
                entity_name = 'Unknown Token'
                exp_time_str = ''
                detail = 'Unable to decode token'

            cred_data = CredentialData(
                id=credential_id,
                name=entity_name,
                detail=detail,
                is_active=is_active,
                is_expired=is_expired,
                provider=self.provider_name,
                raw_data={
                    'token': access_token,
                    'exp_time': exp_time_str
                }
            )
            
            return cred_data, is_expired, is_active
        except Exception:
            return None, None, None
    
    def delete_credential(self, credential_id: str, credential_data: Optional[CredentialData] = None) -> str:
        """Delete an Entra credential."""
        try:
            manager = EntraTokenManager()
            
            if credential_data and credential_data.raw_data and 'token' in credential_data.raw_data:
                manager.delete_token(credential_data.raw_data['token'])
                return f"Entra token '{credential_data.name}' deleted successfully!"
            else:
                # Find and delete by ID using the actual token storage format
                for token_entry in manager.tokens.get('AllTokens', []):
                    access_token = manager._get_token_value(token_entry)
                    if not access_token:
                        continue
                        
                    expected_id = access_token.split('.')[-1] if '.' in access_token else access_token[-16:]
                    if expected_id == credential_id:
                        # Get entity name from decoded token
                        try:
                            token_info = manager.decode_jwt_token(access_token)
                            entity_name = token_info.get('Entity', 'Unknown')
                        except Exception:
                            entity_name = 'Unknown Token'
                        
                        # Use the manager's delete method instead of manual deletion
                        manager.delete_token(access_token)
                        return f"Entra token '{entity_name}' deleted successfully!"
                        
                return "Entra token not found"
        except Exception as e:
            return f"Failed to delete Entra credential: {str(e)}"
    
    def set_active_credential(self, credential_data: CredentialData) -> str:
        """Set an Entra credential as active."""
        try:
            if not credential_data.raw_data or 'token' not in credential_data.raw_data:
                return "Invalid credential data"
            
            manager = EntraTokenManager()
            manager.set_active_token(credential_data.raw_data['token'])
            return f"Entra credential '{credential_data.name}' set as active successfully!"
        except Exception as e:
            return f"Failed to set active Entra credential: {str(e)}"