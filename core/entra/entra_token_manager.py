import yaml
import threading
import time
import datetime
import requests
from typing import Optional, Dict, Tuple, Union
from core.Constants import MSFT_TOKENS_FILE
from core.entra.token_info import Msft_Token
from core.logging.logger import graph_logger

class TokenRefreshError(Exception):
    """Custom exception for token refresh failures"""
    pass

class EntraTokenManager:
    """
    Store, retrieve, set and manage Entra ID authentication tokens.
    Handles both access tokens and their associated refresh tokens with auto-refresh capability.
    """
    MS_TOKEN_REFRESH_ENDPOINT = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    def __init__(self, check_interval: int = 300):  # 5 minutes check default
        self.yaml_file = MSFT_TOKENS_FILE
        self.tokens = self._load_tokens()
        self.active_token = self._get_token_value(self.tokens.get('Current'))
        self.check_interval = check_interval
        
        # Start token refresh monitoring in a separate thread
        self._stop_monitoring = False
        self._monitor_thread = threading.Thread(target=self._token_monitor, daemon=True)

    def __del__(self):
        """Ensure monitoring thread is stopped when object is destroyed"""
        self.stop_token_monitoring()

    def stop_token_monitoring(self):
        """Stop the token monitoring thread"""
        self._stop_monitoring = True
        if hasattr(self, '_monitor_thread') and self._monitor_thread.is_alive():
            self._monitor_thread.join()

    def _token_monitor(self):
        """Background thread that periodically checks token expiration and refreshes as needed"""
        while not self._stop_monitoring:
            try:
                self._check_and_refresh_tokens()
            except Exception as e:
                graph_logger.error(f"Error in token monitor: {str(e)}")
            time.sleep(self.check_interval)

    def _check_and_refresh_tokens(self):
        """Check all tokens for expiration and refresh if needed"""
        current_time = datetime.datetime.now(datetime.timezone.utc)
        tokens_to_refresh = []

        # Collect tokens that need refresh
        for token_entry in self.tokens["AllTokens"]:
            access_token = self._get_token_value(token_entry)
            if not access_token:
                continue

            try:
                token_info = self.decode_jwt_token(access_token)
                expiration = datetime.datetime.strptime(
                    token_info["Access Exp"], 
                    '%Y-%m-%dT%H:%M:%SZ'
                ).replace(tzinfo=datetime.timezone.utc)
                
                # Refresh if token expires in next 10 minutes
                if (expiration - current_time).total_seconds() < 600:  # 10 minutes
                    refresh_token = self._get_refresh_token(token_entry)
                    if refresh_token:
                        tokens_to_refresh.append((access_token, refresh_token, token_info))
                    else:
                        graph_logger.info(f"Token near expiration but no refresh token available: {access_token[:10]}...")
            except Exception as e:
                graph_logger.error(f"Error checking token expiration: {str(e)}")

        # Refresh collected tokens
        for access_token, refresh_token, token_info in tokens_to_refresh:
            try:
                self._refresh_token(access_token, refresh_token, token_info)
            except TokenRefreshError as e:
                graph_logger.error(f"Failed to refresh token: {str(e)}")

    def _refresh_token(self, access_token: str, refresh_token: str, token_info: Dict) -> None:
        """
        Refresh a Microsoft Graph access token using its refresh token
        
        Args:
            access_token: Current access token
            refresh_token: Refresh token to use
            token_info: Decoded token information from Msft_Token
        """
        try:
            tenant_id = token_info["Target Tenant"]
            refresh_endpoint = self.MS_TOKEN_REFRESH_ENDPOINT.format(tenant_id=tenant_id)
            
            # For Microsoft Graph tokens we need to request the same scope
            scopes = " ".join(token_info["Access scope"])
            
            data = {
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'scope': scopes  # Request the same scopes as the original token
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            response = requests.post(refresh_endpoint, data=data, headers=headers)
            
            if response.status_code == 200:
                token_data = response.json()
                new_access_token = token_data.get('access_token')
                new_refresh_token = token_data.get('refresh_token', refresh_token)  # Use old if new not provided
                
                if not new_access_token:
                    raise TokenRefreshError("No access token in refresh response")
                
                # Update token in storage
                self._update_token(access_token, new_access_token, new_refresh_token)
                graph_logger.info(f"Successfully refreshed token: {access_token[:10]}...")
            else:
                error_desc = response.json().get('error_description', 'Unknown error')
                raise TokenRefreshError(f"Token refresh failed: {error_desc}")
                
        except requests.RequestException as e:
            raise TokenRefreshError(f"Failed to refresh token: {str(e)}")
        except Exception as e:
            raise TokenRefreshError(f"Unexpected error refreshing token: {str(e)}")

    def _update_token(self, old_access_token: str, new_access_token: str, new_refresh_token: str):
        """Update a token entry with new access and refresh tokens"""
        # Find and update token in AllTokens
        for i, token_entry in enumerate(self.tokens["AllTokens"]):
            if self._get_token_value(token_entry) == old_access_token:
                self.tokens["AllTokens"][i] = {
                    'access_token': new_access_token,
                    'refresh_token': new_refresh_token
                }
                break
        
        # Update Current if it was the active token
        if self.active_token == old_access_token:
            self.tokens['Current'] = {
                'access_token': new_access_token,
                'refresh_token': new_refresh_token
            }
            self.active_token = new_access_token
        
        self._save_tokens()

    def _get_refresh_token(self, token_entry: Union[str, Dict]) -> Optional[str]:
        """Extract refresh token from token entry"""
        if isinstance(token_entry, dict):
            return token_entry.get('refresh_token')
        return None

    def _get_token_value(self, token_entry: Union[str, Dict, None]) -> Optional[str]:
        """Extract access token value from token entry"""
        if isinstance(token_entry, dict):
            return token_entry.get('access_token')
        return token_entry

    def _load_tokens(self) -> Dict:
        """Load tokens from YAML file with default structure if file not found"""
        try:
            with open(self.yaml_file, 'r') as file:
                tokens = yaml.safe_load(file) or {}
                # Initialize with default structure if empty
                if not tokens:
                    tokens = {
                        'Current': None,
                        'AllTokens': []
                    }
                return tokens
        except FileNotFoundError:
            return {
                'Current': None,
                'AllTokens': []
            }

    def _save_tokens(self):
        """Save tokens to YAML file"""
        with open(self.yaml_file, 'w') as file:
            yaml.dump(self.tokens, file)

    def _get_token_entry(self, token_value: str) -> Optional[Dict]:
        """Get full token entry (including refresh token) from access token value"""
        for token in self.tokens["AllTokens"]:
            if isinstance(token, dict):
                if token.get('access_token') == token_value:
                    return token
            elif token == token_value:  # Handle legacy token format
                return token
        return None

    def add_token(self, access_token: str, refresh_token: Optional[str] = None):
        """
        Stores supplied token to Halberd apps tokens store.
        If refresh token is provided, stores access+refresh token combination.
        
        Args:
            access_token: The access token string
            refresh_token: Optional refresh token string
        """
        token_entry = {
            'access_token': access_token,
            'refresh_token': refresh_token
        } if refresh_token else access_token
        
        self.tokens["AllTokens"].append(token_entry)
        self._save_tokens()

    def set_active_token(self, token_value: str):
        """
        Sets supplied token as active token in app. 
        Active token is used by app as default to make graph requests.
        
        Args:
            token_value: The access token string to set as active
        
        Raises:
            ValueError: If token not found in app
        """
        token_entry = self._get_token_entry(token_value)
        if token_entry:
            self.tokens['Current'] = token_entry
            self.active_token = token_value
            self._save_tokens()
        else:
            raise ValueError("Token not found in app")

    def delete_token(self, token_value: str):
        """
        Deletes token from app token store
        
        Args:
            token_value: The access token string to delete
            
        Raises:
            ValueError: If token not found in app
        """
        token_entry = self._get_token_entry(token_value)
        if token_entry:
            self.tokens["AllTokens"].remove(token_entry)
            if self.active_token == token_value:
                self.active_token = None
                self.tokens['Current'] = None
            self._save_tokens()
        else:
            raise ValueError("Token not found in app")

    def get_all_tokens(self) -> list:
        """
        Returns list of all available access tokens (without refresh tokens)
        """
        return [self._get_token_value(token) for token in self.tokens["AllTokens"]]

    def get_token_pair(self, access_token: str) -> Tuple[str, Optional[str]]:
        """
        Returns the access token and its associated refresh token
        
        Args:
            access_token: The access token string
            
        Returns:
            Tuple of (access_token, refresh_token). refresh_token may be None
            
        Raises:
            ValueError: If token not found in app
        """
        token_entry = self._get_token_entry(access_token)
        if token_entry:
            if isinstance(token_entry, dict):
                return token_entry['access_token'], token_entry.get('refresh_token')
            return token_entry, None
        raise ValueError("Token not found in app")

    def get_active_token(self) -> Optional[str]:
        """
        Returns currently active MSFT access token
        """
        if self.active_token:
            return self.active_token
        return None

    def get_active_token_pair(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Returns currently active access token and its refresh token
        
        Returns:
            Tuple of (access_token, refresh_token). Both may be None
        """
        if not self.active_token:
            return None, None
            
        current = self.tokens.get('Current')
        if isinstance(current, dict):
            return current.get('access_token'), current.get('refresh_token')
        return current, None

    def create_auth_header(self, token_value: Optional[str] = None):
        """
        Returns a MSFT Graph request header
        
        Args:
            token_value: Optional specific access token to use
            
        Returns:
            Dict with authorization header
            
        Raises:
            ValueError: If no token available
        """
        if token_value is None:
            token = self.get_active_token()
        else:
            token = token_value
        
        if token:
            return {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
        else:
            if token_value is None:
                raise ValueError("No active token set")
            else:
                raise ValueError("Token not found")

    def decode_jwt_token(self, token_value: str) -> dict:
        """
        Decodes MSFT JWT and returns token information
        
        Args:
            token_value: The access token to decode
            
        Returns:
            Dict with decoded token information
        """
        access_info = Msft_Token(token_value).get_access_info()
        return access_info