import yaml
from typing import Optional
from core.Constants import MSFT_TOKENS_FILE
from core.entra.token_info import Msft_Token

class EntraTokenManager:
    """
    Store, retrieve, set and manage Entra ID authentication tokens.
    """
    def __init__(self):
        self.yaml_file = MSFT_TOKENS_FILE
        self.tokens = self._load_tokens()
        self.active_token = self.tokens.get('Current')

    def _load_tokens(self):
        try:
            with open(self.yaml_file, 'r') as file:
                return yaml.safe_load(file) or {}
        except FileNotFoundError:
            return {}

    def _save_tokens(self):
        with open(self.yaml_file, 'w') as file:
            yaml.dump(self.tokens, file)

    def add_token(self, token_value : str):
        """
        Stores supplied token to app tokens store
        """
        self.tokens["AllTokens"].append(token_value)
        self._save_tokens()

    def set_active_token(self, token_value : str):
        """
        Sets supplied token as active token in app. Active token is used by app as default to make graph requests. 
        """
        if token_value in self.tokens["AllTokens"]:
            self.tokens['Current'] = token_value
            self.active_token = token_value
            self._save_tokens()
        else:
            raise ValueError(f"Token not found in app")

    def delete_token(self, token_value : str):
        """
        Deletes token from app token store
        """
        # Check token present in tokens list
        if token_value in self.tokens["AllTokens"]:
            # Get token index
            token_index = self.tokens["AllTokens"].index(token_value)
            # Delete token
            del self.tokens["AllTokens"][token_index]
            # Check if token is active token
            if self.active_token == token_value:
                # Set active tokne to none
                self.active_token = None
                self.tokens['Current'] = None
            self._save_tokens()
        else:
            raise ValueError(f"Token not found in app")

    def get_all_tokens(self) -> list:
        """
        Returns list of all available MSFT tokens
        """
        return self.tokens["AllTokens"]

    def get_active_token(self):
        """
        Returns currently active MSFT token
        """
        if self.active_token:
            return self.tokens.get('Current')
        return None

    def create_auth_header(self, token_value : Optional[str] = None):
        """
        Returns a MSFT Graph request header
        """
        if token_value == None:
            token = self.get_active_token() 
        else:
            token = token_value
        
        if token:
            return {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
        
        else:
            if token_value is None:
                raise ValueError("No active token set")
            else:
                raise ValueError(f"Token not found")

    def decode_jwt_token(self, token_value : str) -> dict:
        """
        Decodes MSFT JWT and returns token information
        """
        access_info = Msft_Token(token_value).get_access_info()

        return access_info