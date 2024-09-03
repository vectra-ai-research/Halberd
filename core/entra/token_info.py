import jwt
import datetime
from typing import Optional, Union

class Msft_Token:
    """
    Creates a new MSFT token instance
    """
    def __init__(self, token_value: str):
        self.token_value = token_value
        self.decoded_token = self._decode_token()
        self.app_name = self.decoded_token['app_displayname']
        self.target_tenant = self.decoded_token['tid']
        self.entity_type = self.decoded_token['idtyp']
        self.expiration = self._convert_expiration(self.decoded_token['exp'])
        self.authenticated_entity = self._get_authenticated_entity()
        self.scope = self._get_scope()
        self.access_type = "Delegated" if self.entity_type == "user" else "App-only"

    def _decode_token(self) -> dict:
        """
        Decodes a MSFT JWT
        """
        try:
            return jwt.decode(self.token_value, options={"verify_signature": False})
        except jwt.DecodeError:
            raise ValueError(f"Invalid JWT token: {self.token_value}")

    @staticmethod
    def _convert_expiration(exp_epoch: int) -> str:
        return datetime.datetime.fromtimestamp(exp_epoch, tz=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    def _get_authenticated_entity(self) -> str:
        return self.decoded_token['upn'] if self.entity_type == "user" else self.decoded_token['app_displayname']

    def _get_scope(self) -> Union[str, list]:
        return self.decoded_token['scp'] if self.entity_type == "user" else self.decoded_token['roles']
    
    def _get_access_type(self) -> str:
        return "Delegated" if self.entity_type == "user" else "App-only"

    def get_access_info(self) -> dict:
        """
        :return: Dict with JWT access information
        {
            "Entity": <entity>,
            "Entity Type": <entity_type>,
            "Access Exp": <token-expiration>,
            "Access scope": <access-scope>,
            "Target App Name": <app-name>,
            "Target Tenant": <target-tenant>,
            "Access Type": <access-type>
        }
        """
        return {
            "Entity": self.authenticated_entity,
            "Entity Type": self.entity_type,
            "Access Exp": self.expiration,
            "Access scope": self.scope,
            "Target App Name": self.app_name,
            "Target Tenant": self.target_tenant,
            "Access Type": self.access_type
        }

    @classmethod
    def from_token(cls, token_value: Optional[str] = None) -> 'Msft_Token':
        if token_value is None:
            raise ValueError("Token not found")
        return cls(token_value)