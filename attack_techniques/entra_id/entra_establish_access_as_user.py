from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.entra_token_manager import EntraTokenManager
import requests

@TechniqueRegistry.register
class EntraEstablishAccessAsUser(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1078.004",
                technique_name="Valid Accounts",
                tactics=["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
                sub_technique_name="Cloud Accounts"
            )
        ]
        super().__init__("Establish Access As User - Delegated Access", "Established delegated access using user credentials (username + password). For non-MFA enabled accounts only.", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            username: str = kwargs.get('username', None)
            password: str = kwargs.get('password', None)
            client_id: str = kwargs.get('client_id', "d3590ed6-52b3-4102-aeff-aad2292ab01c")
            save_token: str = kwargs.get('save_token', True)
            set_as_active_token: str = kwargs.get('set_as_active_token', False)
            
            if username in [None, ""] or password in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Invalid Technique Input"
                }
            
            if client_id in [None, ""]:
                client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c" # default client ID
            
            if save_token in [None, ""]:
                save_token = True # default to True
            
            if set_as_active_token in [None, ""] :
                set_as_active_token = False # default to False

            endpoint_url = "https://login.microsoft.com/common/oauth2/token"
            resource = "https://graph.microsoft.com"
            scope = ['openid']

            headers = {
                "Accept" : "application/json",
                "Content-Type" : "application/x-www-form-urlencoded"
            }

            # Create request payload
            data = {
                "grant_type": "password",
                "password" : password,
                "client_id" : client_id,
                "username" : username,
                "resource" : resource,
                "scope" : ' '.join(scope)
            }

            # request authentication
            raw_response = requests.post(url = endpoint_url, headers = headers, data = data)

            # Create account successfull
            if 200 <= raw_response.status_code < 300:
                token_manager = EntraTokenManager()
                token = raw_response.json()
                access_token = token.get('access_token')
                refresh_token = token.get('refresh_token')
                # save access token
                if save_token:
                    # save token to app
                    token_manager.add_token(access_token=access_token, refresh_token=refresh_token)
                    if set_as_active_token:
                        # set as active token to use
                        token_manager.set_active_token(access_token)
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully established access as {username}",
                    "value": {
                        "username" : username,
                        "access_token" : access_token,
                        "token_saved" : True,
                        "token_active" : set_as_active_token
                    }
                }
            
            # Establish access failed
            else:
                return ExecutionStatus.FAILURE, {
                    "error": {"error_code" : raw_response.json().get('error_codes'), 
                              "error_message" :raw_response.json().get('error'),
                              "error_detail" : raw_response.json().get('error_description')
                              },
                    "message": "Failed to establish access as user"
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to establish access as user"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "username": {"type": "str", "required": True, "default":None, "name": "Username", "input_field_type" : "text"},
            "password": {"type": "str", "required": True, "default":None, "name": "Password", "input_field_type" : "password"},
            "client_id": {"type": "str", "required": False, "default":"d3590ed6-52b3-4102-aeff-aad2292ab01c", "name": "Client ID", "input_field_type" : "text"},
            "save_token": {"type": "bool", "required": False, "default":True, "name": "Save Token to App?", "input_field_type" : "bool"},
            "set_as_active_token": {"type": "bool", "required": False, "default":False, "name": "Set As Active Token?", "input_field_type" : "bool"}
        }