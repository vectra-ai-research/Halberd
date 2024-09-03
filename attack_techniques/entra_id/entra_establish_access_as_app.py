from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.entra_token_manager import EntraTokenManager
import msal 

@TechniqueRegistry.register
class EntraEstablishAccessAsApp(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1078.004",
                technique_name="Valid Accounts",
                tactics=["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
                sub_technique_name="Cloud Accounts"
            )
        ]
        super().__init__("Establish Access As App", "Establishes app-only access to Entra ID", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        try:
            client_id: str = kwargs["client_id"]
            client_secret: str = kwargs["client_secret"]
            tenant_id: str = kwargs["tenant_id"]
            save_token: bool = kwargs.get('save_token', True)
            set_as_active_token: str = kwargs.get('set_as_active_token', False)

            if client_id in [None, ""] or client_secret in [None, ""] or tenant_id in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Invalid Technique Input"
                }

            if save_token in [None, ""]:
                save_token = True # default to True

            if set_as_active_token in [None, ""] :
                set_as_active_token = False # default to False

            client = msal.ConfidentialClientApplication(client_id, authority=f"https://login.microsoftonline.com/{tenant_id}", client_credential=client_secret)

            raw_response = client.acquire_token_for_client(scopes=['https://graph.microsoft.com/.default'])

            if 'access_token' in raw_response:
                access_token = raw_response['access_token']
                # save token
                if save_token:
                    EntraTokenManager().add_token(access_token)
                    if set_as_active_token:
                        # set as active token to use
                        EntraTokenManager().set_active_token(access_token)
            
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully authenticated as app",
                    "value": {
                        "access_token" : access_token,
                        "expires_in" : raw_response.get('expires_in', 'N/A'),
                        "is_token_saved" : save_token
                    }
                }
            else:
                return ExecutionStatus.FAILURE, {
                "error": raw_response.get('error_description', 'N/A'),
                "message": "Failed to authenticate with app credentials"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to authenticate with app credentials"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "client_id": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "Client ID", 
                "input_field_type" : "text"
            },
            "client_secret": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "Client Secret", 
                "input_field_type" : "password"
            },
            "tenant_id": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "Tenant ID", 
                "input_field_type" : "text"
            },
            "save_token": {
                "type": "bool", 
                "required": False, 
                "default":True, 
                "name": "Save Token", 
                "input_field_type" : "bool"
            },
            "set_as_active_token": {
                "type": "bool", 
                "required": True, 
                "default":False, 
                "name": "Set As Active Token?", 
                "input_field_type" : "bool"
            }
        }