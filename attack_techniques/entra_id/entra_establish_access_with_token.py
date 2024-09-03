from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.entra_token_manager import EntraTokenManager

@TechniqueRegistry.register
class EntraEstablishAccessWithToken(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1078.004",
                technique_name="Valid Accounts",
                tactics=["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
                sub_technique_name="Cloud Accounts"
            ),
            MitreTechnique(
                technique_id="T1550.001",
                technique_name="Use Alternate Authentication Material",
                tactics=["Defense Evasion", "Lateral Movement"],
                sub_technique_name="Application Access Token"
            )
        ]
        super().__init__("Establish Access With Token", "Adds access token to app to access target environment and use in future actions", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            access_token: str = kwargs.get('access_token', None)
            set_as_active_token: bool = kwargs.get('set_as_active_token', False)
            
            if access_token in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Invalid Technique Input"
                }
            
            if set_as_active_token in [None, ""]:
                set_as_active_token = False

            try:
                # Decode token information
                token_info = EntraTokenManager().decode_jwt_token(access_token)
            except Exception as e:
                return ExecutionStatus.FAILURE, {
                    "error": str(e),
                    "message": "Failed to decode JWT access token. Check token."
                }
            
            # Add token to app
            EntraTokenManager().add_token(access_token)

            # Set token active if selected
            if set_as_active_token:
                EntraTokenManager.set_active_token(access_token)
            
            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully added access to app",
                "value": {
                    "token_added" : True,
                    "token_active" : set_as_active_token,
                    "token_details" : token_info
                }
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to add token to app"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "access_token": {"type": "str", "required": True, "default":None, "name": "Access Token", "input_field_type" : "text"},
            "set_as_active_token": {"type": "bool", "required": False, "default":False, "name": "Set as Active Token?", "input_field_type" : "bool"},
        }