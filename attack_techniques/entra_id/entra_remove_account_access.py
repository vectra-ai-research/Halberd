from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraRemoveAccountAccess(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1531",
                technique_name="Account Access Removal",
                tactics=["Impact"],
                sub_technique_name=None
            )
        ]

        super().__init__("Remove Account Access", "Delete an user account in Entra ID to remove their access", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            user_id: str = kwargs.get('user_id', None)
            
            if user_id in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Invalid Technique Input"
                }

            endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
            
            raw_response = GraphRequest().delete(url = endpoint_url)

            # Request successfull
            if 200 <= raw_response.status_code < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully removed account {user_id} access",
                    "value": {
                        "user" : user_id,
                        "user_deleted" : True
                    }
                }
            
            # Request failed
            else:
                return ExecutionStatus.FAILURE, {
                    "error": {"error_code" : raw_response.json().get('error').get('code', 'N/A'), 
                              "error_message" :raw_response.json().get('error').get('message', 'N/A')
                              },
                    "message": "Failed to remove account access"
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to remove account access"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "user_id": {"type": "str", "required": True, "default":None, "name": "Target Account UPN", "input_field_type" : "email"}
        }