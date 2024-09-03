from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraCreateNewApp(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1098.001",
                technique_name="Account Manipulation",
                tactics=["Persistence", "Privilege Escalation"],
                sub_technique_name="Additional Cloud Credentials"
            )
        ]
        super().__init__("Create New Application", "Create a new application in Entra ID which can allow persistence or privilege escalation", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            new_app_name: str = kwargs.get('new_app_name', None)
            
            if new_app_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Invalid Technique Input"
                }

            endpoint_url = "https://graph.microsoft.com/v1.0/applications"

            # provide new application display name
            data = {
                "displayName": new_app_name
            }

            raw_response = GraphRequest().post(url = endpoint_url, data = data)

            # Create app successfull
            if 200 <= raw_response.status_code < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully created new application {new_app_name} in tenant",
                    "value": {
                        "app_display_name" : new_app_name,
                        "created" : True
                    }
                }
            
            # Create app failed
            else:
                return ExecutionStatus.FAILURE, {
                    "error": {"error_code" : raw_response.json().get('error').get('code', 'N/A'), 
                              "error_message" :raw_response.json().get('error').get('message', 'N/A')
                              },
                    "message": "Failed to create new app in tenant"
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to create new app in tenant"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "new_app_name": {"type": "str", "required": True, "default":None, "name": "New App Name", "input_field_type" : "text"},
        }