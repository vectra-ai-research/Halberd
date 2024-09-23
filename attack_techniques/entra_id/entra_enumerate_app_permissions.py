from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraEnumerateAppPermissions(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1069.003",
                technique_name="Permission Groups Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Groups"
            )
        ]
        super().__init__("Enumerate Application Permissions", "Enumerates Microsoft Graph application permissions available in tenant", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
            
            endpoint_url = f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '{app_id}'"
            
            raw_response = GraphRequest().get(url = endpoint_url)

            if 'error' in raw_response:
                return ExecutionStatus.FAILURE, {
                    "error": {"error_code" :raw_response.get('error').get('code'),
                              "error_detail" : raw_response.get('error').get('message')
                              },
                    "message": "Failed to enumerate application permissions"
                }

            output = []
            if raw_response:
                # Get Microsoft Graph SP permissions
                output = [role_info for role_info in raw_response[0]['appRoles']]

                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(output)} microsoft graph permissions",
                    "value": output
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": f"No permissions found",
                    "value": output
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate application permissions"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}