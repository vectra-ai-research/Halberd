from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraEnumerateDirectoryRoles(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1069.003",
                technique_name="Permission Groups Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Groups"
            )
        ]
        super().__init__("Enumerate Directory Roles", "Enumerates directory roles in microsoft tenant", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            endpoint_url = "https://graph.microsoft.com/v1.0/directoryRoles"
            
            raw_response = GraphRequest().get(url = endpoint_url)

            if 'error' in raw_response:
                return ExecutionStatus.FAILURE, {
                    "error": {"error_code" :raw_response.get('error').get('code'),
                              "error_detail" : raw_response.get('error').get('message')
                              },
                    "message": "Failed to enumerate directory roles in tenant"
                }

            output = []
            if raw_response:
                output = [({
                    'display_name' : role_info.get('displayName', 'N/A'),
                    'description' : role_info.get('description', 'N/A'),
                    'role_template_id' : role_info.get('roleTemplateId', 'N/A'),
                    'id' : role_info.get('id', 'N/A')
                }) for role_info in raw_response]

                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(output)} directory roles",
                    "value": output
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": f"No directory roles found",
                    "value": output
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate directory roles"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}