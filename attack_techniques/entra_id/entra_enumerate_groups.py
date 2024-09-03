from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraEnumerateGroups(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1069.003",
                technique_name="Permission Groups Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Groups"
            )
        ]
        super().__init__("Enumerate Groups", "Enumerates groups in Entra ID", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            endpoint_url = "https://graph.microsoft.com/v1.0/groups"
            
            raw_response = GraphRequest().get(url = endpoint_url)

            if 'error' in raw_response:
                return ExecutionStatus.FAILURE, {
                    "error": {"error_code" :raw_response.get('error').get('code'),
                              "error_detail" : raw_response.get('error').get('message')
                              },
                    "message": "Failed to enumerate groups in tenant"
                }

            output = []
            if raw_response:
                output = [({
                    'display_name' : application_info.get('displayName', 'N/A'),
                    'id' : application_info.get('id', 'N/A'),
                    'description' : application_info.get('description', 'N/A'),
                    'assignable_role' : application_info.get('isAssignableToRole', 'N/A'),
                    'membership_rule' : application_info.get('membershipRule', 'N/A'),
                    'security_enabled' : application_info.get('securityEnabled', 'N/A'),
                    'visibility' : application_info.get('visibility', 'N/A')
                }) for application_info in raw_response]

                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(output)} groups",
                    "value": output
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": f"No groups found",
                    "value": output
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate groups in tenant"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}