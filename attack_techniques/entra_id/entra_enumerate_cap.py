from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraEnumerateCAP(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1518.001",
                technique_name="Software Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate Conditional Access Policies", "Enumerates conditional access policies in microsoft tenant", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            endpoint_url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            
            raw_response = GraphRequest().get(url = endpoint_url)

            if 'error' in raw_response:
                return ExecutionStatus.FAILURE, {
                    "error": {"error_code" :raw_response.get('error').get('code'),
                              "error_detail" : raw_response.get('error').get('message')
                              },
                    "message": "Failed to enumerate conditional access policies in tenant"
                }

            if raw_response:
                output = [({
                    'display_name' : cap_info.get('displayName', 'N/A'),
                    'id' : cap_info.get('id', 'N/A'),
                    'description' : cap_info.get('description', 'N/A'),
                    'state' : cap_info.get('state', 'N/A'),
                    'conditions' : cap_info.get('conditions', 'N/A'),
                    'grant_controls' : cap_info.get('grantControls', 'N/A'),
                }) for cap_info in raw_response]

                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(output)} conditional access policies",
                    "value": output
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate conditional access policies in tenant"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}