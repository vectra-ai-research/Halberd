from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraEnumerateUsers(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1087.004",
                technique_name="Account Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Account"
            )
        ]
        super().__init__("Enumerate Users", "Enumerates users in Entra ID", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            endpoint_url = "https://graph.microsoft.com/v1.0/users/"
            
            raw_response = GraphRequest().get(url = endpoint_url)

            if 'error' in raw_response:
                return ExecutionStatus.FAILURE, {
                    "error": {"error_code" :raw_response.get('error').get('code'),
                              "error_detail" : raw_response.get('error').get('message')
                              },
                    "message": "Failed to enumerate users in tenant"
                }

            output = []
            if raw_response:
                output = [({
                    'display_name' : user_info.get('displayName', 'N/A'),
                    'upn' : user_info.get('userPrincipalName', 'N/A'),
                    'mail' : user_info.get('mail', 'N/A'),
                    'job_title' : user_info.get('jobTitle', 'N/A'),
                    'mobile_phone' : user_info.get('mobilePhone', 'N/A'),
                    'office_ocation' : user_info.get('officeLocation', 'N/A'),
                    'id' : user_info.get('id', 'N/A'),
                }) for user_info in raw_response]

                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(output)} users",
                    "value": output
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": f"No users found",
                    "value": output
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate users in tenant"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}