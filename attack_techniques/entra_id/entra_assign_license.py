from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraAssignLicense(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1098",
                technique_name="Account Manipulation",
                tactics=["Persistence", "Privilege Escalation"],
                sub_technique_name=None
            )
        ]

        technique_refs = [
            TechniqueReference("Microsoft Graph API - assignLicense", "https://learn.microsoft.com/en-us/graph/api/user-assignlicense"),
            TechniqueReference("Common Microsoft 365 License SKU IDs", "https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference")
        ]
        
        technique_notes = [
            TechniqueNote("Common SKUs: Office 365 E3 (6fd2c87f-b296-42f0-b197-1e91e994b900), Office 365 E5 (c7df2760-2c81-4ef7-b578-5b5392b571df)"),
            TechniqueNote("Assigning E5 licenses can grant high-privilege features like eDiscovery access")
        ]

        super().__init__(
            "Assign License to User", 
            "Assigns Microsoft licenses to target users, enabling service access and potentially escalating privileges. This technique can upgrade user capabilities by adding specific license SKUs, granting access to additional Microsoft cloud services and potentially higher-privileged functionality. The technique supports disabling specific service plans within a license for more targeted assignments, and can be used both for initial privilege escalation and for expanding access across the Microsoft cloud environment.",
            mitre_techniques,
            references=technique_refs,
            notes=technique_notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            user_id: str = kwargs.get('user_id', None)
            license_sku_id: str = kwargs.get('license_sku_id', None)
            disabled_plans: str = kwargs.get('disabled_plans', None)
            
            # Input validation
            if user_id in [None, ""] or license_sku_id in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "User ID and License SKU ID are required"
                }

            # Format disabled plans if provided
            disabled_service_plans = []
            if disabled_plans:
                # Split disabled plans by comma and strip whitespace
                disabled_service_plans = [plan.strip() for plan in disabled_plans.split(',')]
            
            # Request endpoint
            endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/assignLicense"
            
            # Request payload
            data = {
                "addLicenses": [
                    {
                        "skuId": license_sku_id,
                        "disabledPlans": disabled_service_plans
                    }
                ],
                "removeLicenses": []
            }
            
            # Assign license
            raw_response = GraphRequest().post(url=endpoint_url, data=data)
            
            # Request successful
            if 200 <= raw_response.status_code < 300:
                # Get assigned licenses to return in response
                licenses_endpoint = f"https://graph.microsoft.com/v1.0/users/{user_id}/licenseDetails"
                licenses_response = GraphRequest().get(url=licenses_endpoint)
                
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully assigned license to user {user_id}",
                    "value": {
                        "user_id": user_id,
                        "license_assigned": license_sku_id,
                        "disabled_plans": disabled_service_plans,
                        "all_licenses": licenses_response if not isinstance(licenses_response, dict) or 'error' not in licenses_response else []
                    }
                }
            
            # Request failed
            else:
                return ExecutionStatus.FAILURE, {
                    "error": {
                        "error_code": raw_response.json().get('error').get('code', 'N/A'),
                        "error_message": raw_response.json().get('error').get('message', 'N/A')
                    },
                    "message": "Failed to assign license to user"
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to assign license to user"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "user_id": {
                "type": "str", 
                "required": True, 
                "default": None, 
                "name": "User ID or UPN", 
                "input_field_type": "text"
            },
            "license_sku_id": {
                "type": "str", 
                "required": True, 
                "default": None, 
                "name": "License SKU ID", 
                "input_field_type": "text"
            },
            "disabled_plans": {
                "type": "str", 
                "required": False, 
                "default": None, 
                "name": "Disabled Service Plans (comma-separated)", 
                "input_field_type": "text"
            }
        }