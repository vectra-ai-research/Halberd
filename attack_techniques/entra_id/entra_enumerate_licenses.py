from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueReference, TechniqueNote
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraEnumerateLicenses(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1526",
                technique_name="Cloud Service Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        technique_ref = [
            TechniqueReference("Microsoft Licensing Service Plan Reference", "https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference")
        ]
        technique_notes = [
            TechniqueNote("If no target user is specified, the current authenticate user licenses are enumerated.")
        ]
        super().__init__(
            "Enumerate User Licenses", 
            "Enumerate licenses assigned to a user in the tenant. When no specific user is provided, it enumerates licenses for the currently authenticated user. This technique provides insights about assigned licenses and service plans, which is valuable for understanding the potential access scope and available services. License information can reveal enterprise service subscriptions that might be exploitable for lateral movement, data access, or privilege escalation.", 
            mitre_techniques,
            references=technique_ref,
            notes=technique_notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            # Get the optional target user parameter
            target_user = kwargs.get("target_user", None)
            
            # Select endpoint based on whether a target user is specified
            if target_user:
                # For a specific user, we need to look up their ID first
                user_lookup_url = f"https://graph.microsoft.com/v1.0/users?$filter=userPrincipalName eq '{target_user}' or mail eq '{target_user}' or displayName eq '{target_user}'"
                user_response = GraphRequest().get(url=user_lookup_url)
                
                if 'error' in user_response:
                    return ExecutionStatus.FAILURE, {
                        "error": {
                            "error_code": user_response.get('error').get('code', 'N/A'),
                            "error_detail": user_response.get('error').get('message', 'N/A')
                        },
                        "message": f"Failed to find user: {target_user}"
                    }
                
                if not user_response:
                    return ExecutionStatus.FAILURE, {
                        "error": "User not found",
                        "message": f"User '{target_user}' not found in the directory"
                    }
                
                # Get the user ID from the response
                user_id = user_response[0].get('id')
                endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/licenseDetails"
                user_info = user_response[0]
            else:
                # For the authenticated user
                endpoint_url = "https://graph.microsoft.com/v1.0/me/licenseDetails"
                # Also get basic info about the current user
                me_info_url = "https://graph.microsoft.com/v1.0/me?$select=displayName,userPrincipalName,mail,id"
                user_info = GraphRequest().get(url=me_info_url)
                if 'error' in user_info:
                    user_info = {"userPrincipalName": "current user", "displayName": "current user"}
            
            # Make the request for license details
            raw_response = GraphRequest().get(url=endpoint_url)

            # Error handling
            if 'error' in raw_response:
                return ExecutionStatus.FAILURE, {
                    "error": {
                        "error_code": raw_response.get('error').get('code', 'N/A'),
                        "error_detail": raw_response.get('error').get('message', 'N/A')
                    },
                    "message": f"Failed to enumerate licenses for {target_user if target_user else 'current user'}"
                }
            
            # Format license data for the output
            formatted_licenses = []
            
            for license in raw_response:
                # Extract service plans that are enabled (not disabled)
                enabled_services = [
                    service_plan for service_plan in license.get('servicePlans', []) 
                    if service_plan.get('provisioningStatus', '') == 'Success'
                ]
                
                # Get disabled service plans
                disabled_services = [
                    service_plan for service_plan in license.get('servicePlans', []) 
                    if service_plan.get('provisioningStatus', '') != 'Success'
                ]
                
                # Format the license entry
                license_entry = {
                    "license_name": self._get_friendly_license_name(license.get('skuPartNumber', '')),
                    "sku_id": license.get('skuId', 'N/A'),
                    "sku_part_number": license.get('skuPartNumber', 'N/A'),
                    "enabled_service_plans": [
                        {
                            "service_plan_id": service.get('servicePlanId', 'N/A'),
                            "service_plan_name": service.get('servicePlanName', 'N/A'),
                            "provisioning_status": service.get('provisioningStatus', 'N/A')
                        }
                        for service in enabled_services
                    ],
                    "disabled_service_plans": [
                        {
                            "service_plan_id": service.get('servicePlanId', 'N/A'),
                            "service_plan_name": service.get('servicePlanName', 'N/A'),
                            "provisioning_status": service.get('provisioningStatus', 'N/A')
                        }
                        for service in disabled_services
                    ]
                }
                
                formatted_licenses.append(license_entry)
            
            # Add user information to the output
            user_display = user_info.get('displayName', 'N/A')
            user_upn = user_info.get('userPrincipalName', 'N/A')
            
            # Return success with formatted license data
            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully enumerated {len(formatted_licenses)} license(s) for {user_display} ({user_upn})",
                "value": {
                    "user": {
                        "displayName": user_display,
                        "userPrincipalName": user_upn
                    },
                    "licenses": formatted_licenses
                }
            }
        
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": f"Failed to enumerate licenses for {kwargs.get('target_user', 'current user')}"
            }
    
    def _get_friendly_license_name(self, sku_part_number: str) -> str:
        """
        Map license SKU part numbers to friendly names when known
        Ref: https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference
        """
        license_names = {
            "SPE_E3": "Microsoft 365 E3",
            "SPE_E5": "Microsoft 365 E5",
            "INFORMATION_PROTECTION_COMPLIANCE": "Microsoft 365 E5 Compliance",
            "IDENTITY_THREAT_PROTECTION": "Microsoft 365 E5 Security",
            "SPB": "Microsoft 365 Business Premium",
            "O365_BUSINESS_PREMIUM": "Microsoft 365 Business Standard",
            "EXCHANGESTANDARD": "Exchange Online (Plan 1)",
            "EXCHANGEENTERPRISE": "Exchange Online (Plan 2)",
            "MCOMEETADV": "Microsoft Teams Audio Conferencing",
            "TEAMS_COMMERCIAL_TRIAL": "Microsoft Teams Commercial Trial",
            "MCOEV": "Microsoft Teams Phone Standard",
            "MCOSTANDARD": "Skype for Business Online (Plan 2)",
            "SHAREPOINTENTERPRISE": "SharePoint Online (Plan 2)",
            "SHAREPOINTSTANDARD": "SharePoint Online (Plan 1)",
            "POWER_BI_STANDARD": "Power BI Free",
            "POWER_BI_PRO": "Power BI Pro",
            "POWER_BI_PREMIUM_P1": "Power BI Premium P1",
            "POWER_BI_PREMIUM_P2": "Power BI Premium P2",
            "DYN365_ENTERPRISE_PLAN1": "Dynamics 365 Plan 1 Enterprise Edition",
            "AAD_PREMIUM": "Microsoft Entra ID P1",
            "AAD_PREMIUM_P2": "Microsoft Entra ID P2",
            "FLOW_FREE": "Microsoft Power Automate Free",
            "POWERAPPS_VIRAL": "Microsoft Power Apps Plan 2 Trial",
            "M365_F1": "Microsoft 365 F1",
            "DESKLESSPACK": "Office 365 F3",
            "WIN10_PRO_ENT_SUB": "Windows 10/11 Enterprise E3",
            "WIN10_VDA_E3": "Windows 10/11 Enterprise E3",
            "WIN_ENT_E5": "Windows 10/11 Enterprise E5",
            "EMS": "Enterprise Mobility + Security E3",
            "EMSPREMIUM": "Enterprise Mobility + Security E5",
            "ENTERPRISEPREMIUM": "Office 365 E5",
            "ENTERPRISEPACK": "Office 365 E3",
            "STANDARDPACK": "Office 365 E1"
        }
        
        return license_names.get(sku_part_number, sku_part_number)

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target_user": {
                "type": "str", 
                "required": False, 
                "default": None, 
                "name": "Target User (Optional)", 
                "input_field_type": "text"
            }
        }