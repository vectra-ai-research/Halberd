from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.storage import StorageManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureEnumerateStorageAccounts(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1580",
                technique_name="Cloud Infrastructure Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate Storage Accounts", "Performs reconnaissance of Azure Storage accounts across all accessible subscriptions to identify potential data storage targets and security misconfigurations. This technique enumerates all storage accounts and collects critical security information including account names, resource IDs, and public access settings. The discovery of storage accounts is particularly valuable for attackers as these resources often contain sensitive business data, application backups, virtual machine disks, and other critical assets. The technique specifically identifies storage accounts with blob public access enabled, which may indicate security misconfigurations that could be exploited for unauthorized data access. The enumerated information serves as a foundation for other attack techniques like key extraction, public access exploitation, shared access signature (SAS) abuse, or container enumeration. Storage account naming patterns discovered through this technique can also reveal information about associated applications, environments, or organizational structure.", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
    
        try:
            credential = AzureAccess.get_azure_auth_credential()
            # retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # create client
            client = StorageManagementClient(credential, subscription_id)
            
            # list vms
            response = client.storage_accounts.list()

            storage_accounts_list = [{"name":storage_account.name, "id":storage_account.id, "blob_public_access": storage_account.allow_blob_public_access} for storage_account in response]

            if storage_accounts_list:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(storage_accounts_list)} Azure Storage Accounts",
                    "value": storage_accounts_list
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": "No storage accounts found in the subscription",
                    "value": []
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate Azure Storage Accounts"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}