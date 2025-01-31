from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient, ContainerClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureEnumerateStorageContainers(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1619",
                technique_name="Cloud Storage Object Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        technique_notes = [
            TechniqueNote("The technique requires Storage Account Contributor or higher role to access the storage account keys"),
            TechniqueNote("Use file type analysis to identify containers with potentially sensitive content (e.g., databases, backups, configuration files)"),
            TechniqueNote("Monitor containers with public access enabled as they may expose data without authentication"),
            TechniqueNote("Large containers with recent modifications could indicate active data stores worth targeting"),
            TechniqueNote("Containers with immutability policies or legal holds may contain business-critical or compliance-related data"),
            TechniqueNote("The technique handles access denied scenarios, allowing identification of containers where additional privileges are needed")
        ]
        technique_refs = [
            TechniqueReference("Security recommendations for Blob storage", "https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations"),
            TechniqueReference("Manage storage account access keys", "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage?tabs=azure-portal")
        ]
        super().__init__(
            name="Enumerate Storage Account Containers", 
            description="This technique performs deep reconnaissance of Azure Storage Account containers by enumerating all containers and analyzing their contents. It leverages the Azure Storage Account access keys to gain administrative access and extract detailed information about each container including access levels, size metrics, file types, and security configurations. This level of insight allows attackers to identify high-value data stores, potential security misconfigurations like public access settings, and containers with sensitive content based on file types or naming patterns.", 
            mitre_techniques=mitre_techniques,
            references=technique_refs,
            notes=technique_notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        def _get_container_stats(container_client: ContainerClient) -> Dict[str, Any]:
            """Get detailed container statistics"""
            try:
                blob_list = list(container_client.list_blobs())
                total_size = sum(blob.size for blob in blob_list)
                return {
                    "blob_count": len(blob_list),
                    "total_size_bytes": total_size,
                    "last_modified_blob": max((blob.last_modified for blob in blob_list), default=None),
                    "file_types": list(set(blob.name.split('.')[-1].lower() for blob in blob_list if '.' in blob.name))
                }
            except Exception:
                return {
                    "blob_count": "Access Denied",
                    "total_size_bytes": "Access Denied",
                    "last_modified_blob": "Access Denied",
                    "file_types": "Access Denied"
                }
            
        try:
            storage_account_name: str = kwargs["storage_account_name"]
            rg_name: str = kwargs["rg_name"]
            
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
            
            # Create storage management client
            storage_client = StorageManagementClient(credential, subscription_id)
            
            # Get storage account keys
            keys = storage_client.storage_accounts.list_keys(rg_name, storage_account_name)
            storage_key = keys.keys[0].value

            # Create blob service client
            account_url = f"https://{storage_account_name}.blob.core.windows.net"
            blob_service_client = BlobServiceClient(
                account_url=account_url, 
                credential=storage_key,
                connection_verify=False
            )
            
            # List all containers and their properties
            containers = []
            container_list = blob_service_client.list_containers(include_metadata=True)
            
            for container in container_list:
                container_info = {
                    "name": container.name,
                    "last_modified": str(container.last_modified),
                    "metadata": container.metadata,
                    "lease_status": container.lease.status,
                    "public_access": container.public_access,
                    "has_immutability_policy": container.has_immutability_policy,
                    "has_legal_hold": container.has_legal_hold,
                }

                try:
                    # Get additional container info
                    container_client = blob_service_client.get_container_client(container.name)
                    container_stat = _get_container_stats(container_client)
                    container_info['stats'] = container_stat
                except Exception as e:
                    pass
                
                # add container to output containers list
                containers.append(container_info)

            if containers:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(containers)} containers in storage account {storage_account_name}",
                    "value": {
                        "containers_found": len(containers),
                        "containers":containers
                    }
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": f"No containers found in storage account {storage_account_name}",
                    "value": []
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate storage account containers"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "storage_account_name": {
                "type": "str", 
                "required": True, 
                "default": None,
                "name": "Storage Account Name",
                "input_field_type": "text"
            },
            "rg_name": {
                "type": "str",
                "required": True,
                "default": None,
                "name": "Resource Group Name", 
                "input_field_type": "text"
            }
        }