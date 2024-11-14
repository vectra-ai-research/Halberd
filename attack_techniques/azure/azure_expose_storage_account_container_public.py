from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.storage.blob import BlobServiceClient, PublicAccess
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureExposeStorageAccountContainerPublic(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1562.007",
                technique_name="Impair Defenses",
                tactics=["Defense Evasion"],
                sub_technique_name="Disable or Modify Cloud Firewall"
            )
        ]
        super().__init__("Expose Storage Account Container Public", "Modifies access controls on Azure Storage Account containers to enable anonymous public access. The technique can set container access level to either 'blob' (allowing public read access to blob data) or 'container' (allowing public read and list access to entire containers). This intentional exposure of private data makes container contents publicly accessible over the internet without authentication. This technique is particularly impactful as storage containers often hold sensitive business data, backups, and application files.", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            storage_account_name: str = kwargs["storage_account_name"]
            container_name: str = kwargs["container_name"]
            access_level: str = kwargs.get("access_level","Blob")

            # Input Validation
            if storage_account_name in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required": "Storage Account Name"}
                }
            
            if container_name in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required": "Container Name"}
                }
                
            if access_level in ["",None]:
                access_level = "Blob" # Set default

            # Acces level (Blob or Container)
            if access_level.upper() not in ["BLOB", "CONTAINER"]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"invalid_value": "Access Level"}
                }

            # Get credential
            credential = AzureAccess.get_azure_auth_credential()
            
            # Create blob service client
            account_url = f"https://{storage_account_name}.blob.core.windows.net"
            blob_service_client = BlobServiceClient(account_url = account_url, credential=credential, connection_verify=False)

            # Create container client
            container_client = blob_service_client.get_container_client(container_name)

            # Modify container to enable public access
            if access_level.upper() == "BLOB":
                container_client.set_container_access_policy(signed_identifiers={}, public_access=PublicAccess.BLOB)
            else:
                container_client.set_container_access_policy(signed_identifiers={}, public_access=PublicAccess.CONTAINER)

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully set container {container_name} access level to - {access_level.upper()}",
                "value": {
                    "storage_account_name" : storage_account_name,
                    "container_name" : container_name,
                    "access_level" : access_level.upper(),
                    "public_access" : True
                }
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": f"Failed to set container {container_name} access level to - {access_level.upper()}"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "storage_account_name": {"type": "str", "required": True, "default": None, "name": "Storage Account Name", "input_field_type" : "text"},
            "container_name": {"type": "str", "required": True, "default": None, "name": "Container Name", "input_field_type" : "text"},
            "access_level": {"type": "str", "required": False, "default": "Blob", "name": "Access Level", "input_field_type" : "text"},
        }