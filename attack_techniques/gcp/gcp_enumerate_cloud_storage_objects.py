from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry

from typing import Dict, Any, Tuple, List
from datetime import datetime
import json
import base64
import bisect

from core.gcp.gcp_access import GCPAccess
from google.cloud import storage
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google.auth.transport.requests import Request

@TechniqueRegistry.register
class GCPEnumerateCloudStorageObjects(BaseTechnique):
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
            TechniqueNote(
                "Ensure proper permissions exist in the service account or user credentials (roles/storage.objectViewer or similar)"
            ),
            TechniqueNote(
                "Large buckets with many objects may take longer to enumerate, especially in recursive mode"
            ),
            TechniqueNote(
                "Public buckets may be accessible without authentication but still require valid GCP credentials"
            ),
            TechniqueNote(
                "Consider using folder paths to target specific data when bucket contains large amounts of objects"
            )
        ]

        technique_refs = [
            TechniqueReference(
                "GCP Storage Bucket Enumeration",
                "https://cloud.google.com/storage/docs/listing-objects"
            ),
            TechniqueReference(
                "Storage Object Permissions",
                "https://cloud.google.com/storage/docs/access-control/iam-roles"
            )
        ]

        super().__init__(
            "Enumerate Cloud Storage Objects", 
            ("Performs reconnaissance of Google Cloud Storage buckets to identify potentially sensitive or "
             "exposed data. This technique enumerates objects within target buckets, collecting metadata "
             "like object names, sizes, storage classes, and timestamps. The enumeration can target specific "
             "folders and recursively discover all nested content, making it effective for both broad bucket "
             "assessment and focused data discovery. This technique is particularly valuable during cloud "
             "security assessments as storage buckets often contain sensitive assets like application backups, "
             "configuration files, credentials, and business data."),
            mitre_techniques,
            references=technique_refs,
            notes=technique_notes
        )

    def _list_objects(self, bucket: storage.Bucket, folder_path: str = None, recursive: bool = False, versions: bool = None) -> List[Dict[str, Any]]:
        """Helper function to list objects in bucket with optional folder filtering"""
        objects = []
        
        # If folder path provided, ensure it ends with /
        if folder_path:
            if not folder_path.endswith('/'):
                folder_path += '/'
        
        blobs = bucket.list_blobs(prefix=folder_path, versions=versions)
        
        for blob in blobs:
            # Skip folders themselves in non-recursive mode
            if not recursive and '/' in blob.name[len(folder_path or ''):]:
                continue
                
            # Skip the folder prefix itself
            if folder_path and blob.name == folder_path:
                continue
            
            if any(object.get("name") == blob.name for object in objects) :
                for object in objects :
                    if object.get("name") == blob.name:
                        date_to_compare = []
                        for version in object.get("versions"):
                            updated_date = datetime.fromisoformat(version.get("updated"))
                            date_to_compare.append(updated_date)
                        index = len(object["versions"]) - bisect.bisect_right(date_to_compare, blob.updated)
                        version =  {
                            "updated": blob.updated.isoformat() if blob.updated else None,
                            "revision": blob.generation,
                            'md5_hash': blob.md5_hash
                        }
                        object["versions"].insert(index, version)
            else :
                objects.append({
                    'name': blob.name,
                    'size': blob.size,
                    'content_type': blob.content_type,
                    'created': blob.time_created.isoformat() if blob.time_created else None,
                    'storage_class': blob.storage_class,
                    "versions": [
                        {
                            "updated": blob.updated.isoformat() if blob.updated else None,
                            "revision": blob.generation,
                            'md5_hash': blob.md5_hash
                        }
                    ]
                })


        for object in objects:
            versions = object["versions"]
            version_number = len(versions)
            for index, version in enumerate(versions): 
                version["version_number"] = version_number
                version_number -= 1
            
        return objects

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            bucket_name: str = kwargs.get("bucket_name", None)
            folder_path: str = kwargs.get("folder_path", None)
            recursive: bool = kwargs.get("recursive", False)
            all_version: bool = kwargs.get("all_versions", False)
            
            # Input validation
            if bucket_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required": "Bucket Name"}
                }

            # Get GCP credentials from GCP access manager
            manager = GCPAccess()
            current_access = manager.get_current_access()
            loaded_credential = json.loads(base64.b64decode(current_access["credential"]))
            scopes = [
                "https://www.googleapis.com/auth/devstorage.read_only"
            ]
            request = Request()
            credential = ServiceAccountCredentials.from_service_account_info(loaded_credential, scopes=scopes)
            credential.refresh(request=request)
            
            # Initialize storage client
            storage_client = storage.Client(credentials=credential)
            
            # Get bucket
            try:
                bucket = storage_client.get_bucket(bucket_name)
            except Exception as e:
                return ExecutionStatus.FAILURE, {
                    "error": str(e),
                    "message": f"Failed to access bucket: {bucket_name}"
                }
            
            # List objects based on parameters
            objects = self._list_objects(bucket, folder_path, recursive, all_version)
            
            # Create output statistics
            stats = {
                "total_objects": len(objects),
                "total_size": sum(obj["size"] for obj in objects),
                "folder_path": folder_path if folder_path else "root",
                "recursive": recursive
            }
            
            if objects:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(objects)} objects in bucket '{bucket_name}'",
                    "value": {
                        "bucket_name": bucket_name,
                        "statistics": stats,
                        "objects": objects
                    }
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": f"No objects found in bucket '{bucket_name}'",
                    "value": {
                        "bucket_name": bucket_name,
                        "statistics": stats,
                        "objects": []
                    }
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate bucket objects"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "bucket_name": {
                "type": "str",
                "required": True,
                "default": None,
                "name": "Bucket Name",
                "input_field_type": "text"
            },
            "folder_path": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Folder Path",
                "input_field_type": "text"
            },
            "recursive": {
                "type": "bool",
                "required": False,
                "default": False,
                "name": "Recursive Search",
                "input_field_type": "bool"
            },
            "all_versions": {
                "type": "bool",
                "required": False,
                "default": False,
                "name": "All Versions",
                "input_field_type": "bool"
            },
            
        }