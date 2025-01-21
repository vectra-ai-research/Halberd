from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry

from typing import Dict, Any, Tuple
import json
import base64

from core.gcp.gcp_access import GCPAccess
from google.cloud import storage
from google.api_core.exceptions import PermissionDenied, Forbidden
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google.auth.transport.requests import Request

storage_class_options = [
    {
        "label": "ANY",
        "value": None
    },
    {
        "label": "STANDARD",
        "value": "STANDARD"
    },
    {
        "label": "NEARLINE",
        "value": "NEARLINE"
    },
    {
        "label": "COLDLINE",
        "value": "COLDLINE"
    },
    {
        "label": "ARCHIVE",
        "value": "ARCHIVE"
    }
]

@TechniqueRegistry.register
class GCPEnumerateCloudStorageBuckets(BaseTechnique):
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
            TechniqueNote("Project filtering requires Storage Admin role on the project level"),
            TechniqueNote("Location filtering uses bucket's geographical placement, not data residency"),
            TechniqueNote("Storage Classes available: STANDARD, NEARLINE, COLDLINE, ARCHIVE"),
            TechniqueNote("Public buckets include both allUsers and allAuthenticatedUsers permission"),
            TechniqueNote("IAM policy checks require additional storage.buckets.getIamPolicy permission"),
            TechniqueNote("Label filtering is case-sensitive and must match exactly")
        ]

        technique_refs = [
            TechniqueReference("Google Cloud Storage Best Practices", "https://cloud.google.com/storage/docs/best-practices"),
            TechniqueReference("GCP Bucket Naming Requirements", "https://cloud.google.com/storage/docs/naming-buckets"),
            TechniqueReference("Cloud Storage Access Control", "https://cloud.google.com/storage/docs/access-control"),
            TechniqueReference("GCP Storage Locations", "https://cloud.google.com/storage/docs/locations"),
            TechniqueReference("Google Cloud Storage Public Access Prevention", "https://cloud.google.com/storage/docs/public-access-prevention"),
        ]

        super().__init__(
            name="Enumerate Cloud Storage Buckets",
            description=("Performs comprehensive storage bucket enumeration across GCP projects. "
            
            "The technique supports targeted enumeration in large environments through multiple filtering options: "
            "1. Project ID: Limit scope to specific projects "
            "2. Location: Target specific geographic regions "
            "3. Labels: Filter by environment, application, or team tags "
            "4. Prefix: Search buckets matching naming patterns "
            "5. Storage Class: Focus on specific storage tiers "
            "6. Public Access: Identify exposure risks"),
            mitre_techniques=mitre_techniques,
            references=technique_refs,
            notes=technique_notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            project_id: str = kwargs.get("project_id", None)
            location: str = kwargs.get("location", None)
            label_key: str = kwargs.get("label_key", None)
            label_value: str = kwargs.get("label_value", None)
            prefix: str = kwargs.get("prefix", None)
            max_results: int = kwargs.get("max_results", None)
            storage_class: str = kwargs.get("storage_class", None)
            only_public: bool = kwargs.get("only_public", False)
            exclude_folders: bool = kwargs.get("exclude_folders", False)

            if storage_class == "ANY":
                storage_class = None 

            # Initialize GCP credentials
            manager = GCPAccess()
            current_access = manager.get_current_access()
            if not current_access:
                return ExecutionStatus.FAILURE, {
                    "error": "No valid GCP credentials found",
                    "message": "Failed to enumerate storage buckets - No valid credentials"
                }
            
            loaded_credential = json.loads(base64.b64decode(current_access["credential"]))
            scopes = [
                "https://www.googleapis.com/auth/devstorage.read_only"
            ]
            request = Request()
            credential = ServiceAccountCredentials.from_service_account_info(loaded_credential, scopes=scopes)
            credential.refresh(request=request)

            # Initialize storage client with project if specified
            if project_id:
                storage_client = storage.Client(project=project_id, credentials=credential)
            else:
                storage_client = storage.Client(credentials=credential)
            
            # List all buckets with filters
            buckets = []
            try:
                # Apply max_results if specified
                if max_results:
                    bucket_iterator = storage_client.list_buckets(max_results=max_results)
                else:
                    bucket_iterator = storage_client.list_buckets()

                # Process each bucket
                for bucket in bucket_iterator:
                    # Apply prefix filter if specified
                    if prefix and not bucket.name.startswith(prefix):
                        continue

                    # Apply location filter if specified
                    if location and bucket.location.lower() != location.lower():
                        continue

                    # Apply storage class filter if specified
                    if storage_class and bucket.storage_class.lower() != storage_class.lower():
                        continue

                    # Apply label filter if specified
                    if label_key and label_value:
                        if not bucket.labels or label_key not in bucket.labels or bucket.labels[label_key] != label_value:
                            continue
                    elif label_key:
                        if not bucket.labels or label_key not in bucket.labels:
                            continue

                    # Skip folder-like buckets if specified
                    if exclude_folders and bucket.name.endswith('/'):
                        continue
                    bucket_info = {
                        "name": bucket.name,
                        "project": bucket.project_number,
                        "created": bucket.time_created.isoformat() if bucket.time_created else None,
                        "updated": bucket.updated.isoformat() if bucket.updated else None,
                        "class": bucket.storage_class,
                        "location": bucket.location,
                        "public_access": {
                            "public_access_prevention": bucket.iam_configuration.get("publicAccessPrevention", "inherited"),
                            "uniform_bucket_level_access": bucket.iam_configuration.get("uniformBucketLevelAccess", {}).get("enabled", False),
                        },
                        "retention_period": bucket.retention_period if hasattr(bucket, 'retention_period') else None,
                        "labels": bucket.labels if bucket.labels else {},
                        "versioning_enabled": bucket.versioning_enabled,
                        "requester_pays": bucket.requester_pays,
                        "url": f"https://storage.cloud.google.com/{bucket.name}",
                        "gsutil_uri": f"gs://{bucket.name}/"
                    }
                    
                    # Check for public IAM policies
                    try:
                        policy = bucket.get_iam_policy()
                        public_roles = []
                        for binding in policy.bindings:
                            if "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]:
                                public_roles.append(binding["role"])
                        bucket_info["public_access"]["public_roles"] = public_roles
                    except (PermissionDenied, Forbidden):
                        bucket_info["public_access"]["public_roles"] = "Access Denied"
                    
                    # Skip non-public buckets if only_public flag is set
                    if only_public:
                        if bucket_info["public_access"]["public_roles"] and bucket_info["public_access"]["public_roles"] != "Access Denied":
                            buckets.append(bucket_info)
                    else:
                        buckets.append(bucket_info)

                if buckets:
                    return ExecutionStatus.SUCCESS, {
                        "message": f"Successfully enumerated {len(buckets)} storage buckets",
                        "value": {
                            "total_buckets": len(buckets),
                            "summary": {
                                "public_buckets": sum(1 for b in buckets if b["public_access"]["public_roles"] and b["public_access"]["public_roles"] != "Access Denied"),
                                "versioned_buckets": sum(1 for b in buckets if b["versioning_enabled"]),
                                "locations": list(set(b["location"] for b in buckets)),
                                "storage_classes": list(set(b["class"] for b in buckets))
                            },
                            "buckets": buckets
                        }
                    }
                else:
                    return ExecutionStatus.SUCCESS, {
                        "message": "No storage buckets found",
                        "value": {
                            "total_buckets": 0,
                            "summary": {
                                "public_buckets": 0,
                                "versioned_buckets": 0,
                                "locations": [],
                                "storage_classes": []
                            },
                            "buckets": []
                        }
                    }

            except PermissionDenied as e:
                return ExecutionStatus.FAILURE, {
                    "error": str(e),
                    "message": "Failed to enumerate storage buckets - Permission denied"
                }
            except Exception as e:
                return ExecutionStatus.FAILURE, {
                    "error": str(e),
                    "message": "Failed to enumerate storage buckets"
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate storage buckets"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "project_id": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Project ID",
                "input_field_type": "text"
            },
            "location": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Location (e.g., US-EAST1)",
                "input_field_type": "text"
            },
            "label_key": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Label Key",
                "input_field_type": "text"
            },
            "label_value": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Label Value",
                "input_field_type": "text"
            },
            "prefix": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Bucket Name Prefix",
                "input_field_type": "text"
            },
            "max_results": {
                "type": "int",
                "required": False,
                "default": None,
                "name": "Maximum Results",
                "input_field_type": "number"
            },
            "storage_class": {
                "type": "str",
                "required": False,
                "default": "ANY",
                "name": "Storage Class",
                "input_field_type": "select",
                "input_list": storage_class_options
            },
            "only_public": {
                "type": "bool",
                "required": False,
                "default": False,
                "name": "Only Show Public Buckets",
                "input_field_type": "bool"
            },
            "exclude_folders": {
                "type": "bool",
                "required": False,
                "default": False,
                "name": "Exclude Folder-like Buckets",
                "input_field_type": "bool"
            }
        }