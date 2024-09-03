from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSAssumeIAMRole(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1098.003",
                technique_name="Account Manipulation",
                tactics=["Persistence", "Privilege Escalation"],
                sub_technique_name="Additional Cloud Roles"
            )
        ]
        super().__init__("Assume Role", "Generates temporary credentials to access AWS resources", mitre_techniques)
        
    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            role_arn: str = kwargs.get("role_arn", None)
            role_session_name: str = kwargs.get("role_session_name", None)

            if role_arn in [None, ""] or role_session_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }
            
            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sts/client/assume_role.html#

            # Initialize boto3 client
            my_client = boto3.client("sts")

            raw_response = my_client.assume_role(
                RoleArn = role_arn,
                RoleSessionName= role_session_name,
            )

            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully assumed role",
                    "value": {
                        "credentials": raw_response.get("Credentials","N/A"),
                        "assumed_role_user" : raw_response.get("AssumedRoleUser","N/A")
                    }
                }
        
            return ExecutionStatus.FAILURE, {
                    "error": raw_response.get('ResponseMetadata'),
                    "message": "Failed to assume role"
                }
        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to assume role"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to assume role"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "role_arn": {"type": "str", "required": True, "default": None, "name": "Role ARN", "input_field_type" : "text"},
            "role_session_name": {"type": "str", "required": True, "default": None, "name": "Role Session Name", "input_field_type" : "text"}
        }