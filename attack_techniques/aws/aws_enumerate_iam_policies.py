from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSEnumerateIAMPolicies(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1087.004",
                technique_name="Account Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Account"
            )
        ]
        super().__init__("Enumerate IAM Policies", "Enumerates all IAM policies. Optionally, supply scope & path prefix to enumerate specific policies", mitre_techniques)
        

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            scope:str = kwargs.get("scope", None)
            path_prefix:str = kwargs.get("path_prefix", None)

            if scope not in [None, "", 'All', 'AWS', 'Local']:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input : Scope"},
                    "message": {"Error" : "Invalid Technique Input : Scope"}
                }
            
            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_policies.html

            # Initialize boto3 client
            my_client = boto3.client("iam")

            if path_prefix in [None, ""]:
                if scope in [None, ""]:
                    # list policies in aws account
                    raw_response = my_client.list_policies()
                else:
                    # list policies in aws account with specified scope
                    raw_response = my_client.list_policies(
                        Scope = scope
                    )
            else:
                if scope in [None, ""]:
                    # list policies in aws account with specified path prefix
                    raw_response = my_client.list_policies(
                        PathPrefix = path_prefix
                    )
                else:
                    # list policies in aws account with specified path prefix & scope
                    raw_response = my_client.list_policies(
                        PathPrefix = path_prefix,
                        Scope = scope
                    )                

            # Create output
            policies = [policy['PolicyName'] for policy in raw_response['Policies']]

            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(policies)} users" if policies else "No users found",
                    "value": policies
                }
        
            return ExecutionStatus.FAILURE, {
                "error": raw_response.get('ResponseMetadata'),
                "message": "Failed to enumerate IAM policies"
            }
        
        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate IAM policies"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate IAM policies"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "scope": {"type": "str", "required": False, "default": None, "name": "Scope ['All', 'AWS', 'Local']", "input_field_type" : "text"},
            "path_prefix": {"type": "str", "required": False, "default": None, "name": "Role Path Prefix", "input_field_type" : "text"}
        }