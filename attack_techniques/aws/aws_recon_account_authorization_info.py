from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSReconAccountAuthorizationInfo(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1087.004",
                technique_name="Account Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Account"
            ),
            MitreTechnique(
                technique_id="T1069",
                technique_name="Permission Groups Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            ),
            MitreTechnique(
                technique_id="T1087.004",
                technique_name="Password Policy Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Recon Account Authorization Info", "Retrieves information about all IAM users, groups, roles, and policies in your AWS account, including their relationships to one another", mitre_techniques)
        

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            filter_user: bool = kwargs.get("filter_user", False)
            filter_role: bool = kwargs.get("filter_role", False)
            filter_group: bool = kwargs.get("filter_group", False)
            filter_local_managed_policy: bool = kwargs.get("filter_local_managed_policy", False)
            filter_aws_managed_policy: bool = kwargs.get("filter_aws_managed_policy", False)
            
            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/get_account_authorization_details.html

            # Initialize boto3 client
            my_client = boto3.client("iam")

            # Create filter
            filter = []
            if filter_user:
                filter.append("User")
            if filter_role:
                filter.append("Role")
            if filter_group:
                filter.append("Group")
            if filter_local_managed_policy:
                filter.append("LocalManagedPolicy")
            if filter_aws_managed_policy:
                filter.append("AWSManagedPolicy")

            # Send request
            if filter:
                raw_response = my_client.get_account_authorization_details(Filter=filter)
            else:
                raw_response = my_client.get_account_authorization_details()

            # Request successful
            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                output = {}
                output['user_detail'] = raw_response['UserDetailList']
                output['role_detail'] = raw_response['RoleDetailList']
                output['group_detail'] = raw_response['GroupDetailList']
                output['policies'] = raw_response['Policies']

                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully collected AWS account authorization information",
                    "value": output
                }
            else:
                return ExecutionStatus.FAILURE, {
                    "error": raw_response.get('error').get('message', 'N/A'),
                    "message": "Failed to collect AWS account authorization information"
                }
        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to collect AWS account authorization information"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to collect account authorization information"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "filter_user": {"type": "bool", "required": False, "default": False, "name": "Filter Users?", "input_field_type" : "bool"},
            "filter_role": {"type": "bool", "required": False, "default": False, "name": "Filter Roles?", "input_field_type" : "bool"},
            "filter_group": {"type": "bool", "required": False, "default": False, "name": "Filter Groups?", "input_field_type" : "bool"},
            "filter_local_managed_policy": {"type": "bool", "required": False, "default": False, "name": "Filter Locally Managed Policies?", "input_field_type" : "bool"},
            "filter_aws_managed_policy": {"type": "bool", "required": False, "default": False, "name": "Filter AWS Managed Policied?", "input_field_type" : "bool"}
        }