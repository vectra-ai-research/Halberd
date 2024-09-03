from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSEnumerateEC2Instances(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1580",
                technique_name="Cloud Infrastructure Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate EC2 Instances", "Enumerates instances in AWS EC2. Optionally, pass additional parameters to filter results", mitre_techniques)
        

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            aws_region: str = kwargs.get("aws_region", "us-east-1")
            instance_id: str = kwargs.get("instance_id", None)
            state: str = kwargs.get("state", None)
            max_results: int = kwargs.get("max_results", None)
            dry_run: bool = kwargs.get("dry_run", False)

            valid_aws_regions = ["us-east-2", "us-east-1", "us-west-1", "us-west-2", "af-south-1", "ap-east-1", "ap-south-2", "ap-southeast-3", "ap-southeast-4", "ap-south-1", "ap-northeast-3", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ca-central-1", "ca-west-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-south-1", "eu-west-3", "eu-south-2", "eu-north-1", "eu-central-2", "il-central-1", "me-south-1", "me-central-1", "sa-east-1", "us-gov-east-1", "us-gov-west-1"]
            
            if aws_region:
                if aws_region.lower() not in valid_aws_regions:
                    return ExecutionStatus.FAILURE, {
                        "error": {"Error" : "Invalid Technique Input"},
                        "message": {"Error" : "Invalid Technique Input"}
                    }
            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_instances.html

            # create filter based on user supplied parameters
            filters = []

            if state:
                filters.append(
                    {
                        'Name': 'instance-state-name',
                        'Values': [state]
                    },
                )

            if instance_id:
                filters.append(
                    {
                        'Name': 'instance-id',
                        'Values': [instance_id]
                    },
                )

            if dry_run:
                dry_run = True
            else:
                dry_run = False

            # Enumerate EC2
            # Initiate output
            output = {}
            total_instances = 0
            if aws_region:
                regions_to_enumerate = [aws_region]
            else:
                regions_to_enumerate = valid_aws_regions
            
            for aws_region in regions_to_enumerate:
                try:
                    # Initialize boto3 client
                    my_client = boto3.client("ec2", region_name = aws_region)

                    if max_results:
                        raw_response = my_client.describe_instances(Filters = filters, DryRun = dry_run, MaxResults = max_results)
                    else:
                        raw_response = my_client.describe_instances(Filters = filters, DryRun = dry_run)

                    if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                        # Create output
                        instances = []
                        for reservation in raw_response['Reservations']:
                            for instance in reservation['Instances']:
                                instances.append(instance['InstanceId'])
                        # Add to main output
                        output[aws_region] = instances
                        total_instances += len(instance)
                    else:
                        # No action
                        pass
                except Exception as e:
                    # No action
                    pass

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully enumerated {total_instances} EC2 instances" if output else "No EC2 instances found",
                "value": output
            }

        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate EC2 instances"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "aws_region": {"type": "str", "required": False, "default": None, "name": "AWS Region", "input_field_type" : "text"},
            "instance_id": {"type": "str", "required": False, "default": None, "name": "Instance ID", "input_field_type" : "text"},
            "state": {"type": "str", "required": False, "default": None, "name": "Instance State", "input_field_type" : "text"},
            "max_results": {"type": "int", "required": False, "default": None, "name": "Max Results", "input_field_type" : "number"},
            "dry_run": {"type": "bool", "required": False, "default": False, "name": "Dry Run", "input_field_type" : "bool"}
        }