from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3

@TechniqueRegistry.register
class AWSEnumerateGuarddutyDetectors(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1526",
                technique_name="Cloud Service Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate GuardDuty Detectors", "Enumerates all GuardDuty detectors in the AWS account. The technique first retrieves list of all regions in the account and then enumerates through regions to get all GuardDuty detector IDs", mitre_techniques)
        
    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            # Initialize boto3 client
            my_ec2_client = boto3.client('ec2')

            # Get all regions
            response = my_ec2_client.describe_regions()
            
            # Extract all region names
            all_regions = [region['RegionName'] for region in response['Regions']]
            
            all_detector_ids = {}
            for region in all_regions:
                try:
                    # Initialize boto3 client
                    my_client = boto3.client('guardduty', region_name=region)
                    
                    # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/guardduty/client/list_detectors.html
                    # List all guardduty detectors
                    raw_response = my_client.list_detectors()
                    # Extract detector IDs from response
                    all_detector_ids[region] = raw_response['DetectorIds']
                    # all_detector_ids += raw_response['DetectorIds']
                except:
                    pass
            
            # counter for all detector IDs
            did_count = 0
            for value in all_detector_ids.values():
                if isinstance(value, list):
                    did_count += len(value)
                else:
                    did_count += 1
            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully enumerated {did_count} GuardDuty detectors" if did_count > 0 else "No GuardDuty detectors found",
                "value": all_detector_ids
            }
        
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate GuardDuty detectors"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}