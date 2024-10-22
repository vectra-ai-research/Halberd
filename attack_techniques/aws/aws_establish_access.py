from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.aws.aws_session_manager import SessionManager
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSEstablishAccess(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1078.004",
                technique_name="Valid Accounts",
                tactics=["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
                sub_technique_name="Cloud Accounts"
            )
        ]
        super().__init__("Establish Access", "Creates new AWS session", mitre_techniques)
        
    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            session_name: str = kwargs.get("session_name", None)
            access_key: str = kwargs.get("access_key", None)
            secret: str = kwargs.get("secret", None)
            aws_region: str = kwargs.get("aws_region", None)
            session_token: str = kwargs.get("session_token", None)
            set_as_active_session: bool = kwargs.get("set_as_active_session", False)

            if session_name in [None, ""] or access_key in [None, ""] or secret in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }
            
            if aws_region in [None, ""]:
                aws_region = "us-east-1"

            manager = SessionManager()
            if session_token:
                new_session = manager.create_session(session_name=session_name, aws_access_key_id=access_key, aws_secret_access_key=secret, region_name = aws_region, aws_session_token = session_token)
            else:
                new_session = manager.create_session(session_name=session_name, aws_access_key_id=access_key, aws_secret_access_key=secret, region_name = aws_region)

            my_session = manager.get_session(new_session["name"])
            sts = my_session.client('sts')
            caller_info = sts.get_caller_identity()

            caller_info_output = {
                'user_id' : caller_info.get('UserId', 'N/A'),
                'account' : caller_info.get('Account', 'N/A'),
                'arn' : caller_info.get('Arn', 'N/A'),
                'active_session': False
            }

            if set_as_active_session:
                # Set new session as default active session to use
                manager.set_active_session(new_session["name"])
                caller_info_output['active_session'] = True

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully established access to AWS",
                "value": caller_info_output
            }

        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to establish access to AWS"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to establish access to AWS"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "session_name": {"type": "str", "required": True, "default": None, "name": "New Session Name", "input_field_type" : "text"},
            "access_key": {"type": "str", "required": True, "default": None, "name": "Access Key", "input_field_type" : "text"},
            "secret": {"type": "str", "required": True, "default": None, "name": "Key Secret", "input_field_type" : "password"},
            "aws_region": {"type": "str", "required": False, "default": "us-east-1", "name": "AWS Region", "input_field_type" : "text"},
            "session_token": {"type": "str", "required": False, "default": None, "name": "Session Token", "input_field_type" : "text"},
            "set_as_active_session": {"type": "bool", "required": False, "default": False, "name": "Set As Active Session?", "input_field_type" : "bool"}
        }