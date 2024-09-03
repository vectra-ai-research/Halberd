from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraAddUserToGroup(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1098.003",
                technique_name="Cloud Storage Object Discovery",
                tactics=["Persistence", "Privilege Escalation"],
                sub_technique_name="Additional Cloud Roles"
            )
        ]
        super().__init__("Add User To Group", "Adds user to a target group in Entra ID", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        try:
            user_id: str = kwargs.get('user_id', None)
            group_id: str = kwargs.get('group_id', None)
            access_token: str = kwargs.get('access_token', None)
            
            if user_id in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input - user_id"},
                    "message": {"Error" : "Invalid Technique Input"}
                }

            if group_id in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input - user_id"},
                    "message": {"Error" : "Invalid Technique Input"}
                }

            # recon applications
            endpoint_url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref"
            data = {
                "@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"
            }
            
            if access_token:
                raw_response = GraphRequest().post(url = endpoint_url, data = data, access_token= access_token)
            else:
                raw_response = GraphRequest().post(url = endpoint_url, data = data)
            

            # add user to group operation successfull
            if 200 <= raw_response.status_code < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully added user to group",
                    "value": {
                        'Group' : group_id,
                        'User' : user_id
                    }
                }
            else:
                return ExecutionStatus.FAILURE, {
                    "error": raw_response.json().get('error').get('message', 'N/A'),
                    "message": "Failed to add user to group"
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to add user to group"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "user_id": {"type": "str", "required": True, "default":None, "name": "User ID", "input_field_type" : "text"},  
            "group_id": {"type": "str", "required": True, "default":None, "name": "Group ID", "input_field_type" : "text"},
            "access_token": {"type": "str", "required": False, "default":None, "name": "Access Token", "input_field_type" : "text"}
        }