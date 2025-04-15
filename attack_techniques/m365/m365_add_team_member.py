from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class M365AddTeamMember(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1098",
                technique_name="Account Manipulation",
                tactics=["Persistence", "Privilege Escalation"],
                sub_technique_name=None
            )
        ]

        technique_refs=[
                TechniqueReference("Microsoft Graph API - Add Member to Team", "https://learn.microsoft.com/en-us/graph/api/team-post-members")
            ]

        technique_notes = [
                TechniqueNote("Ensure the account being used to execute this technique has sufficient permissions to add members to the target team."),
                TechniqueNote("For internal users, the specified user must already exist in the organization's directory."),
                TechniqueNote("This technique requires you to know the team's ID, which can be obtained using the 'M365 Enumerate Teams' technique."),
                TechniqueNote("The newly added member will have the default role of 'member' unless specified otherwise."),
                TechniqueNote("Consider using this technique in conjunction with other M365 techniques to establish persistence across multiple services.")
            ]

        super().__init__(
            "Add User to Team", 
            "Adds a user to a Microsoft Teams team, granting access to team resources and channels. This technique facilitates persistence through legitimate access methods by adding a compromised or controlled account to an existing team. Once added to a team, the attacker gains access to shared files, conversations, and potentially sensitive information shared in the team.",
            mitre_techniques,
            references=technique_refs,
            notes=technique_notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            team_id: str = kwargs.get('team_id', None)
            user_identifier: str = kwargs.get('user_identifier', None)
            member_role: str = kwargs.get('member_role', 'member')

            # Input validation
            if team_id in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error": "Invalid Technique Input"},
                    "message": {"Error": "Team ID is required"}
                }

            if user_identifier in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error": "Invalid Technique Input"},
                    "message": {"Error": "User identifier (ID, UPN, or email) is required"}
                }
            
            if member_role in [None, ""]:
                member_role= "member" # defaults to member

            # Validate member role
            valid_roles = ["member", "owner"]
            if member_role not in valid_roles:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error": "Invalid Technique Input"},
                    "message": {"Error": f"Role must be one of: {', '.join(valid_roles)}"}
                }

            # Create the request endpoint
            endpoint_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/members"

            # Create payload
            data = {
                "@odata.type": "#microsoft.graph.aadUserConversationMember",
                "roles": [member_role] if member_role != "member" else [],
                "user@odata.bind": f"https://graph.microsoft.com/v1.0/users/{user_identifier}"
            }

            # Execute the request
            raw_response = GraphRequest().post(url=endpoint_url, data=data)

            # Handle response
            if 200 <= raw_response.status_code < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully added user to team",
                    "value": {
                        "team_id": team_id,
                        "user_identifier": user_identifier,
                        "display_name": raw_response.json().get('displayName', "N/A"),
                        "roles": raw_response.json().get("roles", []),
                        "status": "Added",
                        "member_id": raw_response.json().get('id', 'N/A')
                    }
                }
            else:
                return ExecutionStatus.FAILURE, {
                    "error": {
                        "error_code": raw_response.json().get('error', {}).get('code', 'N/A'),
                        "error_message": raw_response.json().get('error', {}).get('message', 'N/A')
                    },
                    "message": "Failed to add user to team"
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to add user to team"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "team_id": {
                "type": "str",
                "required": True,
                "default": None,
                "name": "Target Team ID",
                "input_field_type": "text"
            },
            "user_identifier": {
                "type": "str",
                "required": True,
                "default": None,
                "name": "User ID/UPN",
                "input_field_type": "text"
            },
            "member_role": {
                "type": "str",
                "required": False, 
                "default": "member",
                "name": "Member Role",
                "input_field_type": "select",
                "input_list": ["member", "owner"]
            }
        }