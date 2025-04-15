from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class M365EnumerateTeamMembers(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1087.004",
                technique_name="Account Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Account"
            ),
            MitreTechnique(
                technique_id="T1069.003",
                technique_name="Permission Groups Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Groups"
            )
        ]

        technique_notes = [
            TechniqueNote("Enumerate membership of multiple teams by adding multiple Team IDs separated by comma in the input")
        ]

        super().__init__(
            "Enumerate Team Members", 
            "Enumerates members of a Team in Microsoft Teams. This technique gathers information about Teams members, including user identity, roles, display names and email addresses to build a detailed membership map. This data can be used to identify key personnel, discover roles with higher privileges, and plan further targeted attacks against specific individuals or user groups. The technique can be directed at specific teams of interest or used broadly to enumerate multiple teams simultaneously, making it valuable for both targeted and broad reconnaissance.", 
            mitre_techniques,
            notes=technique_notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            team_ids: str = kwargs.get('team_ids', None)
            include_guest_members: bool = kwargs.get('include_guest_members', True)
            
            # Input validation
            if team_ids in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error": "Invalid Technique Input"},
                    "message": {"Error": "Team IDs are required"}
                }
            
            # Set guest member enum default
            if include_guest_members in [None, ""]:
                include_guest_members = True
            
            # Process multiple team IDs
            team_list = [team_id.strip() for team_id in team_ids.split(',')]
            results = {}
            
            for team_id in team_list:
                # Verify team exists and get basic info
                team_info = self._get_team_info(team_id)
                if not team_info:
                    results[team_id] = {"error": "Team not found or access denied"}
                    continue
                
                # Get team members
                endpoint_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/members"
                raw_response = GraphRequest().get(url=endpoint_url)

                if 'error' in raw_response:
                    return ExecutionStatus.FAILURE, {
                        "error": {
                            "error_code" :raw_response.get('error').get('code'),
                            "error_detail" : raw_response.get('error').get('message')
                        },
                        "message": "Failed to enumerate users in tenant"
                    }

                team_members = []
                for member in raw_response:
                    # Skip guest members if not requested
                    if not include_guest_members and "guest" in member.get("userType", "").lower():
                        continue
                        
                    team_members.append({
                        "displayName": member.get("displayName", "N/A"),
                        "email": member.get("email", "N/A"),
                        "roles": member.get("roles", []),
                        "userId": member.get("userId", "N/A"),
                        "id": member.get("id", "N/A")
                    })

                if not team_members:
                    results[team_id] = {
                        "info": team_info,
                        "member_count": len(team_members),
                        "members": [],
                        "message": "No members found or access denied"
                    }
                    continue
                
                # Store results for this team
                results[team_id] = {
                    "info": team_info,
                    "member_count": len(team_members),
                    "members": team_members
                }
            
            if not results:
                return ExecutionStatus.FAILURE, {
                    "error": "Failed to enumerate any team members",
                    "message": "No valid teams found or insufficient permissions"
                }
            
            # Calculate total members found
            total_members = sum(result.get("member_count", 0) for result in results.values() if "member_count" in result)
            
            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully enumerated {total_members} members across {len(team_list)} teams",
                "value": {
                    "result": f"Successfully enumerated {total_members} members across {len(team_list)} teams",
                    "team_details": results
                }
            }
            
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate team members"
            }

    def _get_team_info(self, team_id: str) -> Dict[str, Any]:
        """Get basic information about a team"""
        endpoint_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}"
        
        response = GraphRequest().get(url=endpoint_url)
        
        if 'error' in response:
            return None
        
        return {
            "id": response.get("id", "N/A"),
            "displayName": response.get("displayName", "N/A"),
            "description": response.get("description", "N/A"),
            "visibility": response.get("visibility", "N/A"),
            "isArchived": response.get("isArchived", False)
        }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "team_ids": {
                "type": "str", 
                "required": True, 
                "default": None, 
                "name": "Team ID(s) (comma-separated)", 
                "input_field_type": "text"
            },
            "include_guest_members": {
                "type": "bool", 
                "required": False, 
                "default": True, 
                "name": "Include Guest Members", 
                "input_field_type": "bool"
            }
        }