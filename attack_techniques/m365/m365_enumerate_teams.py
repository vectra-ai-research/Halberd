from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class M365EnumerateTeams(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1069.003",
                technique_name="Permission Groups Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Groups"
            )
        ]

        technique_notes = [
            TechniqueNote("Private Teams won't appear in results unless the user is a member"),
            TechniqueNote("Team discovery is often a starting point for more targeted data collection techniques")
        ]

        super().__init__(
            "Enumerate Teams", 
            "Enumerates all Microsoft Teams accessible to the current user, including both public and private teams where the user is a member. This technique extracts team data such as team names, descriptions, visibility, and channel information, which can be valuable for mapping organizational structures, identifying collaboration patterns, and discovering potential data repositories for further targeting. Enumerating Teams provides insights that can be leveraged for lateral movement or targeted data collection.",
            mitre_techniques,
            notes=technique_notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            include_channels: bool = kwargs.get('include_channels', False)
            team_id: str = kwargs.get('team_id', None)

            # Input validation
            if include_channels in [None, ""]:
                include_channels = False

            # First, enumerate available teams
            if team_id:
                # If team_id is provided, only enumerate that specific team
                endpoint_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}"
                raw_response = GraphRequest().get(url=endpoint_url)
                
                if 'error' in raw_response:
                    return ExecutionStatus.FAILURE, {
                        "error": str(raw_response.get('error', "")),
                        "message": "Failed to retrieve specified team"
                    }
                
                teams = [raw_response]
            else:
                # Enumerate all teams the user is a member of
                endpoint_url = "https://graph.microsoft.com/v1.0/me/joinedTeams"
                raw_response = GraphRequest().get(url=endpoint_url)
                
                if 'error' in raw_response:
                    return ExecutionStatus.FAILURE, {
                        "error": str(raw_response.get('error', "")),
                        "message": "Failed to enumerate teams"
                    }
                
                teams = raw_response
            
            # Process team data and optionally get channels
            processed_teams = []
            
            for team in teams:
                team_data = {
                    "displayName": team.get('displayName', 'N/A'),
                    "id": team.get('id', 'N/A'),
                    "description": team.get('description', 'N/A'),
                    "visibility": team.get('visibility', 'N/A'),
                    "isArchived": team.get('isArchived', False),
                    "webUrl": team.get('webUrl', 'N/A'),
                    "isMembershipLimitedToOwners": team.get('isMembershipLimitedToOwners', 'N/A'),
                    "memberSettings": team.get('memberSettings', 'N/A'),
                    "guestSettings": team.get('guestSettings', 'N/A'),
                }
                
                # If include channels enum, retrieve them
                if include_channels:
                    channels_url = f"https://graph.microsoft.com/v1.0/teams/{team['id']}/channels"
                    channels_response = GraphRequest().get(url=channels_url)
                    
                    if 'error' not in channels_response:
                        channels = []
                        for channel in channels_response:
                            channel_data = {
                                "id": channel.get('id', 'N/A'),
                                "displayName": channel.get('displayName', 'N/A'),
                                "description": channel.get('description', 'N/A'),
                                "webUrl": channel.get('webUrl', 'N/A'),
                                "membershipType": channel.get('membershipType', 'standard')
                            }
                            channels.append(channel_data)
                        
                        team_data["channels"] = channels
                        team_data["channelCount"] = len(channels)
                    else:
                        team_data["channels"] = {"error": "Failed to retrieve channels"}
                
                processed_teams.append(team_data)
            
            if team_id and processed_teams:
                # Return single team details
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully retrieved team information for {processed_teams[0]['displayName']}",
                    "value": processed_teams[0]
                }
            else:
                # Return all teams
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(processed_teams)} Teams",
                    "value": {
                        "result": f"Successfully enumerated {len(processed_teams)} Teams", "team_details": processed_teams}
                }
                
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate Microsoft Teams"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "include_channels": {
                "type": "bool", 
                "required": False, 
                "default": False, 
                "name": "Include Channels", 
                "input_field_type": "bool"
            },
            "team_id": {
                "type": "str", 
                "required": False, 
                "default": None, 
                "name": "Specific Team ID (Optional)", 
                "input_field_type": "text"
            }
        }