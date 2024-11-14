from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class M365SearchTeamsChat(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1530",
                technique_name="Data from Cloud Storage",
                tactics=["Collection"],
                sub_technique_name=None
            ),
            MitreTechnique(
                technique_id="T1552.008",
                technique_name="Unsecured Credentials",
                tactics=["Credential Access"],
                sub_technique_name="Chat Messages"
            )
        ]
        super().__init__("Search Teams Chat", "Searches chats in microsoft teams to collect data", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        try:
            user_id: str = kwargs.get('user_id', None)
            search_keyword: str = kwargs.get('search_keyword', None)
            
            if user_id in [None, ""] or  search_keyword in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }

            output = []
            raw_response = RetrieveTeamsChats(user_id)

            if 'error' in raw_response:
                return ExecutionStatus.FAILURE, {
                    "error": str(raw_response.get('error', "")),
                    "message": "Failed to search teams chat"
                }

            all_matched_messages = []
            for chat in raw_response:
                matched_message = SearchChat(chat['id'], search_keyword)
                all_matched_messages += matched_message

            if all_matched_messages == []:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Found {len(all_matched_messages)} matching chats",
                    "value": output
                }
            
            for message in all_matched_messages:
                # Checking keys for inconsistent data
                if 'body' in message.keys():
                    content_type = message.get('body', 'N/A').get('contentType', 'N/A')
                    content = message.get('body', 'N/A').get('content', 'N/A')
                else:
                    content_type = 'N/A'
                    content = 'N/A'
                if 'from' in message.keys():
                    sender = message.get('from', 'N/A').get('user').get('displayName', 'N/A')
                else:
                    sender = 'N/A'
                if 'attachments' in message.keys():
                    attachment = message.get('attachments', 'N/A')
                else:
                    attachment = 'N/A'

                output.append({
                    "from" :sender,
                    "content_type" : content_type,
                    "message" : content,
                    "attachments" : attachment
                })
        
            if output:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully found {len(output)} matching chats",
                    "value": output
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": f"No matching chats found",
                    "value": []
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to search teams chat"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "user_id": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "User UPN", 
                "input_field_type" : "text"
            },
            "search_keyword": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "Search Keyword", 
                "input_field_type" : "text"
            }
        }
    
def RetrieveTeamsChats(user_id):
    endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/chats"

    raw_response = GraphRequest().get(url = endpoint_url)

    return raw_response

def RetrieveMessagesinChat(chat_id):
    endpoint_url = f"https://graph.microsoft.com/v1.0/chats/{chat_id}/messages?$top=2"

    raw_response = GraphRequest().get(url = endpoint_url)

    return raw_response

def SearchChat(chat_id, search_keyword):
    matched_messages = []
    chat = RetrieveMessagesinChat(chat_id = chat_id)

    for message in chat:
        message_content = message['body']['content']
        if search_keyword in message_content:
            matched_messages.append(message)

    return matched_messages