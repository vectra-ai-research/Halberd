from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class M365SendOutlookEmail(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1534",
                technique_name="Internal Spearphishing",
                tactics=["Lateral Movement"],
                sub_technique_name=None
            )
        ]
        super().__init__("Send Outlook email", "Send email using users mailbox", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        try:
            user_id: str = kwargs.get('user_id', None)
            to_recipient: str = kwargs.get('to_recipient', None)
            subject: str = kwargs.get('subject', None)
            email_content: str = kwargs.get('email_content', None)
            hide_from_mailbox: bool = kwargs.get('hide_from_mailbox', False)

            if user_id in [None, ""] or  to_recipient in [None, ""] or  subject in [None, ""] or  email_content in [None, ""] or  hide_from_mailbox in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }

            endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/sendMail"
            
            # Create payload
            data = {
                "message" : {
                    "subject" : subject,
                    "body" : {
                        "contentType" : "Text",
                        "content" : email_content
                    },
                    "toRecipients": [
                        {
                            "emailAddress": {
                                "address": to_recipient
                            }
                        }
                    ],
                },
                "saveToSentItems": not hide_from_mailbox
            }
            
            raw_response = GraphRequest().post(url = endpoint_url, data = data)

            # Request successful
            if 200 <= raw_response.status_code < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully sent email from users mailbox",
                    "value": {
                        "sender" : user_id,
                        "recipient" : to_recipient,
                        "subject" : subject,
                        "content" : email_content,
                        "email_hidden" : hide_from_mailbox
                    }
                }

            else:
                return ExecutionStatus.FAILURE, {
                    "error": {
                        "error_code": raw_response.json().get('error').get('code', 'N/A'),
                        "eror_message": raw_response.json().get('error').get('message', 'N/A')
                    },
                    "message": "Failed to send email from users mailbox"
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to send email from users mailbox"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "user_id": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "Sender Email", 
                "input_field_type" : "email"
            },
            "to_recipient": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "Recipient Email", 
                "input_field_type" : "email"
            },
            "subject": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "Email Subject", 
                "input_field_type" : "text"
            },
            "email_content": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "Email Content", 
                "input_field_type" : "text"
            },
            "hide_from_mailbox": {
                "type": "bool", 
                "required": True, 
                "default":False, 
                "name": "Hide Sent Email from Senders Mailbox?", 
                "input_field_type" : "bool"
            }
        }