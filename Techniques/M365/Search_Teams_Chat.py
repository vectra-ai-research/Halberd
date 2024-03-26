'''
Module Name : Search_Teams_Chat
Description : Recon chats in microsoft teams to collect data
'''
from core.GraphFunctions import graph_get_request

def TechniqueMain(user_id, search_keyword):
    raw_response = RetrieveTeamsChats(user_id)
    
    # check for error in response
    if 'error' in raw_response:
        return False, {"Error" : raw_response.get('error').get('message', 'N/A')}, None

    all_matched_messages = []

    for chat in raw_response:
        matched_message = SearchChat(chat['id'], search_keyword)
        all_matched_messages += matched_message

    if all_matched_messages == []:
        return True, all_matched_messages, None
    
    # parse raw response => pretty response
    try:
        # create pretty response
        pretty_response = {}

        for message in all_matched_messages:
            # checking keys for inconsistent data
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

            pretty_response[message['id']] = {
                'From' :sender,
                'Content Type' : content_type,
                'Message' : content,
                'attachments' : attachment,
            }

        return True, all_matched_messages, pretty_response
    except:
        # return only raw response if pretty response fails
        return True, all_matched_messages, None

def RetrieveTeamsChats(user_id):
    endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/chats"

    raw_response = graph_get_request(url = endpoint_url)

    return raw_response

def RetrieveMessagesinChat(chat_id):
    endpoint_url = f"https://graph.microsoft.com/v1.0/chats/{chat_id}/messages?$top=2"

    raw_response = graph_get_request(url = endpoint_url)

    return raw_response

def SearchChat(chat_id, search_keyword):
    matched_messages = []
    chat = RetrieveMessagesinChat(chat_id = chat_id)

    for message in chat:
        message_content = message['body']['content']
        if search_keyword in message_content:
            matched_messages.append(message)

    return matched_messages

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "User UPN", "id" : "chat-search-user-text-input", "type" : "email", "placeholder" : "user@corp.com", "element_type" : "dcc.Input"},
        {"title" : "Search Keyword", "id" : "chat-search-keyword-text-input", "type" : "text", "placeholder" : "secrets", "element_type" : "dcc.Input"}
    ]