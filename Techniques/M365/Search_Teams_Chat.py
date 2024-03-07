from core.GraphFunctions import graph_get_request

def TechniqueMain(user_id, search_keyword):
    all_chats = RetrieveTeamsChats(user_id)
    print(all_chats)

    all_matched_messages = []

    for chat in all_chats:
        matched_message = SearchChat(chat['id'], search_keyword)
        all_matched_messages += matched_message
    
    return all_matched_messages

def RetrieveTeamsChats(user_id):
    endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/chats"

    chats = graph_get_request(url = endpoint_url)

    return chats

def RetrieveMessagesinChat(chat_id):
    endpoint_url = f"https://graph.microsoft.com/v1.0/chats/{chat_id}/messages?$top=2"

    messages = graph_get_request(url = endpoint_url)

    return messages

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