# Invite external user to tenant
from core.GraphFunctions import graph_post_request

def TechniqueMain(external_user_email):
    endpoint_url = f"https://graph.microsoft.com/v1.0/invitations"

    data = {
        "invitedUserEmailAddress": f"{external_user_email}",
        "inviteRedirectUrl": "https://myapp.contoso.com",
        'sendInvitationMessage': True,
        'invitedUserMessageInfo': {
            'customizedMessageBody': 'Welcome to the organization! Visit the link to accept the invitation.'
        }
    }

    response = graph_post_request(url = endpoint_url, data= data)
    return response

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "External User Email", "id" : "external-user-text-input", "type" : "email", "placeholder" : "user@ext_domain.com", "element_type" : "dcc.Input"}
    ]