'''
Module Name: Invite_External_User
Module Description: Invite any external user to grant access to the current tenant
'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(external_user_email):

    # input validation
    if external_user_email in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None

    endpoint_url = f"https://graph.microsoft.com/v1.0/invitations"

    data = {
        "invitedUserEmailAddress": f"{external_user_email}",
        "inviteRedirectUrl": "https://myapp.contoso.com",
        'sendInvitationMessage': True,
        'invitedUserMessageInfo': {
            'customizedMessageBody': 'Welcome to the organization! Visit the link to accept the invitation.'
        }
    }

    try:
        raw_response = graph_post_request(url = endpoint_url, data = data)

        # invite external user operation successfull
        if 200 <= raw_response.status_code < 300:
            # parse raw response => pretty response
            try:
                # create pretty response
                pretty_response = {}

                pretty_response["Success"] = {
                    'Message' : "External user invitation sent",
                    'External User' : raw_response.json().get('invitedUserEmailAddress', 'N/A'),
                    'invitedUserType' : raw_response.json().get('invitedUserType', 'N/A'),
                    'Invited User Id' : raw_response.json().get('invitedUser', 'N/A').get('id', 'N/A'),
                    'Invitation Message' : raw_response.json().get('invitedUserMessageInfo', 'N/A').get('customizedMessageBody', 'N/A'),
                    'Invite Status' : raw_response.json().get('status', 'N/A'),
                    'Invite Redeem URL' : raw_response.json().get('inviteRedeemUrl', 'N/A')
                }
                return True, raw_response, pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response, None
        
        # invite external user operation failed
        else:
            return False, {"Error" : {"Response Status" : raw_response.status_code, "Code" : raw_response.json().get('error').get('code', 'N/A'), "Message" : raw_response.json().get('error').get('message', 'N/A')}}, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "External User Email", "id" : "external-user-text-input", "type" : "email", "placeholder" : "user@ext_domain.com", "element_type" : "dcc.Input"}
    ]