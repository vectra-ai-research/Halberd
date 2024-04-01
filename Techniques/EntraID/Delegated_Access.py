'''
Module Name: Delegated_Access
Module Description: Generates graph access token by authenticating with a username & password
'''
import requests
import yaml

def TechniqueMain(user_name, password, client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c",save_token = True):

    # input validation
    if user_name in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if password in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if client_id in [None, ""]:
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c" #Setting the default client to use if user does not specify

    endpoint_url = "https://login.microsoft.com/common/oauth2/token"
    resource = "https://graph.microsoft.com"
    scope = ['openid']
    
    headers = {
        "Accept" : "application/json",
        "Content-Type" : "application/x-www-form-urlencoded"
    }

    data = {
        "grant_type": "password",
        "password" : password,
        "client_id" : client_id,
        "username" : user_name,
        "resource" : resource,
        "scope" : ' '.join(scope)
    }

    # request access token
    try:
        raw_response = requests.post(url = endpoint_url, headers = headers, data = data)

        if 200 <= raw_response.status_code < 300:
            access_token = raw_response.json().get('access_token')
            # save access token
            if save_token == True:
                SaveTokens(access_token)
            
            # parse raw response => pretty response
            try:
                # create pretty response
                pretty_response = {}

                pretty_response["Success"] = {
                    'Message' : "Authentication successful",
                    "Username" : user_name,
                    "Access Token" : access_token,
                    "Token Saved" : save_token
                }
                return True, raw_response, pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response, None
        
        # delegated access operation failed
        else:
            return False, {"Error" : {"Response Status" : raw_response.status_code, "Code" : raw_response.json().get('error'), "Message" : raw_response.json().get('error_description')}}, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def SaveTokens(new_token):

    '''Add new access tokens to tokens yaml file'''
    tokens_file = "./local/MSFT_Graph_Tokens.yml"

    '''If read fails because file does not exist - create file and initialize tokens array'''
    try:
        with open(tokens_file, "r") as tokens_data:
            all_tokens_data = yaml.safe_load(tokens_data)
    except:
        with open(tokens_file, "w") as file:
            all_tokens_data = {'AllTokens':[]}

    if new_token not in all_tokens_data['AllTokens']:
        all_tokens_data['AllTokens'].append(new_token)

        with open(tokens_file, 'w') as file:
            yaml.dump(all_tokens_data, file)

        return True
    else:
        return None


def TechniqueInputSrc():
    '''Returns the input fields required as parameters for the technique execution'''

    return [
        {"title" : "Username", "id" : "text-input-username", "type" : "text", "placeholder" : "user@corp.com", "element_type" : "dcc.Input"},
        {"title" : "Password", "id" : "password-input-password", "type" : "password", "placeholder" : "you got this right?", "element_type" : "dcc.Input"},
        {"title" : "App ID (Optional)", "id" : "text-input-client-id", "type" : "text", "placeholder" : "Optional (Default: Microsoft Office)", "element_type" : "dcc.Input"}
    ]