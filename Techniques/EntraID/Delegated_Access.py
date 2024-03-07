import requests
import yaml

def TechniqueMain(user_name, password, client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c",save_token = True):
    '''Generates graph access token by authenticating with a username & password'''

    endpoint_url = "https://login.microsoft.com/common/oauth2/token"
    resource = "https://graph.microsoft.com"
    scope = ['openid']
    
    headers = {
        "Accept" : "application/json",
        "Content-Type" : "application/x-www-form-urlencoded"
    }

    if client_id == None:
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c" #Setting the default client to use if user does not specify

    data = {
        "grant_type": "password",
        "password" : password,
        "client_id" : client_id,
        "username" : user_name,
        "resource" : resource,
        "scope" : ' '.join(scope)
    }

    '''Request access token'''
    try:
        token_request = requests.post(url = endpoint_url, headers = headers, data = data).json()
        access_token = token_request['access_token']

        '''Save access token to tokens file'''
        if save_token == True:
            SaveTokens(access_token)
            return access_token

    except Exception as e:
        return None


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