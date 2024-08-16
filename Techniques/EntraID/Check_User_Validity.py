'''
Module Name : Check user validity
Description : Check if a user exists in a target Microsoft tenant
Ref: https://aadinternals.com/post/just-looking/
'''

import requests
import json
import base64

def TechniqueMain(target_username, username_file_content = None):

    user_list = []

    # username input validation
    if target_username == [None,""]:
        return {"Error" : "Username file required"}

    # if file provided -> extract usernames from username text file
    if username_file_content[0]:
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
    else: 
        user_list.append(target_username)


    # GetCredentialType endpoint
    endpoint_url = "https://login.microsoftonline.com/common/GetCredentialType"
    
    # create request header
    headers = {
        "Content-Type": "application/json"
    }

    pretty_response = {}

    try:
        for user_name in user_list:
            # create request body
            request_body = {
                "username": user_name,
                "isOtherIdpSupported": True
            }
            # send request to endpoint
            raw_response = requests.post(endpoint_url, data=json.dumps(request_body), headers=headers)

            # parse data if request is successful
            if raw_response.status_code == 200:
                target_info = raw_response.json()

                # parse raw response => pretty response
                try:
                    pretty_response[target_info.get("Username")] = {
                        "User Exists" : True if target_info.get("IfExistsResult") == 0 else False
                    }
                except:
                    pass
            else:
                # if request fails, return error code and message
                return False, {"Error" : {"Error Code" : raw_response.status_code, "Message" : raw_response.content}}, None
        
        # return result
        return True, raw_response, pretty_response
    
    except Exception as e:
        return False, {"Error" : e}, None


def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Target Username", "id" : "target-username-text-input", "type" : "text", "placeholder" : "corp.com", "element_type" : "dcc.Input"},
        {"title" : "Username List File", "id" : "ps-username-file-uploader", "type" : "text", "placeholder" : "you got this right?", "element_type" : "dcc.Upload"}
        ]