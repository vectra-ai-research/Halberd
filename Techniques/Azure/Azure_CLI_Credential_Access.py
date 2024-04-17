'''
Module Name : Azure_CLI_Credential_Access
Module Description : Attempts to authenticate using a username and password via the azure cli. 
'''
import subprocess
import json

def TechniqueMain(user_name, password):

    # input validation
    if user_name in ["", None]:
        return False, {"Error" : "Username required"}, None
    if password in ["", None]:
        return False, {"Error" : "Password required"}, None
    
    try:
        raw_response = subprocess.run(["az", "login", "-u", user_name, "-p", password], capture_output=True)

        if raw_response.returncode == 0:
            output = raw_response.stdout
            struc_output = json.loads(output.decode('utf-8'))

            pretty_response = {}
            for subscription in struc_output:
                pretty_response[subscription.get("id", "N/A")] = {
                    "Subscription Name" : subscription.get("name", "N/A"),
                    "Subscription ID" : subscription.get("id", "N/A"),
                    "Home Tenant Id" : subscription.get("homeTenantId", "N/A"),
                    "State" : subscription.get("state", "N/A"),
                    "Identity (User/App)" : subscription.get("user", "N/A").get("name","N/A"),
                    "Identity Type" : subscription.get("user", "N/A").get("type","N/A"),
                }
            return True, raw_response, pretty_response 
        
        else:
            return True, struc_output, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Username", "id" : "username-text-input", "type" : "text", "placeholder" : "user@corp.com", "element_type" : "dcc.Input"},
        {"title" : "Password", "id" : "password-text-input", "type" : "password", "placeholder" : "something_long&difficu1t", "element_type" : "dcc.Input"}
    ]