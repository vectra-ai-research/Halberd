'''
Module Name: App_Only_Access
Module Description: Generates graph access token by authenticating with a application client credentials
'''
import yaml
import msal 

def TechniqueMain(client_id, client_secret,tenant_id, save_token = True):
    # input validation
    if client_id in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if client_secret in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if tenant_id in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None

    try:
        client = msal.ConfidentialClientApplication(client_id, authority=f"https://login.microsoftonline.com/{tenant_id}", client_credential=client_secret)

        raw_response = client.acquire_token_for_client(scopes=['https://graph.microsoft.com/.default'])

        if 'access_token' in raw_response:
            access_token = raw_response['access_token']
            # save token
            if save_token == True:
                SaveTokens(access_token)
            try:
                # create pretty response
                pretty_response = {}

                pretty_response["Success"] = {
                    "Access Token" : access_token,
                    "Expires In" : raw_response.get('expires_in', 'N/A'),
                    "Token Saved" : save_token
                }
                return True, raw_response, pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response, None
        else:
            return False, {"Error": {"Error" : raw_response.get('error', 'N/A')}, "Description": raw_response.get('error_description', 'N/A'), "Error Code": raw_response.get('error_codes', 'N/A')}, None

    except Exception as e:
        return False, {"Error" : e}, None

def SaveTokens(new_token):

    # add new access token to tokens yaml file
    tokens_file = "./Local/MSFT_Graph_Tokens.yml"

    # if read fails because file does not exist - create file and initialize tokens array
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


def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Client ID", "id" : "text-input-app-client-id", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"},
        {"title" : "Client Secret", "id" : "text-input-app-client-secret", "type" : "text", "placeholder" : "ssshhhhh_l0/\/g-s3c12et", "element_type" : "dcc.Input"},
        {"title" : "Tenant ID", "id" : "text-input-tenant-id", "type" : "text", "placeholder" : "abc123-xyz456-a1b2c3-x4y5z6", "element_type" : "dcc.Input"}
    ]