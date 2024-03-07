from core.GraphFunctions import graph_post_request, graph_base_url
from dash import dcc,html
import yaml
import msal 

def TechniqueMain(client_id, client_secret,tenant_id, save_token = True):
    '''Generates graph access token by authenticating with a application client credentials'''
    try:
        client = msal.ConfidentialClientApplication(client_id, authority=f"https://login.microsoftonline.com/{tenant_id}", client_credential=client_secret)

        token_result = client.acquire_token_for_client(scopes=['https://graph.microsoft.com/.default'])
        if 'access_token' in token_result:
            access_token = token_result['access_token']
        else:
            pass
            
        headers = {'Content-Type': 'application/json','Authorization': 'Bearer ' + access_token}
        data = {}
        data['headers'] = headers

        '''Save accquired token'''
        if save_token == True:
            SaveTokens(access_token)
            
        return access_token

    except:
        return None

def SaveTokens(new_token):

    '''Add new access tokens to tokens yaml file'''
    tokens_file = "./Local/MSFT_Graph_Tokens.yml"

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


def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Client ID", "id" : "text-input-app-client-id", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"},
        {"title" : "Client Secret", "id" : "text-input-app-client-secret", "type" : "text", "placeholder" : "ssshhhhh_l0/\/g-s3c12et", "element_type" : "dcc.Input"},
        {"title" : "Tenant ID", "id" : "text-input-tenant-id", "type" : "text", "placeholder" : "abc123-xyz456-a1b2c3-x4y5z6", "element_type" : "dcc.Input"}
    ]