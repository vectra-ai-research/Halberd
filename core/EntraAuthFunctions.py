'''
Ref: https://learn.microsoft.com/en-us/troubleshoot/azure/active-directory/verify-first-party-apps-sign-in
'''

import requests
import json
import msal 
import json
import yaml
import base64
import datetime
from core.Local import WriteAppLog
import time


def PasswordAccess(user_name, password, client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c",save_token = True ):
    '''Generates graph access token by authenticating with a username & password'''

    endpoint_url = "https://login.microsoft.com/common/oauth2/token"
    resource = "https://graph.microsoft.com"
    scope = ['openid']
    
    headers = {
        "Accept" : "application/json",
        "Content-Type" : "application/x-www-form-urlencoded"
    }

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

    except Exception as e:
        WriteAppLog("PasswordAccess: Token request failed")
        return None
    
    '''Save access token to tokens file'''
    if save_token == True:
        SaveTokens(access_token)
    return access_token
    

def AzureAppAccess(client_id, client_secret,tenant_id, save_token = True):
    '''Generates graph access token by authenticating with a application client credentials'''
    try:
        client = msal.ConfidentialClientApplication(client_id, authority=f"https://login.microsoftonline.com/{tenant_id}", client_credential=client_secret)

        token_result = client.acquire_token_for_client(scopes=['https://graph.microsoft.com/.default'])
        if 'access_token' in token_result:
            access_token = token_result['access_token']
        else:
            # print(token_result.get('error'))
            # print(token_result.get('error_description'))
            # print(token_result.get('correlation'))
            WriteAppLog("AzureAppAccess: Token request failed")

        headers = {'Content-Type': 'application/json','Authorization': 'Bearer ' + access_token}
        data = {}
        data['headers'] = headers

        '''Save accquired token'''
        if save_token == True:
            SaveTokens(access_token)
            
        return access_token

    except:
        WriteAppLog("AzureAppAccess: Token request failed")
        return None

def SaveTokens(new_token):

    '''Add new access tokens to tokens yaml file'''
    tokens_file = "./Local/MSFT_Graph_Tokens.yml"

    '''If read fails because file does not exist - create file and initialize tokens array'''
    try:
        with open(tokens_file, "r") as tokens_data:
            all_tokens_data = yaml.safe_load(tokens_data)
    except:
        WriteAppLog("SaveTokens: Tokens file not found")
        with open(tokens_file, "w") as file:
            all_tokens_data = {'AllTokens':[]}
            WriteAppLog("SaveTokens: Tokens file created")

    if new_token not in all_tokens_data['AllTokens']:
        all_tokens_data['AllTokens'].append(new_token)

        with open(tokens_file, 'w') as file:
            yaml.dump(all_tokens_data, file)

        WriteAppLog("New token added")
        return True
    else:
        WriteAppLog("Duplicate token: Token add skipped")
        return None


def FetchAllTokens():

    '''Fetch access tokens from the tokens yaml file'''
    tokens_file = "./Local/MSFT_Graph_Tokens.yml"

    if tokens_file != None:
        with open(tokens_file, "r") as tokens_data:
            all_tokens_data = yaml.safe_load(tokens_data)

        '''Returns a list of all stored tokens'''
        return all_tokens_data.get('AllTokens')
    
    else:
        return None

def SetSelectedToken(access_token):

    '''Set a token as selected for use all across by the user'''
    tokens_file = "./Local/MSFT_Graph_Tokens.yml"

    if tokens_file != None:
        with open(tokens_file, "r") as tokens_data:
            all_tokens_data = yaml.safe_load(tokens_data)

    all_tokens_data.update({'Current': access_token})

    with open(tokens_file, 'w') as file:
        yaml.dump(all_tokens_data, file)
    
    WriteAppLog("New token selection updated")


def FetchSelectedToken():

    '''Fetch token selected by user for use'''
    tokens_file = "./Local/MSFT_Graph_Tokens.yml"

    if tokens_file != None:
        with open(tokens_file, "r") as tokens_data:
            all_tokens_data = yaml.safe_load(tokens_data)
    
    return all_tokens_data.get('Current')


def CreateHeader(access_token):

    '''Create header for MS Graph requests using the passed access token'''
    headers = {'Content-Type': 'application/json','Authorization': 'Bearer ' + access_token}
    return headers

def DecodeJWToken(access_token):

    '''Decode JWT access token to make information readable'''
    try:
        access_token_info = access_token.split(".")[1].replace("-", "+").replace("_", "/")
        
        '''validate base64 length, if required, add '=' to add padding'''
        while (len(access_token_info)%4 != 0):
            access_token_info += "="

        '''base64 decode token'''
        b64_decoded_token = base64.b64decode(access_token_info)
        '''plain text token info'''
        token_pt = b64_decoded_token.decode()

        token_info = json.loads(token_pt)

        '''return token info in dict'''
        return token_info
    except:
        WriteAppLog("DecodeJWToken: Failed to decode token")
        return None

def ExtractTokenInfo(access_token):
    
    '''Retrieve latest token in use'''
    '''Decode the token'''
    token_info = DecodeJWToken(access_token)

    if token_info != None:
        try:
            '''Extract required info from token'''
            token_app_name = token_info['app_displayname']
            token_target_tenant = token_info['tid']
            token_entity_type = token_info['idtyp']
            token_expiration = datetime.datetime.utcfromtimestamp(token_info['exp']).strftime('%Y-%m-%dT%H:%M:%SZ')
            
            '''Extract inforamtion depending on delegated or app-only access '''
            if token_entity_type == "user":
                token_authenticated_entity = token_info['upn']
                token_scope = token_info['scp']
                access_type = "Delegated"
            else: 
                token_authenticated_entity = token_info['app_displayname']
                token_scope = token_info['roles']
                access_type = "App-only"

            access_info = {"Entity": token_authenticated_entity, "Entity Type": token_entity_type, "Access Exp": token_expiration, "Access scope": token_scope, "Target App Name": token_app_name, "Target Tenant": token_target_tenant, "Access Type": access_type}

            return access_info
        except:
            '''Failed to decode token'''
            WriteAppLog("ExtractTokenInfo: Failed to extract token info")
            return None
    else:
        WriteAppLog("ExtractTokenInfo: Did not receive decoded token")
        return None



def DeviceCodeFlow(tenant_id, client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"):
    
    endpoint_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
    scope = "https://graph.microsoft.com/.default"

    data = {
        "client_id": client_id,
        "scope": scope,
    }

    generate_device_code_flow = requests.post(url=endpoint_url, data=data).json()
    print(generate_device_code_flow)

    user_code = generate_device_code_flow['user_code']
    verification_uri = generate_device_code_flow['verification_uri']
    device_code = generate_device_code_flow['device_code']
    polling_interval = generate_device_code_flow['interval']

    print(f"Please go to {verification_uri} and enter the code {user_code}")

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": client_id,
        "device_code": device_code,
    }

    return verification_uri, user_code, token_url, token_data, polling_interval

def AcquireDeviceCodeFlowToken(token_url, token_data, polling_interval):

    while True:
        time.sleep(polling_interval)
        token_response = requests.post(token_url, data=token_data)

        if token_response.status_code == 200:
            token_json = token_response.json()
            access_token = token_json['access_token']
            SaveTokens(access_token)
            return access_token
            break
        elif token_response.status_code == 400 and 'error' in token_response.json() and token_response.json()['error'] == 'authorization_pending':
            # Continue polling
            print("User has not yet authenticated. Continuing to poll...")
        else:
            print(f"Error: {token_response.status_code} - {token_response.text}")
            break