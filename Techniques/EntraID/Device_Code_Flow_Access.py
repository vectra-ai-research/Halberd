import yaml
import requests
import time
from multiprocessing import Process, Queue

def TechniqueMain(tenant_id, client_id = None):
    endpoint_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
    scope = "https://graph.microsoft.com/.default"

    if client_id == None:
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"

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

    '''Wait for device code flow auth to finish'''
    queue = Queue()
    process = Process(target=AcquireDeviceCodeFlowToken(token_url, token_data, polling_interval), args=(queue, 1))
    
    return "Access Token Added"

def AcquireDeviceCodeFlowToken(token_url, token_data, polling_interval):

    while True:
        time.sleep(polling_interval)
        token_response = requests.post(token_url, data=token_data)

        if token_response.status_code == 200:
            token_json = token_response.json()
            access_token = token_json['access_token']
            SaveTokens(access_token)
            print("Access token saved")
            return access_token
            break
        elif token_response.status_code == 400 and 'error' in token_response.json() and token_response.json()['error'] == 'authorization_pending':
            # Continue polling
            print("User has not yet authenticated. Continuing to poll...")
        else:
            print(f"Error: {token_response.status_code} - {token_response.text}")
            break

def SaveTokens(new_token):

    '''Add new access tokens to tokens yaml file'''
    tokens_file = "./local/MSFT_Graph_Tokens.yml"

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
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Tenant ID", "id" : "device-code-flow-tenant-id-text-input", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"},
        {"title" : "Client ID", "id" : "device-code-flow-client-id-text-input", "type" : "text", "placeholder" : "(Optonal)1234-5678-9098-7654-3210", "element_type" : "dcc.Input"}
    ]