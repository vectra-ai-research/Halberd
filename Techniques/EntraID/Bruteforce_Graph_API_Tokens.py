#Bruteforce Graph API Access Tokens via Delegated Access
from dash import dcc,html
import requests
import yaml

def TechniqueMain(username, password):
    '''Enumerate through different default Azure applications using the supplied credentials to grab access tokens with different scopes'''

    # Reference: https://learn.microsoft.com/en-us/troubleshoot/azure/active-directory/verify-first-party-apps-sign-in
    
    default_azure_applications_list = ["23523755-3a2b-41ca-9315-f81f3f566a95", "69893ee3-dd10-4b1c-832d-4870354be3d8", "7ab7862c-4c57-491e-8a45-d52a7e023983", "0cb7b9ec-5336-483b-bc31-b15b5788de71", "7b7531ad-5926-4f2d-8a1d-38495ad33e17", "e9f49c6b-5ce5-44c8-925d-015017e9f7ad", "835b2a73-6e10-4aa5-a979-21dfda45231c", "c44b4083-3bb0-49c1-b47d-974e53cbdf3c", "37182072-3c9c-4f6a-a4b3-b3f91cacffce", "9ea1ad79-fdb6-4f9a-8bc3-2b70f96e34c7", "20a11fe0-faa8-4df5-baf2-f965f8f9972e", "bb2a2e3a-c5e7-4f0a-88e0-8e01fd3fc1f4", "e64aa8bc-8eb4-40e2-898b-cf261a25954f", "00000007-0000-0000-c000-000000000000", "60c8bde5-3167-4f92-8fdb-059f6176dc0f", "497effe9-df71-4043-a8bb-14cf78c4b63b", "f5eaa862-7f08-448c-9c4e-f4047d4d4521", "b669c6ea-1adf-453f-b8bc-6d526592b419", "c35cb2ba-f88b-4d15-aa9d-37bd443522e1", "d9b8ec3a-1e4e-4e08-b3c2-5baf00c0fcb0", "a57aca87-cbc0-4f3c-8b9e-dc095fdc8978", "16aeb910-ce68-41d1-9ac3-9e1673ac9575", "d73f4b35-55c9-48c7-8b10-651f6f2acb2e", "944f0bd1-117b-4b1c-af26-804ed95e767e", "0cd196ee-71bf-4fd6-a57c-b491ffd4fb1e", "ee272b19-4411-433f-8f28-5c13cb6fd407", "0000000c-0000-0000-c000-000000000000", "65d91a3d-ab74-42e6-8a2f-0add61688c74", "38049638-cc2c-4cde-abe4-4479d721ed44", "29d9ed98-a469-4536-ade2-f981bc1d605e", "04b07795-8ddb-461a-bbee-02f9e1bf7b46", "1950a258-227b-4e31-a9cf-717495945fc2", "0000001a-0000-0000-c000-000000000000", "cf36b471-5b44-428c-9ce7-313bf84528de", "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8", "1786c5ed-9644-47b2-8aa0-7201292175b6", "3090ab82-f1c1-4cdf-af2c-5d7a6f3e2cc7", "18fbca16-2224-45f6-85b0-f7bf2b39b3f3", "00000015-0000-0000-c000-000000000000", "6253bca8-faf2-4587-8f2f-b056d80998a7", "99b904fd-a1fe-455c-b86c-2f9fb1da7687", "00000007-0000-0ff1-ce00-000000000000", "51be292c-a17e-4f17-9a7e-4b661fb16dd2", "fb78d390-0c51-40cd-8e17-fdbfab77341b", "c9a559d2-7aab-4f13-a6ed-e7e9c52aec87", "00000003-0000-0000-c000-000000000000", "74bcdadc-2fdc-4bb3-8459-76d06952a0e9", "fc0f3af4-6835-4174-b806-f7db311fd2f3", "d3590ed6-52b3-4102-aeff-aad2292ab01c", "00000006-0000-0ff1-ce00-000000000000", "67e3df25-268a-4324-a550-0de1c7f97287", "d176f6e7-38e5-40c9-8a78-3998aab820e7", "93625bc8-bfe2-437a-97e0-3d0060024faa", "871c010f-5e61-4fb1-83ac-98610a7e9110", "28b567f6-162c-4f54-99a0-6887f387bbcc", "cf53fce8-def6-4aeb-8d30-b158e7b1cf83", "98db8bd6-0cc0-4e67-9de5-f187f1cd1b41", "fdf9885b-dd37-42bf-82e5-c3129ef5a302", "1fec8e78-bce4-4aaf-ab1b-5451cc387264", "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe", "5e3ce6c0-2b1f-4285-8d4b-75ee78787346", "95de633a-083e-42f5-b444-a4295d8e9314", "dfe74da8-9279-44ec-8fb2-2aed9e1c73d0", "4345a7b9-9a63-4910-a426-35363201d503", "00000002-0000-0ff1-ce00-000000000000", "00b41c95-dab0-4487-9791-b9d2c32c80f2", "66a88757-258c-4c72-893c-3e8bed4d6899", "00000003-0000-0ff1-ce00-000000000000", "94c63fef-13a3-47bc-8074-75af8c65887a", "93d53678-613d-4013-afc1-62e9e444a0a5", "2abdc806-e091-4495-9b10-b04d93c3f040", "b23dd4db-9142-4734-867f-3577f640ad0c", "17d5e35f-655b-4fb0-8ae6-86356e9a49f5", "b6e69c34-5f1f-4c34-8cdf-7fea120b8670", "243c63a3-247d-41c5-9d83-7788c43f1c43", "a9b49b65-0a12-430b-9540-c80b3332c127", "4b233688-031c-404b-9a80-a4f3f2351f90", "89bee1f7-5e6e-4d8a-9f3d-ecd601259da7", "0f698dd4-f011-4d23-a33e-b36416dcb1e6", "4765445b-32c6-49b0-83e6-1d93765276ca", "4d5c2d63-cf83-4365-853c-925fd1a64357", "62256cef-54c0-4cb4-bcac-4c67989bdc40", "ab9b8c07-8f02-4f72-87fa-80105867a763", "2d4d3d8e-2be3-4bef-9f87-7875a61c29de", "27922004-5251-4030-b22d-91ecd9a37ea4", "a3475900-ccec-4a69-98f5-a65cd5dc5306", "bdd48c81-3a58-4ea9-849c-ebea7f6b6360", "35d54a08-36c9-4847-9018-93934c62740c", "00000009-0000-0000-c000-000000000000", "ae8e128e-080f-4086-b0e3-4c19301ada69", "ffcb16e8-f789-467c-8ce9-f826a080d987", "08e18876-6177-487e-b8b5-cf950c1e598c", "b4bddae8-ab25-483e-8670-df09b9f1d0ea", "00000004-0000-0ff1-ce00-000000000000", "61109738-7d2b-4a0b-9fe3-660b1ff83505", "91ca2ca5-3b3e-41dd-ab65-809fa3dffffa", "13937bba-652e-4c46-b222-3003f4d1ff97", "26abc9a8-24f0-4b11-8234-e86ede698878", "a970bac6-63fe-4ec5-8884-8536862c42d4", "905fcf26-4eb7-48a0-9ff0-8dcc7194b5ba", "97cb1f73-50df-47d1-8fb0-0271f2728514", "268761a2-03f3-40df-8a8b-c3db24145b6b", "00000005-0000-0ff1-ce00-000000000000", "3c896ded-22c5-450f-91f6-3d1ef0848f6e", "00000002-0000-0000-c000-000000000000", "8edd93e1-2103-40b4-bd70-6e34e586362d", "797f4846-ba00-4fd7-ba43-dac1f8f63013", "a3b79187-70b2-4139-83f9-6016c58cd27b", "26a7ee05-5602-4d76-a7ba-eae8b7b67941", "1b3c667f-cde3-4090-b60b-3d2abd0117f0", "45a330b1-b1ec-4cc1-9161-9f03992aa49f", "c1c74fed-04c9-4704-80dc-9f79a2e515cb", "e1ef36fd-b883-4dbf-97f0-9ece4b576fc6"]
    
    for app in default_azure_applications_list:
        collected_token = []
        access_token = PasswordAccess(username, password, client_id = app)
        if access_token != None:
            collected_token.append(access_token)
        
    return f"{len(collected_token)} tokens collected."

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
        return None
    
    '''Save access token to tokens file'''
    if save_token == True:
        SaveTokens(access_token)
    return access_token

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


def TechniqueInputSrc():
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Username", "id" : "graph-token-bf-username-text-input", "type" : "text", "placeholder" : "user@domain.com", "element_type" : "dcc.Input"},
        {"title" : "Password", "id" : "graph-token-bf-password-text-input", "type" : "password", "placeholder" : "h0peYOU!h@veThis", "element_type" : "dcc.Input"}
    ]