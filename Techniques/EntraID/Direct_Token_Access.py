'''
Module Name: Direct_Token_Access
Module Description: Add an access token to Halberd Access manger
'''
import yaml

def TechniqueMain(new_token):

    # input validation
    if new_token in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None

    # add new access tokens to tokens yaml file
    tokens_file = "./local/MSFT_Graph_Tokens.yml"

    # if read fails because file does not exist - create file and initialize tokens array
    try:
        with open(tokens_file, "r") as tokens_data:
            all_tokens_data = yaml.safe_load(tokens_data)
    except:
        with open(tokens_file, "w") as file:
            all_tokens_data = {'AllTokens':[]}

    # check if same token already exists
    if new_token not in all_tokens_data['AllTokens']:
        all_tokens_data['AllTokens'].append(new_token)

        with open(tokens_file, 'w') as file:
            yaml.dump(all_tokens_data, file)

        # raw response is the user submitted token
        raw_response = new_token
        
        # parse raw response => pretty response
        # create pretty response
        pretty_response = {}

        pretty_response["Success"] = {
            "Token Added" : True,
            "Message" : "Activate token from 'Access' page",
            "Access Token" : new_token
        }

        return True, raw_response, pretty_response
    else:
        return False, {"Error" : {"Message" : "Duplicate token. Token already present in Halberd access manager"}}, None


def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "MS Graph Access Token", "id" : "text-input-graph-token", "type" : "text", "placeholder" : "token:gdasgdyasgdhasgbfdgcdsc", "element_type" : "dcc.Input"}
    ]