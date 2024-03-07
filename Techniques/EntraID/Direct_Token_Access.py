from core.GraphFunctions import graph_post_request, graph_base_url
from dash import dcc,html
import yaml
import msal 

def TechniqueMain(new_token):
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
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "MS Graph Access Token", "id" : "text-input-graph-token", "type" : "text", "placeholder" : "token:gdasgdyasgdhasgbfdgcdsc", "element_type" : "dcc.Input"}
    ]