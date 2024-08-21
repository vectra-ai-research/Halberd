'''
Module Name : Recon_Tenant_Info
Description : Recon information related to the target tenant 
Ref: https://learn.microsoft.com/en-us/graph/api/tenantrelationship-findtenantinformationbydomainname?view=graph-rest-1.0&tabs=http
'''
from core.GraphFunctions import graph_get_request
import requests
import re

def TechniqueMain(target_domain, authenticated = None):

    # username input validation
    if target_domain in [None,""]:
        return False, {"Error" : "Domain Name input required"}, None
    
    if authenticated == True:
        # make authenticated request
        endpoint_url = f"https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByDomainName(domainName='{target_domain}')"

        try:
            # recon tenant info
            raw_response = graph_get_request(url = endpoint_url)

            if 'error' in raw_response:
                return False, {"Error" : raw_response.get('error').get('message', 'N/A')}, None

            # parse raw response => pretty response
            try:
                # create pretty response
                pretty_response = {}
                pretty_response["Success"] = {
                    'Display Name' : raw_response.get('displayName', 'N/A'),
                    'Tenant Id' : raw_response.get('tenantId', 'N/A'),
                    'Default Domain Name' : raw_response.get('defaultDomainName', 'N/A'),
                    'Federation Brand Name' : raw_response.get('federationBrandName', 'N/A')
                }
                return True, raw_response, pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response, None
            
        except Exception as e:
            return False, {"Error" : e}, None
    
    else:
        # make unauthenticated request
        endpoint_url = f"https://login.microsoftonline.com/{target_domain}/.well-known/openid-configuration"
        try:
            raw_response = requests.get(endpoint_url).json()
            pretty_response = {}
            try:
                # extract tenant id
                pattern = r"([a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12})"
                match = re.search(pattern, raw_response['token_endpoint'], re.IGNORECASE)
                tenant_id = match.group(1)

                # parse raw response => pretty response
                pretty_response["Success"] = {
                    'Tenant ID' : tenant_id,
                    'Domain Name' : target_domain,
                    'Token Endpoint' : raw_response.get('token_endpoint', 'N/A'),
                    'Scopes Supported' : raw_response.get('scopes_supported', 'N/A')
                }
                return True, raw_response, pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response, None
            
        except Exception as e:
            return False, {"Error" : e}, None


def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Target Domain Name", "id" : "target-domain-text-input", "type" : "text", "placeholder" : "corp.com", "element_type" : "dcc.Input"},
        {"title" : "Authenticated Request", "id" : "auth-boolean-text-input", "type" : "text", "placeholder" : "corp.com", "element_type" : "daq.BooleanSwitch"}
        ]