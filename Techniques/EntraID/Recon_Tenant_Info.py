'''
Module Name : Recon_Tenant_Info
Description : Recon information related to the target tenant 
Ref: https://learn.microsoft.com/en-us/graph/api/tenantrelationship-findtenantinformationbydomainname?view=graph-rest-1.0&tabs=http
'''
from core.GraphFunctions import graph_get_request

def TechniqueMain(domain):

    # username input validation
    if domain == [None,""]:
        return {"Error" : "Username input required"}

    endpoint_url = f"https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByDomainName(domainName='{domain}')"

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

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Target Domain Name", "id" : "target-domain-text-input", "type" : "text", "placeholder" : "corp.com", "element_type" : "dcc.Input"}
        ]