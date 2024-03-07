# Recon Tenant Info
from core.GraphFunctions import graph_get_request

def TechniqueMain(domain):
    # Ref: https://learn.microsoft.com/en-us/graph/api/tenantrelationship-findtenantinformationbydomainname?view=graph-rest-1.0&tabs=http

    endpoint_url = f"https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByDomainName(domainName='{domain}')"

    # tenant_info = requests.get(url=endpoint_url).json()
    tenant_info = graph_get_request(url = endpoint_url)
    return tenant_info


def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Target Domain Name", "id" : "target-domain-text-input", "type" : "text", "placeholder" : "corp.com", "element_type" : "dcc.Input"}
        ]