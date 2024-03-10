'''
Module Name: List_IAM_Policies.py
Description: List IAM policies in aws account
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_policies.html
'''
from core.AWSFunctions import CreateClient

def TechniqueMain(scope = None, path_prefix = None):

    # scope input validation
    if scope not in [None, "", 'All', 'AWS', 'Local']:
        return "Invalid Input : Invalid scope provided. Acceptable values : All | AWS | Local"

    # initialize boto3 iam client
    my_client = CreateClient('iam')

    try:
        if path_prefix in [None, ""]:
            if scope in [None, ""]:
                # list policies in aws account
                response = my_client.list_policies()
            else:
                # list policies in aws account with specified scope
                response = my_client.list_policies(
                    Scope = scope
                )
        else:
            if scope in [None, ""]:
                # list policies in aws account with specified path prefix
                response = my_client.list_policies(
                    PathPrefix = path_prefix
                )
            else:
                # list policies in aws account with specified path prefix & scope
                response = my_client.list_policies(
                    PathPrefix = path_prefix,
                    Scope = scope
                )

        all_policies = response['Policies']

    except Exception as e:
        return f"Failed to enumerate policies: {e}"

    all_policies_output = {}

    # structure output to display response
    for policy in all_policies:
        all_policies_output[policy['PolicyId']] = {
            'PolicyName': policy.get('PolicyName', 'N/A'),
            'PolicyId': policy.get('PolicyId', 'N/A'),
            'Arn': policy.get('Arn', 'N/A'),
            'Path': policy.get('Path', 'N/A'),
            'AttachmentCount': policy.get('AttachmentCount', 'N/A'),
            'PermissionsBoundaryUsageCount': policy.get('PermissionsBoundaryUsageCount', 'N/A'),
            'IsAttachable': policy.get('IsAttachable', 'N/A'),
            'Description': policy.get('Description', 'N/A'),
        }

    return all_policies_output

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Policy Scope (Optional)", "id" : "scope-text-input", "type" : "text", "placeholder" : "All | AWS | Local", "element_type" : "dcc.Input"},
        {"title" : "Policy Path Prefix (optional)", "id" : "path-prefix-text-input", "type" : "text", "placeholder" : "/app_xyz/comp_123", "element_type" : "dcc.Input"}
    ]