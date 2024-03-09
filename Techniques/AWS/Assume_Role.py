'''
Module Name: Assume Role
Description: Generate temporary credentials to access AWS resources
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sts/client/assume_role.html#
'''
from core.AWSFunctions import CreateClient

def TechniqueMain(role_arn = None, role_session_name = None):

    if role_arn in [None, ""]:
        return "Error : Enter Role ARN"
    
    if role_session_name in [None, ""]:
        return "Error : Enter a Role session name"

    # initialize boto3 s3 client
    my_client = CreateClient('sts')

    try:
        response = my_client.assume_role(
            RoleArn = role_arn,
            RoleSessionName= role_session_name,
        )

    except Exception as e:
        return f"Error: {e}"

    assumed_role = {
        'Credentials': response.get('Credentials', 'N/A'),
        'Assumed Role User' : response.get('AssumedRoleUser', 'N/A')
    }

    return assumed_role

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Role ARN", "id" : "role-arn-text-input", "type" : "text", "placeholder" : "arn:aws:iam::557788119900:role/rolename", "element_type" : "dcc.Input"},
        {"title" : "Role Session Name", "id" : "role-session-name-text-input", "type" : "text", "placeholder" : "testing-session", "element_type" : "dcc.Input"}
    ]