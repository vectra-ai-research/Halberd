'''
Module Name: Assume Role
Module Description: Generate temporary credentials to access AWS resources
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sts/client/assume_role.html#
'''
from core.AWSFunctions import CreateClient

def TechniqueMain(role_arn = None, role_session_name = None):
    # input validation
    if role_arn in [None, ""]:
        return False, {"Error" : "Enter Role ARN"}, None
    
    if role_session_name in [None, ""]:
        return False, {"Error" : "Enter a session name"}, None

    # initialize boto3 s3 client
    my_client = CreateClient('sts')

    try:
        raw_response = my_client.assume_role(
            RoleArn = role_arn,
            RoleSessionName= role_session_name,
        )

        if 'error' in raw_response:
            return False, {"Error" : raw_response.get('error').get('message', 'N/A')}, None
        try:
            # parse raw response => pretty response
            pretty_response = {}
            pretty_response = {
                'Credentials': raw_response.get('Credentials', 'N/A'),
                'Assumed Role User' : raw_response.get('AssumedRoleUser', 'N/A')
            }
            return True, raw_response, pretty_response
        except:
            # return only raw response if pretty response fails
            return True, raw_response, None


    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Role ARN", "id" : "role-arn-text-input", "type" : "text", "placeholder" : "arn:aws:iam::557788119900:role/rolename", "element_type" : "dcc.Input"},
        {"title" : "Role Session Name", "id" : "role-session-name-text-input", "type" : "text", "placeholder" : "testing-session", "element_type" : "dcc.Input"}
    ]