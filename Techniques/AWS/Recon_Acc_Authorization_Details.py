'''
Module Name: Recon_Acc_Authorization_Details
Module Description: Get all information related to IAM users, groups, roles, and policies in AWS account
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/get_account_authorization_details.html
'''
from core.AWSFunctions import CreateClient
def TechniqueMain():

    # initialize boto3 s3 client
    my_client = CreateClient('iam')

    try:
        # request account authorization details
        raw_response = my_client.get_account_authorization_details()

        try:
            # parse raw response => pretty response
            pretty_response = {}

            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                if len(raw_response['UserDetailList']) > 0:
                    pretty_response['User Details'] ={}
                    for user in raw_response['UserDetailList']:
                        pretty_response['User Details'][user['UserId']] = user

                if len(raw_response['GroupDetailList']) > 0:
                    pretty_response['Group Details'] ={}
                    for group in raw_response['GroupDetailList']:
                        pretty_response['Group Details'][group['GroupId']] = group

                if len(raw_response['RoleDetailList']) > 0:
                    pretty_response['Role Details'] ={}
                    for role in raw_response['RoleDetailList']:
                        pretty_response['Role Details'][role['RoleId']] = role

                if len(raw_response['Policies']) > 0:
                    pretty_response['Polciy Details'] ={}
                    for policy in raw_response['Policies']:
                        pretty_response['Polciy Details'][policy['PolicyId']] = policy

                return True, raw_response, pretty_response
            else:
                # request unsuccessful
                return False, {"Error" : raw_response}, None
        except Exception as e:
            # return only raw response if pretty response fails
            return True, raw_response, None

    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return []