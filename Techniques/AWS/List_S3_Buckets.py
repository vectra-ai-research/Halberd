'''
Module Name: Recon S3 Buckets
Description: List AWS S3 buckets owned by the authenticated user.
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html
'''
from core.AWSFunctions import CreateClient

def TechniqueMain():

    # initialize boto3 s3 client
    my_client = CreateClient('s3')

    try:
        # list s3 buckets
        response = my_client.list_buckets()
        buckets = response['Buckets']
        return buckets

    except Exception as e:
        return f"Failed to enumerate buckets: {e}"


def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return []