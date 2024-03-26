'''
Module Name: Recon_S3_Buckets
Description: List AWS S3 buckets owned by the authenticated user.
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html
'''
from core.AWSFunctions import CreateClient

def TechniqueMain():

    # initialize boto3 s3 client
    my_client = CreateClient('s3')

    try:
        # list s3 buckets
        raw_response = my_client.list_buckets()
        buckets = raw_response['Buckets']

        # parse raw response => pretty response
        try:
            # create pretty response
            pretty_response = {}
            for bucket_info in buckets:
                pretty_response[bucket_info['Name']] = {
                    'Bucket Name' : bucket_info.get('Name', 'N/A'),
                    'Creation Date' : bucket_info.get('CreationDate', 'N/A')
                }
            return True, raw_response, pretty_response
        except:
            # return only raw response if pretty response fails
            return True, raw_response, None

    except Exception as e:
        return False, {"Error" : e}, None


def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return []