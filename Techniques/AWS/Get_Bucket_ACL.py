'''
Module Name: Get S3 Bucket ACL
Description: Retrieve AWS S3 buckets ACL.
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/get_bucket_acl.html
'''
from core.AWSFunctions import CreateClient

def TechniqueMain(bucketName):

    # initialize boto3 s3 client
    my_client = CreateClient('s3')

    try:
        response = my_client.get_bucket_acl(Bucket=bucketName)

    except Exception as e:
        return f"Error: {e}"

    bucket_acl = {
        'Owner Display Name': response.get('Owner', 'N/A').get('DisplayName','N/a'),
        'Owner ID' : response.get('Owner', 'N/A').get('ID','N/a'),
        'Grants' : response.get('Grants', 'N/A')
    }

    return bucket_acl
    
def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Bucket Name", "id" : "bucket-text-input", "type" : "text", "placeholder" : "data-bucket", "element_type" : "dcc.Input"}
    ]