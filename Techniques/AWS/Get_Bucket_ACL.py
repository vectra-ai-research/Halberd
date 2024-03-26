'''
Module Name: Get S3 Bucket ACL
Module Description: Retrieve AWS S3 buckets ACL.
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/get_bucket_acl.html
'''
from core.AWSFunctions import CreateClient

def TechniqueMain(bucketName):
    # input validation
    if bucketName in [None, ""]:
        return False, {"Error" : "Invalid input"}, None

    # initialize boto3 s3 client
    my_client = CreateClient('s3')

    try:
        raw_response = my_client.get_bucket_acl(Bucket=bucketName)
    
        try:
            # parse raw response => pretty response
            pretty_response = {}

            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                pretty_response["Success"] = {
                    'Owner Display Name': raw_response.get('Owner', 'N/A').get('DisplayName','N/a'),
                    'Owner ID' : raw_response.get('Owner', 'N/A').get('ID','N/a'),
                    'Grants' : raw_response.get('Grants', 'N/A')
                }

                return True, raw_response, pretty_response
            else:
                return False, {"Error" : raw_response}, None
        except:
            # return only raw response if pretty response fails
            return True, raw_response, None

    except Exception as e:
        return False, {"Error" : e}, None
    
def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Bucket Name", "id" : "bucket-text-input", "type" : "text", "placeholder" : "data-bucket", "element_type" : "dcc.Input"}
    ]