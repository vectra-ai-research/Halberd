'''
Module Name: List_Bucket_Objects
Module Description: List all objects in a specified S3 bucket
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_objects_v2.html
'''
from core.AWSFunctions import CreateClient
def TechniqueMain(bucketName):

    # input validation
    if bucketName in [None, ""]:
        return False, {"Error" : "Invalid input"}, None

    # initialize boto3 s3 client
    my_client = CreateClient('s3')

    try:
        # list objects in bucket
        raw_response = my_client.list_objects_v2(Bucket=bucketName)

        try:
            # parse raw response => pretty response
            pretty_response = {}

            if raw_response['KeyCount'] == 0:
                # no objects returned in bucket
                return True, raw_response, pretty_response

            bucket_objects = raw_response['Contents']
            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                for object in bucket_objects:
                    pretty_response[object['Key']] = {
                        'Object Key': object.get('Key', 'N/A'),
                        'Last Modified' : object.get('LastModified', 'N/A'),
                        'Size' : object.get('Size', 'N/A'),
                        'Owner' : object.get('Owner', 'N/A')
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