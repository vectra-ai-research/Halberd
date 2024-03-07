import boto3
def TechniqueMain(bucketName):
    try:
        my_client = boto3.client('s3')
        response = my_client.get_bucket_acl(Bucket=bucketName)
        return response

    except Exception as e:
        return f"Error: {e}"

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Bucket Name", "id" : "bucket-text-input", "type" : "text", "placeholder" : "data-bucket", "element_type" : "dcc.Input"}
    ]