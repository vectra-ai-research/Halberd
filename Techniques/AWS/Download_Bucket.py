import boto3
def TechniqueMain(bucket, object, file):
    try:
        my_client = boto3.client('s3')
        response = my_client.download_file(bucket, object, file)
        return response

    except Exception as e:
        return f"Error: {e}"

def TechniqueInputSrc() -> dict:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Bucket Name", "id" : "bucket-text-input", "type" : "text", "placeholder" : "data-bucket", "element_type" : "dcc.Input"},
        {"title" : "Object Name", "id" : "object-text-input", "type" : "text", "placeholder" : "bucket-object-name", "element_type" : "dcc.Input"},
        {"title" : "File Name", "id" : "file-text-input", "type" : "text", "placeholder" : "file-name", "element_type" : "dcc.Input"}
    ]


# Ref - https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html#boto3.session.Session.client
