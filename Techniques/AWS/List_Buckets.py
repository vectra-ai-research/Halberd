import boto3

def TechniqueMain():
    try:
        my_client = boto3.client('s3')
        buckets = my_client.list_buckets()
        return buckets

    except Exception as e:
        return f"Error: {e}"

def TechniqueInputSrc() -> dict:
    '''This function returns the input fields required as parameters for the technique execution'''
    return []