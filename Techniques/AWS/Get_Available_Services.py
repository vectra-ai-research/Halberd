def TechniqueMain(session):
    try:
        response = session.get_available_services()
        return response

    except Exception as e:
        return f"Error: {e}"

def TechniqueInputSrc() -> dict:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "S3 Client", "id" : "s3-client-text-input", "type" : "text", "placeholder" : "client 1", "element_type" : "dcc.Input"}
    ]