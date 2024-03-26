from core.AWSFunctions import CreateClient

def TechniqueMain(service = "ec2"):
    try:
        my_client = CreateClient(service)
        response = my_client.get_available_services()
        return response

    except Exception as e:
        return f"Error: {e}"

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Service", "id" : "service-text-input", "type" : "text", "placeholder" : "client 1", "element_type" : "dcc.Input"}
    ]