from core.GraphFunctions import graph_get_request

def TechniqueMain(search_field = None, search_term = None):
    '''
    Ref: https://learn.microsoft.com/en-us/graph/search-query-parameter?tabs=http
    '''
    search_field_options = ['body','subject','attachment','from']
    endpoint_url = 'https://graph.microsoft.com/v1.0/me/messages?$select=id,from,toRecipients,subject,bodyPreview'
    
    if search_term != None:
        endpoint_url = f'https://graph.microsoft.com/v1.0/me/messages?$search="{search_term}"&$select=id,from,toRecipients,subject,bodyPreview'

        if search_field != None and search_term != None:
            endpoint_url = f'https://graph.microsoft.com/v1.0/me/messages?$search="{search_field}:{search_term}"&$select=id,from,toRecipients,subject,bodyPreview'
        
    '''Fetch mails'''
    all_mails = graph_get_request(url = endpoint_url)
    
    if all_mails == []:
        return "No results returned"
    
    return all_mails

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return []