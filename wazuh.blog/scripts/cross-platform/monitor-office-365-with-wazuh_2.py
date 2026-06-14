<!-- Source: https://wazuh.com/blog/monitor-office-365/ | Article: Monitor Office 365 with Wazuh -->
# Manage content type subscriptions
def manage_content_type_subscriptions(contentTypes, clientId, token):
    # For every available content type
    for contentType in availableContentTypes:
        # If it was added as a parameter then start the subscription
        if contentType in contentTypes:
            make_api_request("POST", "{}/api/v1.0/{}/activity/feed/subscriptions/start?contentType={}".format(resource, clientId, contentType), token)
            logging.info("{} subscription was successfully started.".format(contentType))
        # Otherwise stop the subscription
        else:
            make_api_request("POST", "{}/api/v1.0/{}/activity/feed/subscriptions/stop?contentType={}".format(resource, clientId, contentType), token)
            logging.debug("{} subscription was successfully stopped.".format(contentType))