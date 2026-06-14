<!-- Source: https://wazuh.com/blog/monitor-office-365/ | Article: Monitor Office 365 with Wazuh -->
# Obtain a token for accessing the Office 365 management activity API
def obtain_access_token(tenantId, clientId, clientSecret):
    # Add header and payload
    headers = {'Content-Type':'application/x-www-form-urlencoded'}
    payload = 'client_id={}&scope={}/.default&grant_type=client_credentials&client_secret={}'.format(clientId, resource, clientSecret)

    # Request token
    response = make_request("POST", "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(tenantId), headers=headers, data=payload)
    logging.info("Microsoft token was successfully fetched.")

    return json.loads(response.text)['access_token']