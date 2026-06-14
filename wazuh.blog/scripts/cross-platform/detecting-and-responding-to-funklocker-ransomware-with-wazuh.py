<!-- Source: https://wazuh.com/blog/detecting-and-responding-to-funklocker-ransomware-with-wazuh/ | Article: Detecting and responding to Funklocker ransomware with Wazuh -->
from valhallaAPI.valhalla import ValhallaAPI
v = ValhallaAPI(api_key="1111111111111111111111111111111111111111111111111111111111111111")
response = v.get_rules_text()
with open('yara_rules.yar', 'w') as fh:
    fh.write(response)