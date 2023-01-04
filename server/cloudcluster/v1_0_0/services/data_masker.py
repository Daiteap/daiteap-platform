import re

regexes = [
    {
        'pattern': '(?is) Token:.+". ',
        'replacement': ' Token: *******". '
    },
    {
        'pattern': "(?is)'aws_access_key_id': '.+?(?=')",
        'replacement': "'aws_access_key_id': '*******"
    },
    {
        'pattern': "(?is)'aws_secret_access_key': '.+?(?=')",
        'replacement': "'aws_secret_access_key': '*******"
    },
    {
        'pattern': "(?is)'azure_tenant_id': '.+?(?=')",
        'replacement': "'azure_tenant_id': '*******"
    },
    {
        'pattern': "(?is)'azure_subscription_id': '.+?(?=')",
        'replacement': "'azure_subscription_id': '*******"
    },
    {
        'pattern': "(?is)'azure_client_id': '.+?(?=')",
        'replacement': "'azure_client_id': '*******"
    },
    {
        'pattern': "(?is)'azure_client_secret': '.+?(?=')",
        'replacement': "'azure_client_secret': '*******"
    },
    {
        'pattern': "(?is)'region_name': '.+?(?=')",
        'replacement': "'region_name': '*******"
    },
    {
        'pattern': "(?is)'auth_url': '.+?(?=')",
        'replacement': "'auth_url': '*******"
    },
    {
        'pattern': "(?is)'application_credential_id': '.+?(?=')",
        'replacement': "'application_credential_id': '*******"
    },
    {
        'pattern': "(?is)'application_credential_secret': '.+?(?=')",
        'replacement': "'application_credential_secret': '*******"
    },
    {
        'pattern': "(?is)'external_network_id': '.+?(?=')",
        'replacement': "'external_network_id': '*******"
    },
    {
        'pattern': "(?is)'google_key': '.+?(?=')",
        'replacement': "'google_key': '*******"
    },
    {
        'pattern': "(?is)'gw_public_ip': '.+?(?=')",
        'replacement': "'gw_public_ip': '*******"
    },
    {
        'pattern': "(?is)'gw_private_ip': '.+?(?=')",
        'replacement': "'gw_private_ip': '*******"
    },
    {
        'pattern': "(?is)'admin_username': '.+?(?=')",
        'replacement': "'admin_username': '*******"
    },
    {
        'pattern': "(?is)'admin_private_key': '.+?(?=')",
        'replacement': "'admin_private_key': '*******"
    },
    {
        'pattern': "(?is)'admin_private_key_password': '.+?(?=')",
        'replacement': "'admin_private_key_password': '*******"
    },
    {
        'pattern': "(?is)'vpcCidr': '.+?(?=')",
        'replacement': "'vpcCidr': '*******"
    },
]


def mask_in_string(text):
    for regex in regexes:
        text = re.sub(regex['pattern'], regex['replacement'], text)

    return text
