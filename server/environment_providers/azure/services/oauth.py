import time
import msal
import requests
from cloudcluster.settings import (APP_NAME, AZURE_AUTH_SCOPES,
                                   AZURE_CLIENT_AUTHORIZE_URI,
                                   AZURE_CLIENT_CREATE_APP_URI,
                                   AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
                                   AZURE_SERVICE_OAUTH_ACCOUNTS_PREFIX)

AZURE_GRAPH_API = 'https://graph.microsoft.com'
AZURE_MANAGEMENT_API = 'https://management.azure.com'
AZURE_LOGIN_URL = 'https://login.microsoftonline.com'
REQUEST_TIMEOUT = 10

AZURE_PERMISSIONS = [
    "Microsoft.Authorization/roleAssignments/read",
    "Microsoft.Compute/availabilitySets/delete",
    "Microsoft.Compute/availabilitySets/read",
    "Microsoft.Compute/availabilitySets/vmSizes/read",
    "Microsoft.Compute/availabilitySets/write",
    "Microsoft.Compute/disks/delete",
    "Microsoft.Compute/disks/read",
    "Microsoft.Compute/disks/write",
    "Microsoft.Compute/galleries/applications/delete",
    "Microsoft.Compute/galleries/applications/read",
    "Microsoft.Compute/galleries/applications/versions/delete",
    "Microsoft.Compute/galleries/applications/versions/read",
    "Microsoft.Compute/galleries/applications/versions/write",
    "Microsoft.Compute/galleries/applications/write",
    "Microsoft.Compute/galleries/delete",
    "Microsoft.Compute/galleries/images/delete",
    "Microsoft.Compute/galleries/images/read",
    "Microsoft.Compute/galleries/images/versions/delete",
    "Microsoft.Compute/galleries/images/versions/read",
    "Microsoft.Compute/galleries/images/versions/write",
    "Microsoft.Compute/galleries/images/write",
    "Microsoft.Compute/galleries/read",
    "Microsoft.Compute/galleries/share/action",
    "Microsoft.Compute/galleries/write",
    "Microsoft.Compute/virtualMachines/assessPatches/action",
    "Microsoft.Compute/virtualMachines/cancelPatchInstallation/action",
    "Microsoft.Compute/virtualMachines/capture/action",
    "Microsoft.Compute/virtualMachines/convertToManagedDisks/action",
    "Microsoft.Compute/virtualMachines/deallocate/action",
    "Microsoft.Compute/virtualMachines/delete",
    "Microsoft.Compute/virtualMachines/generalize/action",
    "Microsoft.Compute/virtualMachines/installPatches/action",
    "Microsoft.Compute/virtualMachines/performMaintenance/action",
    "Microsoft.Compute/virtualMachines/powerOff/action",
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/virtualMachines/redeploy/action",
    "Microsoft.Compute/virtualMachines/reimage/action",
    "Microsoft.Compute/virtualMachines/restart/action",
    "Microsoft.Compute/virtualMachines/runCommand/action",
    "Microsoft.Compute/virtualMachines/start/action",
    "Microsoft.Compute/virtualMachines/write",
    "Microsoft.Network/connections/delete",
    "Microsoft.Network/connections/read",
    "Microsoft.Network/connections/write",
    "Microsoft.Network/loadBalancers/backendAddressPools/backendPoolAddresses/read",
    "Microsoft.Network/loadBalancers/backendAddressPools/delete",
    "Microsoft.Network/loadBalancers/backendAddressPools/health/action",
    "Microsoft.Network/loadBalancers/backendAddressPools/join/action",
    "Microsoft.Network/loadBalancers/backendAddressPools/queryInboundNatRulePortMapping/action",
    "Microsoft.Network/loadBalancers/backendAddressPools/read",
    "Microsoft.Network/loadBalancers/backendAddressPools/updateAdminState/action",
    "Microsoft.Network/loadBalancers/backendAddressPools/write",
    "Microsoft.Network/loadBalancers/delete",
    "Microsoft.Network/loadBalancers/health/action",
    "Microsoft.Network/loadBalancers/networkInterfaces/read",
    "Microsoft.Network/loadBalancers/read",
    "Microsoft.Network/loadBalancers/write",
    "Microsoft.Network/localnetworkgateways/delete",
    "Microsoft.Network/localnetworkgateways/read",
    "Microsoft.Network/localnetworkgateways/write",
    "Microsoft.Network/networkInterfaces/delete",
    "Microsoft.Network/networkInterfaces/ipconfigurations/read",
    "Microsoft.Network/networkInterfaces/join/action",
    "Microsoft.Network/networkInterfaces/loadBalancers/read",
    "Microsoft.Network/networkInterfaces/read",
    "Microsoft.Network/networkInterfaces/tapConfigurations/delete",
    "Microsoft.Network/networkInterfaces/tapConfigurations/read",
    "Microsoft.Network/networkInterfaces/tapConfigurations/write",
    "Microsoft.Network/networkInterfaces/write",
    "Microsoft.Network/networkSecurityGroups/delete",
    "Microsoft.Network/networkSecurityGroups/join/action",
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Network/networkSecurityGroups/write",
    "Microsoft.Network/privateDnsZones/delete",
    "Microsoft.Network/privateDnsZones/read",
    "Microsoft.Network/privateDnsZones/SOA/read",
    "Microsoft.Network/privateDnsZones/virtualNetworkLinks/delete",
    "Microsoft.Network/privateDnsZones/virtualNetworkLinks/read",
    "Microsoft.Network/privateDnsZones/virtualNetworkLinks/write",
    "Microsoft.Network/privateDnsZones/write",
    "Microsoft.Network/publicIPAddresses/delete",
    "Microsoft.Network/publicIPAddresses/join/action",
    "Microsoft.Network/publicIPAddresses/read",
    "Microsoft.Network/publicIPAddresses/write",
    "Microsoft.Network/routeTables/delete",
    "Microsoft.Network/routeTables/join/action",
    "Microsoft.Network/routeTables/read",
    "Microsoft.Network/routeTables/routes/delete",
    "Microsoft.Network/routeTables/routes/read",
    "Microsoft.Network/routeTables/routes/write",
    "Microsoft.Network/routeTables/write",
    "Microsoft.Network/virtualNetworkGateways/delete",
    "Microsoft.Network/virtualNetworkGateways/read",
    "Microsoft.Network/virtualNetworkGateways/write",
    "Microsoft.Network/virtualNetworks/delete",
    "Microsoft.Network/virtualNetworks/join/action",
    "Microsoft.Network/virtualNetworks/joinLoadBalancer/action",
    "Microsoft.Network/virtualNetworks/read",
    "Microsoft.Network/virtualNetworks/subnets/delete",
    "Microsoft.Network/virtualNetworks/subnets/join/action",
    "Microsoft.Network/virtualNetworks/subnets/read",
    "Microsoft.Network/virtualNetworks/subnets/virtualMachines/read",
    "Microsoft.Network/virtualNetworks/subnets/write",
    "Microsoft.Network/virtualNetworks/write",
    "Microsoft.Resources/subscriptions/resourceGroups/delete",
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.Resources/subscriptions/resourceGroups/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
    "Microsoft.Storage/storageAccounts/blobServices/containers/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/write",
    "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action",
    "Microsoft.Storage/storageAccounts/delete",
    "Microsoft.Storage/storageAccounts/read",
    "Microsoft.Storage/storageAccounts/write"
]

MESSAGE_INTERNAL_ERROR = 'Internal server error'
MESSAGE_EMPTY_TENANT = 'authorize_tenant parameter is empty'
MESSAGE_EMPTY_CODE = 'auth_code parameter is empty'
MESSAGE_EMPTY_ORIGIN = 'origin parameter is empty'
MESSAGE_EMPTY_SUBSCRIPTION_ID = 'subscription_id parameter is empty'
MESSAGE_EMPTY_REDIRECT_URI = 'redirect_uri is empty'
PASSWORD_END_DATE = '2299-12-30T22:00:00.000Z'


class AzureAuthClient():
    __authorize_tenant = ''

    def __init__(self, authorize_tenant):
        if authorize_tenant in ('', None):
            raise Exception(MESSAGE_EMPTY_TENANT)

        self.__authorize_tenant = authorize_tenant

    def __checkForRestError(self, data):
        try:
            data.raise_for_status()
        except Exception as e:
            print(e)
            print(data.json())
            raise Exception(data.json())

    def __checkForError(self, data):
        if 'error' in data:
            raise Exception(str(data))
        if 'responses' in data:
            if data['responses']:
                if 'httpStatusCode' in data['responses'][0]:
                    if data['responses'][0]['httpStatusCode'] > 299:
                        raise Exception(str(data))

    def __getOrCreateApp(self, access_token, origin):

        # Check for existing app
        applications_data = requests.get(
            f'{AZURE_GRAPH_API}/v1.0/applications',
            headers={
                'Authorization': 'Bearer ' + access_token
            },
            timeout=REQUEST_TIMEOUT
        )

        self.__checkForRestError(applications_data)
        self.__checkForError(applications_data.json())
        applications_data = applications_data.json()

        for app in applications_data['value']:
            if app['displayName'] == APP_NAME:
                return app

        # Create new app
        request_body = {
            'displayName': APP_NAME,
            'signInAudience': 'AzureADMyOrg',
            'requiredResourceAccess': [{
                'resourceAppId': '00000003-0000-0000-c000-000000000000', # Microsoft Graph
                'resourceAccess': [{
                    'id': '7ab1d382-f21e-4acd-a863-ba3e13f7da61', # Directory.Read.All
                    'type': 'Role',
                }]
            }],
            'web': {
                'redirectUris': [origin + '/server/azuregrantadminconsent']
            },
        }

        new_application_data = requests.post(
            f'{AZURE_GRAPH_API}/v1.0/applications',
            json=request_body,
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + access_token
            },
            timeout=REQUEST_TIMEOUT
        )

        self.__checkForError(new_application_data)
        new_application_data = new_application_data.json()

        return new_application_data

    def __getOrCreateServiceAccount(self, access_token, app_id):
        service_principal_id = self.__getServiceAccountId(
            access_token,
            app_id
        )

        if service_principal_id == '':
            service_principal_id = self.__createServiceAccount(
                access_token,
                app_id
            )
        return service_principal_id

    def __removeOldPasswords(self, access_token, application_id, user):
        password_data = requests.get(
            f'{AZURE_GRAPH_API}/v1.0/applications/{application_id}',
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + access_token
            },
            timeout=REQUEST_TIMEOUT
        )

        self.__checkForRestError(password_data)
        self.__checkForError(password_data.json())
        password_data = password_data.json()

        for password_credential in password_data['passwordCredentials']:
            if password_credential['displayName'] == AZURE_SERVICE_OAUTH_ACCOUNTS_PREFIX + '-' + str(user.id):
                key_id = password_credential['keyId']

                request_body = {
                    'keyId': key_id
                }

                password_data = requests.post(
                    f'{AZURE_GRAPH_API}/v1.0/applications/{application_id}/removePassword',
                    json=request_body,
                    headers={
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + access_token
                    },
                    timeout=REQUEST_TIMEOUT
                )

                self.__checkForRestError(password_data)

    def __addPassword(self, access_token, application_id, user):

        request_body = {
            'passwordCredential': {
                'displayName': AZURE_SERVICE_OAUTH_ACCOUNTS_PREFIX + '-' + str(user.id),
                'endDateTime': PASSWORD_END_DATE
            }
        }

        password_data = requests.post(
            f'{AZURE_GRAPH_API}/v1.0/applications/{application_id}/addPassword',
            json=request_body,
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + access_token
            },
            timeout=REQUEST_TIMEOUT
        )

        self.__checkForRestError(password_data)
        self.__checkForError(password_data.json())
        password_data = password_data.json()

        return password_data

    def __getServiceAccountId(self, access_token, app_id):
        data = requests.get(
            f'{AZURE_GRAPH_API}/v1.0/servicePrincipals?$filter=appId eq \'{app_id}\'',
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + access_token
            },
            timeout=REQUEST_TIMEOUT
        )

        self.__checkForRestError(data)
        self.__checkForError(data.json())
        service_principals = data.json()

        for service_principal in service_principals['value']:
            if 'appId' in service_principal:
                if service_principal['appId'] == app_id:
                    return service_principal['id']

        return ''

    def __createServiceAccount(self, access_token, app_id):
        request_body = {
            "appId": app_id,
            "tags": [
                "WindowsAzureActiveDirectoryIntegratedApp"
            ]
        }

        create_data = requests.post(
            f'{AZURE_GRAPH_API}/v1.0/servicePrincipals',
            json=request_body,
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + access_token
            },
            timeout=REQUEST_TIMEOUT
        )

        self.__checkForRestError(create_data)
        self.__checkForError(create_data.json())
        service_principal = create_data.json()

        service_principal_id = service_principal['id']

        return service_principal_id

    def __getManagementToken(self, auth_code, origin, uri):
        authority = f'{AZURE_LOGIN_URL}/{self.__authorize_tenant}'
        scopes = [f'{AZURE_MANAGEMENT_API}/.default']
        redirect_uri = f'{origin}{uri}'

        management_token = msal.ConfidentialClientApplication(
            AZURE_CLIENT_ID,
            authority=authority,
            client_credential=AZURE_CLIENT_SECRET).acquire_token_by_authorization_code(
                auth_code,
                scopes=scopes,
                redirect_uri=redirect_uri
            )

        self.__checkForError(management_token)

        return management_token['access_token']

    def __getGraphToken(self):
        authority = f'{AZURE_LOGIN_URL}/{self.__authorize_tenant}'

        scopes = [f'{AZURE_GRAPH_API}/.default']

        graph_token = msal.ConfidentialClientApplication(
            AZURE_CLIENT_ID,
            authority=authority,
            client_credential=AZURE_CLIENT_SECRET).acquire_token_for_client(scopes=scopes)

        self.__checkForError(graph_token)
        return graph_token['access_token']

    def __createAppWithPass(self, user, graph_token, origin):
        app = self.__getOrCreateApp(graph_token, origin)

        self.__removeOldPasswords(graph_token, app['id'], user)
        secret = self.__addPassword(graph_token, app['id'], user)['secretText']

        return {"applicationId": app['appId'], 'id': app['id'], "secret": secret}

    def getSubscriptions(self, auth_code, origin):
        if auth_code in ('', None):
            raise Exception(MESSAGE_EMPTY_TENANT)

        if origin in ('', None):
            raise Exception(MESSAGE_EMPTY_TENANT)

        management_token = self.__getManagementToken(auth_code, origin, "/server/azureauthorize")

        subscriptions_data = requests.get(
            f'{AZURE_MANAGEMENT_API}/subscriptions?api-version=2020-01-01',
            headers={
                'Authorization': 'Bearer ' + management_token
            },
            timeout=REQUEST_TIMEOUT
        )

        self.__checkForRestError(subscriptions_data)
        self.__checkForError(subscriptions_data.json())
        subscriptions_data = subscriptions_data.json()

        return subscriptions_data['value']

    def __createCustomRole(self, subscription_id, management_token):
        request_body = {
            "requests": [
                {
                    "content": {
                        "id": f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/8302173b-ccb4-4c73-be66-bc5025da44ab",
                        "properties": {
                            "roleName": APP_NAME,
                            "description": f"Needed permissions for the {APP_NAME} application.",
                            "assignableScopes": [
                                f"/subscriptions/{subscription_id}"
                            ],
                            "permissions": [
                                {
                                    "actions": AZURE_PERMISSIONS,
                                    "notActions": [],
                                    "dataActions": [
                                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
                                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
                                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/move/action",
                                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action"
                                    ],
                                    "notDataActions": []
                                }
                            ]
                        }
                    },
                    "httpMethod": "PUT",
                    "name": "40db2647-1f85-4b4a-b683-6b399265800d",
                    "requestHeaderDetails": {
                        "commandName": "Microsoft_Azure_AD."
                    },
                    "url": f"{AZURE_MANAGEMENT_API}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/8302173b-ccb4-4c73-be66-bc5025da44ab?api-version=2018-01-01-preview"
                }
            ]
        }

        req_data = requests.post(
            f'{AZURE_MANAGEMENT_API}/batch?api-version=2015-11-01',
            json=request_body,
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + management_token
            },
            timeout=REQUEST_TIMEOUT
        )

        self.__checkForRestError(req_data)
        self.__checkForError(req_data.json())
        req_data = req_data.json()

    def __addRoleAssignment(self, subscription_id, principal_id, management_token):

        request_body = {
            "requests": [
                {
                    "content": {
                        "Id": "b0389200-afec-4af8-9a68-62188a511776",
                        "Properties": {
                            "PrincipalId": f"{principal_id}",
                            "RoleDefinitionId": f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/8302173b-ccb4-4c73-be66-bc5025da44ab",
                            "Scope": f"/subscriptions/{subscription_id}"
                        }
                    },
                    "httpMethod": "DELETE",
                    "name": "40db2647-1f85-4b4a-b683-6b399265801c",
                    "requestHeaderDetails": {
                        "commandName": "Microsoft_Azure_AD."
                    },
                    "url": f"{AZURE_MANAGEMENT_API}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments/b0389200-afec-4af8-9a68-62188a511776?api-version=2018-01-01-preview"
                }
            ]
        }

        req_data = requests.post(
            f'{AZURE_MANAGEMENT_API}/batch?api-version=2015-11-01',
            json=request_body,
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + management_token
            },
            timeout=REQUEST_TIMEOUT
        )

        self.__checkForRestError(req_data)
        self.__checkForError(req_data.json())
        req_data = req_data.json()

        max_retries = 24
        wait_seconds = 5
        for i in range(0, max_retries):
            time.sleep(wait_seconds)
            try:
                request_body = {
                    "requests": [
                        {
                            "content": {
                                "Id": "b0389200-afec-4af8-9a68-62188a511776",
                                "Properties": {
                                    "PrincipalId": f"{principal_id}",
                                    "RoleDefinitionId": f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/8302173b-ccb4-4c73-be66-bc5025da44ab",
                                    "Scope": f"/subscriptions/{subscription_id}"
                                }
                            },
                            "httpMethod": "PUT",
                            "name": "40db2647-1f85-4b4a-b683-6b399265801c",
                            "requestHeaderDetails": {
                                "commandName": "Microsoft_Azure_AD."
                            },
                            "url": f"{AZURE_MANAGEMENT_API}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments/b0389200-afec-4af8-9a68-62188a511776?api-version=2018-01-01-preview"
                        }
                    ]
                }

                req_data = requests.post(
                    f'{AZURE_MANAGEMENT_API}/batch?api-version=2015-11-01',
                    json=request_body,
                    headers={
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + management_token
                    },
                    timeout=REQUEST_TIMEOUT
                )

                self.__checkForRestError(req_data)
                self.__checkForError(req_data.json())
                req_data = req_data.json()


            except Exception as e:
                if i == max_retries - 1:
                    raise Exception(e)
                continue
            break


    def createApp(self, auth_code, subscription_id, origin, user):
        if subscription_id in ('', None):
            raise Exception(MESSAGE_EMPTY_SUBSCRIPTION_ID)

        graph_token = self.__getGraphToken()

        # Creates app and secret
        app = self.__createAppWithPass(
            user, graph_token, origin
        )

        service_principal_id = self.__getOrCreateServiceAccount(
            graph_token, app['applicationId'])

        management_token = self.__getManagementToken(
            auth_code,
            origin,
            "/server/azurecreateapp"
        )

        # Create custom role
        self.__createCustomRole(subscription_id, management_token)

        # Assign role
        self.__addRoleAssignment(
            subscription_id=subscription_id,
            principal_id=service_principal_id,
            management_token=management_token
        )

        return {"secret": app['secret'], "applicationId": app['applicationId']}

    @staticmethod
    def getAuthUrlAdminConsent(redirect_uri):
        if redirect_uri in ('', None):
            raise Exception(MESSAGE_EMPTY_REDIRECT_URI)

        auth_url = f'{AZURE_LOGIN_URL}/common/adminconsent?client_id={AZURE_CLIENT_ID}&redirect_uri={redirect_uri}'
        return auth_url

    @staticmethod
    def getAuthUrlAuthorize(redirect_uri, tenant):
        if redirect_uri in ('', None):
            raise Exception(MESSAGE_EMPTY_REDIRECT_URI)
        if tenant in ('', None):
            raise Exception(MESSAGE_EMPTY_TENANT)

        auth_url = f'{AZURE_LOGIN_URL}/{tenant}/oauth2/v2.0/authorize?scope={AZURE_AUTH_SCOPES}&response_type=code&redirect_uri={redirect_uri}&client_id={AZURE_CLIENT_ID}&response_mode=query&state={tenant}'
        return auth_url

    @staticmethod
    def getAuthUrlCreateApp(redirect_uri, tenant, subscription_id):
        if redirect_uri in ('', None):
            raise Exception(MESSAGE_EMPTY_REDIRECT_URI)
        if tenant in ('', None):
            raise Exception(MESSAGE_EMPTY_TENANT)

        auth_url = f'{AZURE_LOGIN_URL}/{tenant}/oauth2/v2.0/authorize?scope={AZURE_AUTH_SCOPES}&response_type=code&redirect_uri={redirect_uri}&client_id={AZURE_CLIENT_ID}&response_mode=query&state={tenant}|{subscription_id}'
        return auth_url

    @staticmethod
    def getGrantAuthUrlAdminConsent(redirect_uri, app_id):
        if redirect_uri in ('', None):
            print("redirect_uri is empty")
            raise Exception(MESSAGE_EMPTY_REDIRECT_URI)

        print("redirect_uri is not empty")
        auth_url = f'{AZURE_LOGIN_URL}/common/adminconsent?client_id={app_id}&redirect_uri={redirect_uri}'
        print("auth_url: " + auth_url)
        return auth_url