
import base64
import json
import pickle

from django.contrib.auth.models import User

from cloudcluster import models
from cloudcluster.models import Profile, CloudAccount
from cloudcluster.settings import GOOGLE_SERVICE_OAUTH_ACCOUNTS_PREFIX
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from cloudcluster.v1_0_0.services.random_string import get_random_lowercase_hex_letters

MESSAGE_EMPTY_ORIGIN = 'origin parameter is empty'
MESSAGE_EMPTY_PROJECT_ID = 'projectId parameter is empty'
SCOPES = ['https://www.googleapis.com/auth/cloud-platform']


class GoogleAuthClient():
    def _modify_policy_add_member(self, policy, role, member):
        """Adds a new member to a role binding."""

        binding = next(b for b in policy["bindings"] if b["role"] == role)
        binding["members"].append(member)
        return policy

    def _create_role_add_member(self, policy, role, member):
        """Adds a new member to a role binding."""
        binding = {
            'role': role,
            'members': [member]
        }
        policy['bindings'].append(binding)
        return policy

    def _create_key(self, service_account_email, creds):
        """Creates a key for a service account."""

        service = build('iam', 'v1', credentials=creds)

        key = service.projects().serviceAccounts().keys().create(
            name='projects/-/serviceAccounts/' + service_account_email,
            body={}
        ).execute()

        return key

    def _delete_keys(self, service_account_email, creds):
        """Creates a key for a service account."""

        service = build('iam', 'v1', credentials=creds)

        request_list = service.projects().serviceAccounts().keys().list(
            name='projects/-/serviceAccounts/' + service_account_email
        )
        response_list = request_list.execute()

        if 'keys' in response_list:
            for key in response_list['keys']:
                if 'keyType' in key:
                    if key['keyType'] != 'SYSTEM_MANAGED':
                        service.projects().serviceAccounts().keys().delete(
                            name=key['name']
                        ).execute()

    def _add_role(self, creds, project_id, sa, role):
        service = build('cloudresourcemanager', 'v1', credentials=creds)

        policy = service.projects().getIamPolicy(
            resource=project_id,
            body={},
        ).execute()

        member = 'serviceAccount:' + sa['email']

        roles = [b['role'] for b in policy['bindings']]

        if role in roles:
            new_policy = self._modify_policy_add_member(policy, role, member)
        else:
            new_policy = self._create_role_add_member(policy, role, member)

        policy = service.projects().setIamPolicy(
            resource=project_id,
            body={
                'policy': new_policy,
            }).execute()

    def _list_service_accounts(self, project_id, creds):
        service = build(
            'iam', 'v1', credentials=creds)

        service_accounts = service.projects().serviceAccounts().list(
            name='projects/' + project_id
        ).execute()

        return service_accounts

    def _getOrCreateServiceAccount(self, creds, project_id, sa_name, sa_display_name):
        service_accounts = self._list_service_accounts(project_id, creds)

        # check if service account is already created
        if 'accounts' in service_accounts:
            for account in service_accounts['accounts']:
                if 'displayName' in account:
                    if account['displayName'] == sa_display_name:
                        return account

        # Create new service account
        service = build('iam', 'v1', credentials=creds)

        new_service_account = service.projects().serviceAccounts().create(
            name='projects/' + project_id,
            body={
                'accountId': sa_name,
                'serviceAccount': {
                    'displayName': sa_display_name
                }
            }).execute()
        return new_service_account

    def get_auth_url_projects(self, origin):
        if origin in ['', None]:
            raise Exception(MESSAGE_EMPTY_ORIGIN)

        flow = InstalledAppFlow.from_client_secrets_file(
            '/var/credentials/creds.json',
            SCOPES
        )

        flow.redirect_uri = origin + '/server/googleoauth'

        auth_url = flow.authorization_url()[0]

        return auth_url

    def create_service_account(self, project_id, user):
        if project_id in ['', None]:
            raise Exception(MESSAGE_EMPTY_PROJECT_ID)

        # Save credentials for the next flow
        profile = Profile.objects.filter(user=user)[0]
        credentials = pickle.loads(profile.google_auth_creds)

        random_string = get_random_lowercase_hex_letters(6)

        sa_name = GOOGLE_SERVICE_OAUTH_ACCOUNTS_PREFIX + '-' + str(user.id) + '-' + random_string

        sa_display_name = GOOGLE_SERVICE_OAUTH_ACCOUNTS_PREFIX + \
            '-' + str(user.id) + '-' + random_string

        sa = self._getOrCreateServiceAccount(
            creds=credentials,
            project_id=project_id,
            sa_name=sa_name,
            sa_display_name=sa_display_name
        )

        roles = ["roles/compute.admin",
                 "roles/dns.admin",
                 "roles/iam.serviceAccountUser",
                 "roles/cloudasset.viewer",
                 "roles/iam.securityReviewer",
                 "roles/storage.admin",
                 ]

        for role in roles:
            self._add_role(credentials, project_id, sa, role)

        # Delete existing keys
        self._delete_keys(sa['email'], credentials)

        key = self._create_key(sa['email'], credentials)

        key_data = json.dumps(json.loads(
            base64.b64decode(key['privateKeyData'])))

        return key_data

    def get_projects(self, code, user, origin):
        if code in ['', None]:
            raise Exception(MESSAGE_EMPTY_ORIGIN)

        flow = InstalledAppFlow.from_client_secrets_file(
            '/var/credentials/creds.json',
            SCOPES
        )

        flow.redirect_uri = origin + '/server/googleoauth'

        flow.fetch_token(code=code)

        credentials = flow.credentials

        service = build('cloudresourcemanager', 'v1', credentials=credentials)

        request = service.projects().list()
        response = request.execute()

        projects = []

        for project in response.get('projects', []):
            projects.append(
                {
                    'name': project['name'],
                    'projectId': project['projectId']
                }
            )

        # Save credentials for the next flow
        profile = Profile.objects.filter(user=user)[0]
        profile.google_auth_creds = pickle.dumps(credentials)
        profile.save()

        return projects
