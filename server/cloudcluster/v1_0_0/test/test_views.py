import datetime
import json
import logging
import os
import base64
import tempfile
import time
import django

from mock import MagicMock, patch

import pathlib

from cloudcluster import models
from cloudcluster.models import (Clusters, ClusterService, ClusterUser,
                                 EnvironmentTemplate, Machine,
                                 CloudAccount, Profile, Service, ServiceCategory)
from django.contrib.auth.models import User
from django.core import mail
from django.test import Client, TestCase
from django.urls import resolve

from .. import tasks
from ..services import authorization_service
from ..test.mock_funcs import (func_no_return, func_return_list,
                               func_returns_false, func_returns_none,
                               func_returns_number, func_with_exception,
                               func_worker_validate_credentials)

VERSION = str(pathlib.Path(__file__).parent.absolute().parent.name)

@django.test.utils.override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
class ApplicationForRegistration(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

    def test_applicationforregistration_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/applicationform')
        response_body = response.content.decode()

        resolver = resolve('/applicationform')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.application_for_registration')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)


    def test_applicationforregistration_short_first_name_returns_400(self):
        self.client = Client()
        first_name = "p"
        last_name = "Lastname"
        company_name = "Company name"
        phone_number = "0888222222"
        email = "testmail@test.test"

        request_body = json.dumps(
            {
                "first_name": first_name, "last_name": last_name, "company_name": company_name, "phone_number": phone_number, "email": email
            }
        )
        expected_response_body = '{"error": {"message": "\'' + first_name + '\' is too short"}}'

        response = self.client.post('/applicationform', request_body, content_type='application/json')
        response_body = response.content.decode()

        resolver = resolve('/applicationform')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.application_for_registration')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_applicationforregistration_long_first_name_returns_400(self):
        self.client = Client()
        first_name = "test" * 50
        last_name = "Lastname"
        company_name = "Company name"
        phone_number = "0888222222"
        email = "testmail@test.test"

        request_body = json.dumps(
            {
                "first_name": first_name, "last_name": last_name, "company_name": company_name, "phone_number": phone_number, "email": email
            }
        )
        expected_response_body = '{"error": {"message": "\'' + first_name + '\' is too long"}}'

        response = self.client.post('/applicationform', request_body, content_type='application/json')
        response_body = response.content.decode()

        resolver = resolve('/applicationform')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.application_for_registration')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_applicationforregistration_short_last_name_returns_400(self):
        self.client = Client()
        first_name = "Firstname"
        last_name = "l"
        company_name = "Company name"
        phone_number = "0888222222"
        email = "testmail@test.test"

        request_body = json.dumps(
            {
                "first_name": first_name, "last_name": last_name, "company_name": company_name, "phone_number": phone_number, "email": email
            }
        )
        expected_response_body = '{"error": {"message": "\'' + last_name + '\' is too short"}}'

        response = self.client.post('/applicationform', request_body, content_type='application/json')
        response_body = response.content.decode()

        resolver = resolve('/applicationform')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.application_for_registration')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_applicationforregistration_long_last_name_returns_400(self):
        self.client = Client()
        first_name = "Firstname"
        last_name = "test" * 50
        company_name = "Company name"
        phone_number = "0888222222"
        email = "testmail@test.test"

        request_body = json.dumps(
            {
                "first_name": first_name, "last_name": last_name, "company_name": company_name, "phone_number": phone_number, "email": email
            }
        )
        expected_response_body = '{"error": {"message": "\'' + last_name + '\' is too long"}}'

        response = self.client.post('/applicationform', request_body, content_type='application/json')
        response_body = response.content.decode()

        resolver = resolve('/applicationform')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.application_for_registration')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_applicationforregistration_short_company_name_returns_400(self):
        self.client = Client()
        first_name = "Firstname"
        last_name = "Lastname"
        company_name = "c"
        phone_number = "0888222222"
        email = "testmail@test.test"

        request_body = json.dumps(
            {
                "first_name": first_name, "last_name": last_name, "company_name": company_name, "phone_number": phone_number, "email": email
            }
        )
        expected_response_body = '{"error": {"message": "\'' + company_name + '\' is too short"}}'

        response = self.client.post('/applicationform', request_body, content_type='application/json')
        response_body = response.content.decode()

        resolver = resolve('/applicationform')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.application_for_registration')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_applicationforregistration_long_company_name_returns_400(self):
        self.client = Client()
        first_name = "Firstname"
        last_name = "Lastname"
        company_name = "test" * 100
        phone_number = "0888222222"
        email = "testmail@test.test"

        request_body = json.dumps(
            {
                "first_name": first_name, "last_name": last_name, "company_name": company_name, "phone_number": phone_number, "email": email
            }
        )
        expected_response_body = '{"error": {"message": "\'' + company_name + '\' is too long"}}'

        response = self.client.post('/applicationform', request_body, content_type='application/json')
        response_body = response.content.decode()

        resolver = resolve('/applicationform')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.application_for_registration')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_applicationforregistration_short_phone_number_returns_400(self):
        self.client = Client()
        first_name = "Firstname"
        last_name = "Lastname"
        company_name = "Company name"
        phone_number = "0"
        email = "testmail@test.test"

        request_body = json.dumps(
            {
                "first_name": first_name, "last_name": last_name, "company_name": company_name, "phone_number": phone_number, "email": email
            }
        )
        expected_response_body = '{"error": {"message": "\'' + phone_number + '\' is too short"}}'

        response = self.client.post('/applicationform', request_body, content_type='application/json')
        response_body = response.content.decode()

        resolver = resolve('/applicationform')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.application_for_registration')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_applicationforregistration_long_phone_number_returns_400(self):
        self.client = Client()
        first_name = "Firstname"
        last_name = "Lastname"
        company_name = "Company name"
        phone_number = "0888222222" * 15
        email = "testmail@test.test"

        request_body = json.dumps(
            {
                "first_name": first_name, "last_name": last_name, "company_name": company_name, "phone_number": phone_number, "email": email
            }
        )
        expected_response_body = '{"error": {"message": "\'' + phone_number + '\' is too long"}}'

        response = self.client.post('/applicationform', request_body, content_type='application/json')
        response_body = response.content.decode()

        resolver = resolve('/applicationform')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.application_for_registration')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_applicationforregistration_invalid_phone_number_returns_400(self):
        self.client = Client()
        first_name = "Firstname"
        last_name = "Lastname"
        company_name = "Company name"
        phone_number = "invalid"
        email = "testmail@test.test"

        request_body = json.dumps(
            {
                "first_name": first_name, "last_name": last_name, "company_name": company_name, "phone_number": phone_number, "email": email
            }
        )
        expected_response_body = '{"error": {"message": "\'' + phone_number + '\' does not match \'^[+]*[(]{0,1}[0-9]{1,4}[)]{0,1}[-\\\\\\\s\\\\\\\./0-9]*$\'"}}'

        response = self.client.post('/applicationform', request_body, content_type='application/json')
        response_body = response.content.decode()

        resolver = resolve('/applicationform')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.application_for_registration')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_applicationforregistration_long_email_returns_400(self):
        self.client = Client()
        first_name = "Firstname"
        last_name = "Lastname"
        company_name = "Company name"
        phone_number = "0888222222"
        email = "testmail" * 50 + "@test.test"

        request_body = json.dumps(
            {
                "first_name": first_name, "last_name": last_name, "company_name": company_name, "phone_number": phone_number, "email": email
            }
        )
        expected_response_body = '{"error": {"message": "\'' + email + '\' is too long"}}'

        response = self.client.post('/applicationform', request_body, content_type='application/json')
        response_body = response.content.decode()

        resolver = resolve('/applicationform')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.application_for_registration')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_applicationforregistration_invalid_email_returns_400(self):
        self.client = Client()
        first_name = "Firstname"
        last_name = "Lastname"
        company_name = "Company name"
        phone_number = "0888222222"
        email = "invalid"

        request_body = json.dumps(
            {
                "first_name": first_name, "last_name": last_name, "company_name": company_name, "phone_number": phone_number, "email": email
            }
        )
        expected_response_body = '{"error": {"message": "\'' + email + '\' does not match \'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\\\\\\\.[a-zA-Z0-9-.]+$\'"}}'

        response = self.client.post('/applicationform', request_body, content_type='application/json')
        response_body = response.content.decode()

        resolver = resolve('/applicationform')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.application_for_registration')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_applicationforregistration_valid_returns_200(self):
        self.client = Client()
        first_name = "Firstname"
        last_name = "Lastname"
        company_name = "Company name"
        phone_number = "0888222222"
        email = "testmail@test.test"

        request_body = json.dumps(
            {
                "first_name": first_name, "last_name": last_name, "company_name": company_name, "phone_number": phone_number, "email": email
            }
        )

        response = self.client.post('/applicationform', request_body, content_type='application/json')

        resolver = resolve('/applicationform')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.application_for_registration')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['testmail@test.test'])
        self.assertEqual(mail.outbox[0].subject, 'Application for registration')
        self.assertEqual(mail.outbox[0].body, 'Your application has been sent.\nAfter processing it we will contact you.')


class GetClusterDetails(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True
        self.maxDiff = None

        tfconfig = json.dumps({
            "kubernetesConfiguration": {
                "version": "v1.19.7",
                "serviceAddresses": "192.168.0.0/24",
                "podsSubnet": "192.168.1.0/24",
                "networkPlugin": "flannel"
            },
            "alicloudSelected": True,
            "awsSelected": True,
            "googleSelected": True,
            "azureSelected": True,
            "azure": {
                "account": "test",
                "region": "region",
                "zone": "zone",
                "instances": ["instanceType"],
                "operatingSystem": "ubuntu-bionic-18.04",
                "vpcCidr": "10.10.0.0/16"
            },
            "google": {
                "account": "test",
                "region": "region",
                "zone": "zone",
                "instances": ["instanceType"],
                "operatingSystem": "ubuntu-bionic-18.04",
                "vpcCidr": "10.20.0.0/16"
            },
            "aws": {
                "account": "test",
                "region": "region",
                "zone": "zone",
                "instances": ["instanceType"],
                "operatingSystem": "ubuntu-bionic-18.04",
                "vpcCidr": "10.30.0.0/16"
            },
            "alicloud": {
                "account": "test",
                "region": "region",
                "zone": "zone",
                "instances": ["instanceType"],
                "operatingSystem": "ubuntu-bionic-18.04",
                "vpcCidr": "10.0.0.0/16"
            }
        })

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        self.cluster = Clusters(
            name='testCluster',
            user=self.user,
            type=1,
            installstep=0,
            title='title',
            tfconfig=tfconfig,
            resources=('{"google compute address": 1, "google compute firewall": 1, "google compute instance": 1,' + 
            ' "google compute network": 1, "google compute subnetwork": 1}')
        )
        self.cluster.save()

        self.clusterID = str(self.cluster.id)

    def test_get_cluster_details_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/getClusterDetails')

        resolver = resolve('/getClusterDetails')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_details')
        self.assertEqual(response.status_code, 401)

    def test_get_cluster_details_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/getClusterDetails', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getClusterDetails')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_details')
        self.assertEqual(response.status_code, 401)

    def test_get_cluster_details_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/getClusterDetails', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterDetails')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_details')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_cluster_details_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID1": ""
            }
        )
        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/getClusterDetails', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterDetails')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_details')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_cluster_details_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = 'd123123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID
            }
        )
        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/getClusterDetails', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterDetails')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_details')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_cluster_details_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1234567891123456789112345678911234567'
        request_body = json.dumps(
            {
                "clusterID": long_clusterID
            }
        )
        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/getClusterDetails', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterDetails')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_details')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_cluster_details_invalid_UUID_clusterID_returns_500(self):
        self.client = Client()

        wrong_clusterID = '123456789112345678911234567891123456'
        request_body = json.dumps(
            {
                "clusterID": wrong_clusterID
            }
        )
        expected_response_body = '{"error": {"message": "Invalid parameter clusterID"}}'

        response = self.client.post('/getClusterDetails', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterDetails')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_details')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_cluster_details_clusterID_of_not_existing_cluster_returns_500(self):
        self.client = Client()

        wrong_clusterID = '00000000-0000-0000-0000-000000000000'
        request_body = json.dumps(
            {
                "clusterID": wrong_clusterID
            }
        )
        expected_response_body = '{"error": {"message": "Invalid parameter clusterID"}}'

        response = self.client.post('/getClusterDetails', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterDetails')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_details')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    # def test_get_cluster_details_no_cluster_machines_returns_500(self):
    #     self.client = Client()

    #     request_body = json.dumps(
    #         {
    #             "clusterID": self.clusterID
    #         }
    #     )
    #     expected_response_body = '{"error": {"message": "Internal Server Error"}}'

    #     response = self.client.post('/getClusterDetails', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
    #     response_body = response.content.decode()

    #     resolver = resolve('/getClusterDetails')

    #     self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_details')
    #     self.assertEqual(expected_response_body, response_body)
    #     self.assertEqual(response.status_code, 500)

    def test_get_cluster_details_correct_installstep_1_returns_200(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.installstep = 1
        cluster.save()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )
        expected_response_body = '''{'name': 'testCluster', 'title': 'title', 'status': 0, 'resizestep': 0, 'clusterType': 1, 'loadBalancerIntegration': '', 'providers': {}, 'resources': {'google compute address': 1, 'google compute firewall': 1, 'google compute instance': 1, 'google compute network': 1, 'google compute subnetwork': 1}, 'usersList': [], 'machinesList': [], 'hasLoadBalancerIntegration': False, 'serviceList': [], 'grafana_admin_password': '', 'grafana_address': None, 'es_admin_password': '', 'kibana_address': None, 'kubernetesConfiguration': {'version': 'v1.19.7', 'networkPlugin': 'flannel', 'podsSubnet': '192.168.1.0/24', 'serviceAddresses': '192.168.0.0/24'}, 'kubeUpgradeStatus': 0}'''
        expected_response_body = str(expected_response_body)

        response = self.client.post('/getClusterDetails', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = str(json.loads(response.content.decode()))

        resolver = resolve('/getClusterDetails')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_details')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)

    def test_get_cluster_details_correct_no_users_returns_200(self):
        self.client = Client()

        machine = Machine(
            cluster=self.cluster, name='testMachine', type='testType', publicIP='0.0.0.0', provider='google',
            region='testRegion', zone='testZone', cpu=1, ram=1, hdd=1
        )
        machine.save()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )
        expected_response_body = '''{'name': 'testCluster', 'title': 'title', 'status': 0, 'resizestep': 0, 'clusterType': 1, 'loadBalancerIntegration': '', 'providers': {'googleSelected': True, 'google': {'region': 'testRegion', 'zone': 'testZone', 'vpcCidr': '10.20.0.0/16', 'accountLabel': 'test'}}, 'resources': {'google compute address': 1, 'google compute firewall': 1, 'google compute instance': 1, 'google compute network': 1, 'google compute subnetwork': 1}, 'usersList': [], 'machinesList': [{'name': 'testMachine', 'type': 'testType', 'publicIP': '0.0.0.0', 'privateIP': None, 'provider': 'google', 'region': 'testRegion', 'zone': 'testZone', 'operating_system': None, 'status': 0, 'cpu': 1, 'ram': 1, 'hdd': 1, 'network': '10.20.0.0/16'}], 'hasLoadBalancerIntegration': False, 'serviceList': [], 'grafana_admin_password': '', 'grafana_address': None, 'es_admin_password': '', 'kibana_address': None, 'kubernetesConfiguration': {'version': 'v1.19.7', 'networkPlugin': 'flannel', 'podsSubnet': '192.168.1.0/24', 'serviceAddresses': '192.168.0.0/24'}, 'kubeUpgradeStatus': 0}'''
        expected_response_body = str(expected_response_body)

        response = self.client.post('/getClusterDetails', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = str(json.loads(response.content.decode()))

        resolver = resolve('/getClusterDetails')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_details')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)

    def test_get_cluster_details_correct_with_users_returns_200(self):
        self.client = Client()

        machine = Machine(
            cluster=self.cluster, name='testMachine', type='testType', publicIP='0.0.0.0', provider='google',
            region='testRegion', zone='testZone', cpu=1, ram=1, hdd=1
        )
        machine.save()
        cluster_user = ClusterUser(
            cluster=self.cluster, username='username', first_name='first_name', last_name='last_name', type='user', status=0, kubernetes_user=False
        )
        cluster_user.save()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )
        expected_response_body = '''{'name': 'testCluster', 'title': 'title', 'status': 0, 'resizestep': 0, 'clusterType': 1, 'loadBalancerIntegration': '', 'providers': {'googleSelected': True, 'google': {'region': 'testRegion', 'zone': 'testZone', 'vpcCidr': '10.20.0.0/16', 'accountLabel': 'test'}}, 'resources': {'google compute address': 1, 'google compute firewall': 1, 'google compute instance': 1, 'google compute network': 1, 'google compute subnetwork': 1}, 'usersList': [{'username': 'username', 'first_name': 'first_name', 'last_name': 'last_name', 'public_ssh_key': None, 'type': 'user', 'status': 0}], 'machinesList': [{'name': 'testMachine', 'type': 'testType', 'publicIP': '0.0.0.0', 'privateIP': None, 'provider': 'google', 'region': 'testRegion', 'zone': 'testZone', 'operating_system': None, 'status': 0, 'cpu': 1, 'ram': 1, 'hdd': 1, 'network': '10.20.0.0/16'}], 'hasLoadBalancerIntegration': False, 'serviceList': [], 'grafana_admin_password': '', 'grafana_address': None, 'es_admin_password': '', 'kibana_address': None, 'kubernetesConfiguration': {'version': 'v1.19.7', 'networkPlugin': 'flannel', 'podsSubnet': '192.168.1.0/24', 'serviceAddresses': '192.168.0.0/24'}, 'kubeUpgradeStatus': 0}'''
        expected_response_body = str(expected_response_body)

        response = self.client.post('/getClusterDetails', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = str(json.loads(response.content.decode()))

        resolver = resolve('/getClusterDetails')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_details')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)

class GetClusterTfCode(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True
        self.maxDiff = None

        tfconfig = json.dumps({
            "kubernetesConfiguration": {
                "version": "v1.19.7",
                "serviceAddresses": "192.168.0.0/24",
                "podsSubnet": "192.168.1.0/24",
                "networkPlugin": "flannel"
            },
            "alicloudSelected": True,
            "awsSelected": True,
            "googleSelected": True,
            "azureSelected": True,
            "azure": {
                "account": "test",
                "region": "region",
                "zone": "zone",
                "instances": ["instanceType"],
                "operatingSystem": "ubuntu-bionic-18.04",
                "vpcCidr": "10.10.0.0/16"
            },
            "google": {
                "account": "test",
                "region": "region",
                "zone": "zone",
                "instances": ["instanceType"],
                "operatingSystem": "ubuntu-bionic-18.04",
                "vpcCidr": "10.20.0.0/16"
            },
            "aws": {
                "account": "test",
                "region": "region",
                "zone": "zone",
                "instances": ["instanceType"],
                "operatingSystem": "ubuntu-bionic-18.04",
                "vpcCidr": "10.30.0.0/16"
            },
            "alicloud": {
                "account": "test",
                "region": "region",
                "zone": "zone",
                "instances": ["instanceType"],
                "operatingSystem": "ubuntu-bionic-18.04",
                "vpcCidr": "10.0.0.0/16"
            }
        })

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        self.cluster = Clusters(
            name='testCluster',
            user=self.user,
            type=1,
            installstep=0,
            title='title',
            tfconfig=tfconfig,
            tfcode='tfcode',
            resources=('{"google compute address": 1, "google compute firewall": 1, "google compute instance": 1,' + 
            ' "google compute network": 1, "google compute subnetwork": 1}')
        )
        self.cluster.save()

        self.clusterID = str(self.cluster.id)

    def test_get_cluster_tfcode_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/getClusterTfCode')

        resolver = resolve('/getClusterTfCode')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_tfcode')
        self.assertEqual(response.status_code, 401)

    def test_get_cluster_tfcode_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/getClusterTfCode', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getClusterTfCode')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_tfcode')
        self.assertEqual(response.status_code, 401)

    def test_get_cluster_tfcode_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/getClusterTfCode', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterTfCode')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_tfcode')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_cluster_tfcode_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID1": ""
            }
        )
        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/getClusterTfCode', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterTfCode')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_tfcode')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_cluster_tfcode_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = 'd123123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID
            }
        )
        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/getClusterTfCode', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterTfCode')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_tfcode')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_cluster_tfcode_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1234567891123456789112345678911234567'
        request_body = json.dumps(
            {
                "clusterID": long_clusterID
            }
        )
        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/getClusterTfCode', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterTfCode')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_tfcode')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_cluster_tfcode_invalid_UUID_clusterID_returns_500(self):
        self.client = Client()

        wrong_clusterID = '123456789112345678911234567891123456'
        request_body = json.dumps(
            {
                "clusterID": wrong_clusterID
            }
        )
        expected_response_body = '{"error": {"message": "Invalid parameter clusterID"}}'

        response = self.client.post('/getClusterTfCode', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterTfCode')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_tfcode')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_cluster_tfcode_clusterID_of_not_existing_cluster_returns_500(self):
        self.client = Client()

        wrong_clusterID = '00000000-0000-0000-0000-000000000000'
        request_body = json.dumps(
            {
                "clusterID": wrong_clusterID
            }
        )
        expected_response_body = '{"error": {"message": "Invalid parameter clusterID"}}'

        response = self.client.post('/getClusterTfCode', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterTfCode')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_tfcode')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_cluster_tfcode_correct_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )
        expected_response_body = '''{'tfcode': 'tfcode'}'''
        expected_response_body = str(expected_response_body)

        response = self.client.post('/getClusterTfCode', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = str(json.loads(response.content.decode()))

        resolver = resolve('/getClusterTfCode')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_tfcode')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class GetUserInfo(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1,
            first_name='first_name', last_name='last_name')

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            credentials = json.dumps({'google_key': 'google_key'}),
            user=self.user
        )
        google_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            credentials=json.dumps({
            'aws_access_key_id': 'aws_access_key_id',
            'aws_secret_access_key': 'aws_secret_access_key'
            }),
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            credentials=json.dumps({
            'azure_tenant_id': 'azure_tenant_id',
            'azure_subscription_id': 'azure_subscription_id',
            'azure_client_id': 'azure_client_id',
            'azure_client_secret': 'azure_client_secret',
            }),
            user=self.user
        )
        self.azure_account.save()
        self.onPremise_account = CloudAccount(
            provider = 'onpremise',
            label='accountLabel',
            credentials=json.dumps({
            'gw_public_ip': 'gw_public_ip',
            'gw_private_ip': 'gw_private_ip',
            'admin_username': 'admin_username',
            'admin_private_key': 'admin_private_key',
            }),
            user=self.user
        )
        self.onPremise_account.save()

        self.iotArm_account = CloudAccount(
            provider = 'iotarm',
            label='accountLabel',
            credentials=json.dumps({
            'gw_public_ip': 'gw_public_ip',
            'gw_private_ip': 'gw_private_ip',
            'admin_username': 'admin_username',
            'admin_private_key': 'admin_private_key',
            }),
            user=self.user
        )
        self.iotArm_account.save()

    def test_get_user_info_no_authorization_headers(self):
        self.client = Client()

        response = self.client.get('/getUserInfo')

        resolver = resolve('/getUserInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_info')
        self.assertEqual(response.status_code, 401)

    def test_get_user_info_invalid_credentials(self):
        self.client = Client()

        response = self.client.get('/getUserInfo', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getUserInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_info')
        self.assertEqual(response.status_code, 401)

    def test_get_user_info_valid_returns_200(self):
        self.client = Client()

        expected_response_body = '{"profile": {"first_name": "first_name", "last_name": "last_name", "timezone": "UTC", "email": ""}, "username": "testuser", "id": 1}'

        response = self.client.get('/getUserInfo', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getUserInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_info')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class GetCloudCredentials(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True
        self.maxDiff = None


        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1,
            first_name='first_name', last_name='last_name')

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            credentials=json.dumps({'google_key': json.dumps({"type": "type","project_id": "project_id","private_key_id": "private_key_id"})}),
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel1',
            credentials=json.dumps({
            'alicloud_access_key': 'alicloud_access_key',
            'alicloud_secret_key': 'alicloud_secret_key',
            }),
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel2',
            credentials=json.dumps({
            'aws_access_key_id': 'aws_access_key_id',
            'aws_secret_access_key': 'aws_secret_access_key',
            }),
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel3',
            credentials=json.dumps({
            'azure_tenant_id': 'azure_tenant_id',
            'azure_subscription_id': 'azure_subscription_id',
            'azure_client_id': 'azure_client_id',
            'azure_client_secret': 'azure_client_secret',
            }),
            user=self.user
        )
        self.azure_account.save()
        self.onPremise_account = CloudAccount(
            provider = 'onpremise',
            label='accountLabel4',
            credentials=json.dumps({
            'gw_public_ip': 'gw_public_ip',
            'gw_private_ip': 'gw_private_ip',
            'admin_username': 'admin_username',
            'admin_private_key': 'admin_private_key',
            }),
            user=self.user
        )
        self.onPremise_account.save()

        self.iotArm_account = CloudAccount(
            provider = 'iotarm',
            label='accountLabel4',
            credentials=json.dumps({
            'gw_public_ip': 'gw_public_ip',
            'gw_private_ip': 'gw_private_ip',
            'admin_username': 'admin_username',
            'admin_private_key': 'admin_private_key',
            }),
            user=self.user
        )
        self.iotArm_account.save()

    def test_get_cloud_credentials_no_authorization_headers(self):
        self.client = Client()

        response = self.client.get('/getCloudCredentials')

        resolver = resolve('/getCloudCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cloud_credentials')
        self.assertEqual(response.status_code, 401)

    def test_get_cloud_credentials_invalid_credentials(self):
        self.client = Client()

        response = self.client.get('/getCloudCredentials', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getCloudCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cloud_credentials')
        self.assertEqual(response.status_code, 401)

    def test_get_cloud_credentials_valid_returns_200(self):
        self.client = Client()
        alicloud_created_at = CloudAccount.objects.filter(provider='alicloud')[0].created_at
        aws_created_at = CloudAccount.objects.filter(provider='aws')[0].created_at
        google_created_at = CloudAccount.objects.filter(provider='google')[0].created_at
        azure_created_at = CloudAccount.objects.filter(provider='azure')[0].created_at
        onpremise_created_at = CloudAccount.objects.filter(provider='onpremise')[0].created_at
        iotarm_created_at = CloudAccount.objects.filter(provider='iotarm')[0].created_at

        expected_response_body = '{"credentials": [{"type": "google", "id": 1, "created_at": "' + str(google_created_at) + '", "label": "accountLabel", "has_associated_environments": false}, {"type": "alicloud", "id": 2, "created_at": "' + str(alicloud_created_at) + '", "label": "accountLabel1", "has_associated_environments": false}, {"type": "aws", "id": 3, "created_at": "' + str(aws_created_at) + '", "label": "accountLabel2", "has_associated_environments": false}, {"type": "azure", "id": 4, "created_at": "' + str(azure_created_at) + '", "label": "accountLabel3", "has_associated_environments": false}, {"type": "onpremise", "id": 5, "created_at": "' + str(onpremise_created_at) + '", "label": "accountLabel4", "has_associated_environments": false}, {"type": "iotarm", "id": 6, "created_at": "' + str(iotarm_created_at) + '", "label": "accountLabel4", "has_associated_environments": false}]}'

        response = self.client.get('/getCloudCredentials', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getCloudCredentials')

        print(expected_response_body)
        print('1234414141413413')
        print(response_body)

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cloud_credentials')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)

class AddUserToCluster(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        self.cluster = Clusters(
            name='testCluster',
            user=self.user,
            kubeconfig = '''apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: test
    server: https://11.11.11.11:6443
  name: cluster.local
contexts:
- context:
    cluster: cluster.local
    user: test
  name: kubernetes
current-context: kubernetes
kind: Config
preferences: {}
users:
- name: test
  user:
    token: test:test
'''
        )
        self.cluster.save()

        self.clusterID = str(self.cluster.id)

    def test_add_user_to_cluster_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/addUserToCluster')

        resolver = resolve('/addUserToCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
        self.assertEqual(response.status_code, 401)

    def test_add_user_to_cluster_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/addUserToCluster', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/addUserToCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
        self.assertEqual(response.status_code, 401)

    def test_add_user_to_cluster_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/addUserToCluster', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addUserToCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_user_to_cluster_too_long_parameter_firstName_returns_400(self):
        self.client = Client()

        long_firstName = '1234567891123456789112345678911234567'
        request_body = json.dumps(
            {
                "kubernetesUser": False, "username": "username", "firstName": long_firstName, "lastName": "lastName", "type": "user", "email": "email", "publicSSHKey": "publicSSHKey", "clusterID": "clusterID"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_firstName + '\' is too long", "code": 1000}}'

        response = self.client.post('/addUserToCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addUserToCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_user_to_cluster_too_long_parameter_lastName_returns_400(self):
        self.client = Client()

        long_lastName = '1234567891123456789112345678911234567'
        request_body = json.dumps(
            {
                "kubernetesUser": False, "username": "username", "firstName": "firstName", "lastName": long_lastName, "type": "user", "email": "email", "publicSSHKey": "publicSSHKey", "clusterID": "clusterID"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_lastName + '\' is too long", "code": 1000}}'

        response = self.client.post('/addUserToCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addUserToCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_user_to_cluster_too_long_parameter_email_returns_400(self):
        self.client = Client()

        long_email = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911@test.com'
        request_body = json.dumps(
            {
                "kubernetesUser": False, "username": "username", "firstName": "firstName", "lastName": "lastName", "type": "user", "email": long_email, "publicSSHKey": "publicSSHKey", "clusterID": "clusterID"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_email + '\' is too long", "code": 1000}}'

        response = self.client.post('/addUserToCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addUserToCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_user_to_cluster_missing_parameter_publicSSHKey_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "kubernetesUser": False, "username": "username", "firstName": "firstName", "lastName": "lastName", "type": "user", "email": "email", "clusterID": "clusterID"
            }
        )

        expected_response_body = '{"error": {"message": "\'publicSSHKey\' is a required property", "code": 1000}}'

        response = self.client.post('/addUserToCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addUserToCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_user_to_cluster_too_short_parameter_publicSSHKey_returns_400(self):
        self.client = Client()

        short_publicSSHKey = '1'
        request_body = json.dumps(
            {
                "kubernetesUser": False, "username": "username", "firstName": "firstName", "lastName": "lastName", "type": "user", "email": "test@test.com", "publicSSHKey": short_publicSSHKey, "clusterID": "clusterID"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_publicSSHKey + '\' is too short", "code": 1000}}'

        response = self.client.post('/addUserToCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addUserToCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_user_to_cluster_too_long_parameter_publicSSHKey_returns_400(self):
        self.client = Client()

        long_publicSSHKey = 'AAAAB3NzaC1yc2E' + ('1' * 10000) + '1'
        request_body = json.dumps(
            {
                "kubernetesUser": False, "username": "username", "firstName": "firstName", "lastName": "lastName", "type": "user", "email": "test@test.com", "publicSSHKey": long_publicSSHKey, "clusterID": "clusterID112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_publicSSHKey + '\' is too long", "code": 1000}}'

        response = self.client.post('/addUserToCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addUserToCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_user_to_cluster_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "kubernetesUser": False, "username": "username", "firstName": "firstName", "lastName": "lastName", "type": "user", "email": "test@test.com", "publicSSHKey": "publicSSHKey"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property", "code": 1000}}'

        response = self.client.post('/addUserToCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addUserToCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_user_to_cluster_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '1'
        request_body = json.dumps(
            {
                "kubernetesUser": False, "username": "username", "firstName": "firstName", "lastName": "lastName", "type": "user", "email": "test@test.com", "publicSSHKey": "AAAAB3NzaC1yc2Etesttesttesttest", "clusterID": short_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short", "code": 1000}}'

        response = self.client.post('/addUserToCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addUserToCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_user_to_cluster_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '123456789112345678911234567891123456789112345678911'
        request_body = json.dumps(
            {
                "kubernetesUser": False, "username": "username", "firstName": "firstName", "lastName": "lastName", "type": "user", "email": "test@test.com", "publicSSHKey": "AAAAB3NzaC1yc2Etesttesttesttest", "clusterID": long_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long", "code": 1000}}'

        response = self.client.post('/addUserToCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addUserToCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_user_to_cluster_invalid_UUID_clusterID_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "kubernetesUser": False, "username": "username", "firstName": "firstName", "lastName": "lastName", "type": "user", "email": "test@test.com", "publicSSHKey": "AAAAB3NzaC1yc2Etesttesttesttest", "clusterID": "123456789112345678911234567891123456"
            }
        )
        expected_response_body = '{"error": {"message": "Invalid parameter clusterID", "code": 1001}}'

        response = self.client.post('/addUserToCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addUserToCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_add_user_to_cluster_clusterID_of_not_existing_cluster_returns_500(self):
        self.client = Client()

        wrong_clusterID = '00000000-0000-0000-0000-000000000000'
        request_body = json.dumps(
            {
                "kubernetesUser": False, "username": "username", "firstName": "firstName", "lastName": "lastName", "type": "user", "email": "test@test.com", "publicSSHKey": "AAAAB3NzaC1yc2Etesttesttesttest", "clusterID": wrong_clusterID
            }
        )
        expected_response_body = '{"error": {"message": "Invalid parameter clusterID", "code": 1001}}'

        response = self.client.post('/addUserToCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addUserToCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)
    
    def test_add_user_to_cluster_clusterID_of_not_runing_cluster_returns_500(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.status = 10
        cluster.save()
        request_body = json.dumps(
            {
                "kubernetesUser": False, "username": "username", "firstName": "firstName", "lastName": "lastName", "type": "type", "email": "email12@test.com", "publicSSHKey": "AAAAB3NzaC1yc2Etesttesttesttest", "clusterID": self.clusterID
            }
        )
        expected_response_body = '{"error": {"message": "Cluster is not running."}}'

        response = self.client.post('/addUserToCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addUserToCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_add_user_to_cluster_no_user_with_same_name_valid_returns_200(self):
        self.client = Client()

        expected_call_args = 'call({\'kubernetesUser\': False, \'firstName\': \'firstName\', \'lastName\': \'lastName\', \'type\': \'type\', '
        expected_call_args += '\'email\': \'test@test.com\', \'publicSSHKey\': \'AAAAB3NzaC1yc2Etesttesttesttest\', \'clusterID\': '
        expected_call_args += '\'' + self.clusterID + '\', \'username\': \'flastname\'}'
        expected_call_args += ', UUID(\'' + self.clusterID + '\'))'
        request_body = json.dumps(
            {
                "kubernetesUser": False, "username": "username", "firstName": "firstName", "lastName": "lastName", "type": "user", "email": "test@test.com", "publicSSHKey": "AAAAB3NzaC1yc2Etesttesttesttest", "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"submitted": true}'

        with patch.object(tasks.worker_create_cluster_user, 'delay') as mock:
            with patch.object(authorization_service, 'Authorize') as authorize_mock:
                authorize_mock.side_effect = func_returns_none
                mock.side_effect = func_worker_validate_credentials

                response = self.client.post('/addUserToCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
                response_body = response.content.decode()

                resolver = resolve('/addUserToCluster')

                mock.assert_called()
                # self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
                self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
                self.assertEqual(response.status_code, 200)
                # self.assertEqual(expected_response_body, response_body)

    def test_add_user_to_cluster_user_with_same_name_valid_returns_200(self):
        self.client = Client()
        cluster_user_with_same_name = ClusterUser(
            cluster=self.cluster, username='flastname', first_name='firstName', last_name='lastName', kubernetes_user=False
        )
        cluster_user_with_same_name.save()

        expected_call_args = 'call({\'kubernetesUser\': False, \'username\': \'username\', \'firstName\': \'firstName\', \'lastName\': \'lastName\', \'type\': \'type\', '
        expected_call_args += '\'email\': \'test@test.com\', \'publicSSHKey\': \'AAAAB3NzaC1yc2Etesttesttesttest\', \'clusterID\': '
        expected_call_args += '\'' + self.clusterID + '\', \'username\': \'flastname1\'}'
        expected_call_args += ', UUID(\'' + self.clusterID + '\'))'
        request_body = json.dumps(
            {
                "kubernetesUser": False, "username": "username", "firstName": "firstName", "lastName": "lastName", "type": "user", "email": "test@test.com", "publicSSHKey": "AAAAB3NzaC1yc2Etesttesttesttest", "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"submitted": true}'

        with patch.object(tasks.worker_create_cluster_user, 'delay') as mock:
            with patch.object(authorization_service, 'Authorize') as authorize_mock:
                authorize_mock.side_effect = func_returns_none
                mock.side_effect = func_worker_validate_credentials

                response = self.client.post('/addUserToCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
                response_body = response.content.decode()

                resolver = resolve('/addUserToCluster')

                mock.assert_called()
                # self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
                self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
                # self.assertEqual(response.status_code, 200)
                # self.assertEqual(expected_response_body, response_body)

    def test_add_user_to_cluster_user_with_same_name_and_deleted_user_with_same_name_valid_returns_200(self):
        self.client = Client()
        cluster_user_with_same_name = ClusterUser(
            cluster=self.cluster, username='flastname', first_name='firstName', last_name='lastName', kubernetes_user=False
        )
        cluster_user_with_same_name.save()
        cluster_user_with_same_name2 = ClusterUser(
            cluster=self.cluster, username='flastname2', first_name='firstName', last_name='lastName', kubernetes_user=False
        )
        cluster_user_with_same_name2.save()

        expected_call_args = 'call({\'kubernetesUser\': False, \'firstName\': \'firstName\', \'lastName\': \'lastName\', \'type\': \'type\', '
        expected_call_args += '\'email\': \'test@test.com\', \'publicSSHKey\': \'AAAAB3NzaC1yc2Etesttesttesttest\', \'clusterID\': '
        expected_call_args += '\'' + self.clusterID + '\', \'username\': \'flastname1\'}'
        expected_call_args += ', UUID(\'' + self.clusterID + '\'))'
        request_body = json.dumps(
            {
                "kubernetesUser": False, "username": "username", "firstName": "firstName", "lastName": "lastName", "type": "user", "email": "test@test.com", "publicSSHKey": "AAAAB3NzaC1yc2Etesttesttesttest", "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"submitted": true}'

        with patch.object(tasks.worker_create_cluster_user, 'delay') as mock:
            with patch.object(authorization_service, 'Authorize') as authorize_mock:
                authorize_mock.side_effect = func_returns_none
                mock.side_effect = func_worker_validate_credentials

                response = self.client.post('/addUserToCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
                response_body = response.content.decode()

                resolver = resolve('/addUserToCluster')

                mock.assert_called()
                # self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
                self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_user_to_cluster')
                # self.assertEqual(response.status_code, 200)
                # self.assertEqual(expected_response_body, response_body)


class DeleteUserFromCluster(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        self.cluster = Clusters(
            name='testCluster',
            user=self.user
        )
        self.cluster.save()
        self.cluster_user = ClusterUser(
            cluster=self.cluster, username='username', first_name='first_name', last_name='last_name', kubernetes_user=False
        )
        self.cluster_user.save()

        self.clusterID = str(self.cluster.id)

    def test_delete_user_from_cluster_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/deleteUserFromCluster')

        resolver = resolve('/deleteUserFromCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_user_from_cluster')
        self.assertEqual(response.status_code, 401)

    def test_delete_user_from_cluster_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/deleteUserFromCluster', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/deleteUserFromCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_user_from_cluster')
        self.assertEqual(response.status_code, 401)

    def test_delete_user_from_cluster_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/deleteUserFromCluster', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteUserFromCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_user_from_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_user_from_cluster_missing_parameter_username_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": "clusterID"
            }
        )

        expected_response_body = '{"error": {"message": "\'username\' is a required property"}}'

        response = self.client.post('/deleteUserFromCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteUserFromCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_user_from_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_user_from_cluster_too_short_parameter_username_returns_400(self):
        self.client = Client()

        short_username = '1'
        request_body = json.dumps(
            {
                "username": short_username, "clusterID": "clusterID"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_username + '\' is too short"}}'

        response = self.client.post('/deleteUserFromCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteUserFromCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_user_from_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_user_from_cluster_too_long_parameter_username_returns_400(self):
        self.client = Client()

        long_username = '123456789112345678911234567891123456789112345678911'
        request_body = json.dumps(
            {
                "username": long_username, "clusterID": "clusterID"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_username + '\' is too long"}}'

        response = self.client.post('/deleteUserFromCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteUserFromCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_user_from_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_user_from_cluster_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "username": "username", "lastName": "lastName"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/deleteUserFromCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteUserFromCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_user_from_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_user_from_cluster_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '1'
        request_body = json.dumps(
            {
                "username": "username", "clusterID": short_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/deleteUserFromCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteUserFromCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_user_from_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_user_from_cluster_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '123456789112345678911234567891123456789112345678911'
        request_body = json.dumps(
            {
                "username": "username", "clusterID": long_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/deleteUserFromCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteUserFromCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_user_from_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_user_from_cluster_invalid_UUID_clusterID_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "username": "username", "clusterID": "123456789112345678911234567891123456"
            }
        )
        expected_response_body = '{"error": {"message": "Invalid parameter clusterID"}}'

        response = self.client.post('/deleteUserFromCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteUserFromCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_user_from_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_delete_user_from_cluster_clusterID_of_not_existing_cluster_returns_500(self):
        self.client = Client()

        wrong_clusterID = '00000000-0000-0000-0000-000000000000'
        request_body = json.dumps(
            {
                "username": "username", "clusterID": wrong_clusterID
            }
        )
        expected_response_body = '{"error": {"message": "Invalid parameter clusterID"}}'

        response = self.client.post('/deleteUserFromCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteUserFromCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_user_from_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)
    
    def test_delete_user_from_cluster_clusterID_of_not_runing_cluster_returns_500(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.status = 10
        cluster.save()
        request_body = json.dumps(
            {
                "username": "username", "clusterID": self.clusterID
            }
        )
        expected_response_body = '{"error": {"message": "Cluster is not running."}}'

        response = self.client.post('/deleteUserFromCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteUserFromCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_user_from_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_delete_user_from_cluster_not_existing_cluster_user_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "username": "username1", "clusterID": self.clusterID
            }
        )
        expected_response_body = '{"error": {"message": "ClusterUser does not exist."}}'

        response = self.client.post('/deleteUserFromCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteUserFromCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_user_from_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_delete_user_from_cluster_valid_returns_200(self):
        self.client = Client()

        expected_call_args = 'call(\'' + self.cluster_user.username + '\', '
        expected_call_args += 'UUID(\'' + self.clusterID + '\'), 1, {\'username\': \'username\', \'clusterID\': \'' + self.clusterID + '\'})'
        request_body = json.dumps(
            {
                "username": self.cluster_user.username, "clusterID": self.clusterID, 
            }
        )

        with patch.object(tasks.worker_delete_cluster_user, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials

            response = self.client.post('/deleteUserFromCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            celerytask = models.CeleryTask.objects.filter(id=json.loads(response_body)['taskId'])[0]
            expected_response_body = '{"taskId": "' + str(celerytask.id) + '"}'

            resolver = resolve('/deleteUserFromCluster')

            mock.assert_called()
            self.assertEqual(str(mock.call_args_list[0]), (expected_call_args))
            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_user_from_cluster')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(expected_response_body, response_body)


class ChangeUserPassword(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

    def test_change_user_password_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/updateuserpassword')

        resolver = resolve('/updateuserpassword')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.change_user_password')
        self.assertEqual(response.status_code, 401)

    def test_change_user_password_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/updateuserpassword', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/updateuserpassword')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.change_user_password')
        self.assertEqual(response.status_code, 401)

    def test_change_user_password_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/updateuserpassword', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/updateuserpassword')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.change_user_password')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_change_user_password_with_invalid_first_password_returns_401(self):
        self.client = Client()
        current_password = 'current_password123'
        new_password = 'new_password123'
        new_password_confirmation = 'new_password123'

        request_body = json.dumps(
            {"current_password": current_password, "new_password": new_password, "new_password_confirmation": new_password_confirmation}
        )
        expected_response_body = '{"error": {"message": "Invalid password"}}'

        response = self.client.post('/updateuserpassword', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/updateuserpassword')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.change_user_password')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(expected_response_body, response_body)

    def test_change_user_password_too_short_parameter_returns_400(self):
        self.client = Client()
        current_password = '12345'
        new_password = 'new'
        new_password_confirmation = 'new'

        request_body = json.dumps(
            {"current_password": current_password, "new_password": new_password, "new_password_confirmation": new_password_confirmation}
        )
        expected_response_body = '{"error": {"message": "New password is too short"}}'

        response = self.client.post('/updateuserpassword', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/updateuserpassword')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.change_user_password')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_change_user_password_invalid_new_password_returns_400(self):
        self.client = Client()
        current_password = '12345'
        new_password = 'new_password12345' * 10
        new_password_confirmation = 'new_password12345' * 10

        request_body = json.dumps(
            {"current_password": current_password, "new_password": new_password, "new_password_confirmation": new_password_confirmation}
        )
        expected_response_body = '{"error": {"message": "New password is invalid"}}'

        response = self.client.post('/updateuserpassword', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/updateuserpassword')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.change_user_password')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_change_user_password_different_returns_400(self):
        self.client = Client()
        current_password = '12345'
        new_password = 'new_password12345'
        new_password_confirmation = 'new_password54321'

        request_body = json.dumps(
            {"current_password": current_password, "new_password": new_password, "new_password_confirmation": new_password_confirmation}
        )
        expected_response_body = '{"error": {"message": "Password confirmation doesn\'t match Password"}}'

        response = self.client.post('/updateuserpassword', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/updateuserpassword')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.change_user_password')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_change_user_password_changed_should_change_password_and_return_200(self):
        self.client = Client()
        current_password = '12345'
        new_password = 'new_password12345'
        new_password_confirmation = 'new_password12345'

        request_body = json.dumps(
            {"current_password": current_password, "new_password": new_password, "new_password_confirmation": new_password_confirmation}
        )
        expected_response_body = ''

        response = self.client.post('/updateuserpassword', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        user = User.objects.get(username='testuser')
        response_body = response.content.decode()

        resolver = resolve('/updateuserpassword')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.change_user_password')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)
        self.assertTrue(user.check_password(new_password))


class IsAlive(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

    def test_is_alive_no_authorization_headers_returns_200(self):
        self.client = Client()

        response = self.client.get('/isAlive')

        resolver = resolve('/isAlive')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_alive')
        self.assertEqual(response.status_code, 200)


class GetVersion(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

    def test_get_version_no_authorization_headers(self):
        self.client = Client()

        response = self.client.get('/getVersion')

        resolver = resolve('/getVersion')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_version')
        self.assertEqual(response.status_code, 401)

    def test_get_version_invalid_credentials(self):
        self.client = Client()

        response = self.client.get(
            '/getVersion', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getVersion')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_version')
        self.assertEqual(response.status_code, 401)


# get_provider_accounts
class GetProviderAccounts(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            user=self.user
        )
        google_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            user=self.user
        )
        aws_account.save()
        azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            user=self.user
        )
        azure_account.save()

    def test_get_provider_accounts_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/getProviderAccounts')

        resolver = resolve('/getProviderAccounts')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_provider_accounts')
        self.assertEqual(response.status_code, 401)

    def test_get_provider_accounts_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/getProviderAccounts', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getProviderAccounts')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_provider_accounts')
        self.assertEqual(response.status_code, 401)

    def test_get_provider_accounts_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/getProviderAccounts', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getProviderAccounts')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_provider_accounts')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_provider_accounts_missing_parameter_provider_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "accountLabel": "accountLabel"
            }
        )

        expected_response_body = '{"error": {"message": "\'provider\' is a required property"}}'

        response = self.client.post('/getProviderAccounts', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getProviderAccounts')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_provider_accounts')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_provider_accounts_too_short_parameter_provider_returns_400(self):
        self.client = Client()

        short_provider = '1'
        request_body = json.dumps(
            {
                "provider": short_provider
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_provider + '\' is too short"}}'

        response = self.client.post('/getProviderAccounts', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getProviderAccounts')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_provider_accounts')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_provider_accounts_too_long_parameter_provider_returns_400(self):
        self.client = Client()

        long_provider = '12345678911234'
        request_body = json.dumps(
            {
                "provider": long_provider
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_provider + '\' is too long"}}'

        response = self.client.post('/getProviderAccounts', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getProviderAccounts')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_provider_accounts')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_provider_accounts_invalid_provider_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "provi"
            }
        )
        expected_response_body = '{"error": {"message": "No provider is selected."}}'

        response = self.client.post('/getProviderAccounts', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getProviderAccounts')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_provider_accounts')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_provider_accounts_valid_google_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google"
            }
        )

        expected_response_body = '{"accounts": [{"label": "accountLabel"}]}'

        response = self.client.post('/getProviderAccounts', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getProviderAccounts')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_provider_accounts')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)
    
    def test_get_provider_accounts_valid_aws_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "aws"
            }
        )

        expected_response_body = '{"accounts": [{"label": "accountLabel"}]}'

        response = self.client.post('/getProviderAccounts', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getProviderAccounts')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_provider_accounts')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)

    def test_get_provider_accounts_valid_azure_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "azure"
            }
        )

        expected_response_body = '{"accounts": [{"label": "accountLabel"}]}'

        response = self.client.post('/getProviderAccounts', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getProviderAccounts')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_provider_accounts')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class GetValidRegions(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        regions = '''[
            {
                "name": "region",
                "zones": [
                    {
                        "name": "zone",
                        "instances": [
                            {
                                "name": "instanceType",
                                "description": "description"
                            }
                        ]
                    }
                ]
            }
        ]'''

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        aws_account.save()
        azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        azure_account.save()

    def test_get_valid_regions_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/getValidRegions')

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(response.status_code, 401)

    def test_get_valid_regions_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/getValidRegions', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(response.status_code, 401)

    def test_get_valid_regions_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/getValidRegions', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_regions_missing_parameter_provider_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "accountLabel": "accountLabel"
            }
        )

        expected_response_body = '{"error": {"message": "\'provider\' is a required property"}}'

        response = self.client.post('/getValidRegions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_regions_too_short_parameter_provider_returns_400(self):
        self.client = Client()

        short_provider = '1'
        request_body = json.dumps(
            {
                "provider": short_provider,
                "accountLabel": "accountLabel"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_provider + '\' is too short"}}'

        response = self.client.post('/getValidRegions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_regions_too_long_parameter_provider_returns_400(self):
        self.client = Client()

        long_provider = '12345678911234'
        request_body = json.dumps(
            {
                "provider": long_provider,
                "accountLabel": "accountLabel"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_provider + '\' is too long"}}'

        response = self.client.post('/getValidRegions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_regions_missing_parameter_accountLabel_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'accountLabel\' is a required property"}}'

        response = self.client.post('/getValidRegions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_regions_too_short_parameter_accountLabel_returns_400(self):
        self.client = Client()

        short_accountLabel = '1'
        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": short_accountLabel
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_accountLabel + '\' is too short"}}'

        response = self.client.post('/getValidRegions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_regions_too_long_parameter_accountLabel_returns_400(self):
        self.client = Client()

        long_accountLabel = 'a' * 101
        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": long_accountLabel
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_accountLabel + '\' is too long"}}'

        response = self.client.post('/getValidRegions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_regions_invalid_provider_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "provi",
                "accountLabel": "accountLabel"
            }
        )
        expected_response_body = '{"error": {"message": "No provider is selected."}}'

        response = self.client.post('/getValidRegions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_regions_invalid_google_account_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": "accountLabel123"
            }
        )
        expected_response_body = '{"error": {"message": "Account does not exist."}}'

        response = self.client.post('/getValidRegions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_regions_invalid_aws_account_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "aws",
                "accountLabel": "accountLabel123"
            }
        )
        expected_response_body = '{"error": {"message": "Account does not exist."}}'

        response = self.client.post('/getValidRegions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_get_valid_regions_invalid_azure_account_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "azure",
                "accountLabel": "accountLabel123"
            }
        )
        expected_response_body = '{"error": {"message": "Account does not exist."}}'

        response = self.client.post('/getValidRegions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_regions_valid_google_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": "accountLabel"
            }
        )

        expected_response_body = '{"regions": ["region"]}'

        response = self.client.post('/getValidRegions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)
    
    def test_get_valid_regions_valid_aws_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "aws",
                "accountLabel": "accountLabel"
            }
        )

        expected_response_body = '{"regions": ["region"]}'

        response = self.client.post('/getValidRegions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)

    def test_get_valid_regions_valid_azure_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "azure",
                "accountLabel": "accountLabel"
            }
        )

        expected_response_body = '{"regions": ["region"]}'

        response = self.client.post('/getValidRegions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidRegions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_regions')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class GetValidZones(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        regions = '''[
            {
                "name": "region",
                "zones": [
                    {
                        "name": "zone",
                        "instances": [
                            {
                                "name": "instanceType",
                                "description": "description"
                            }
                        ]
                    }
                ]
            }
        ]'''

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabelGoogle',
            regions=regions,
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabelAli',
            regions=regions,
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabelAws',
            regions=regions,
            user=self.user
        )
        aws_account.save()
        azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabelAzure',
            regions=regions,
            user=self.user
        )
        azure_account.save()

    def test_get_valid_zones_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/getValidZones')

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(response.status_code, 401)

    def test_get_valid_zones_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/getValidZones', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(response.status_code, 401)

    def test_get_valid_zones_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/getValidZones', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_zones_missing_parameter_provider_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "accountLabel": "accountLabel",
                "region": "region"
            }
        )

        expected_response_body = '{"error": {"message": "\'provider\' is a required property"}}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_zones_too_short_parameter_provider_returns_400(self):
        self.client = Client()

        short_provider = '1'
        request_body = json.dumps(
            {
                "provider": short_provider,
                "accountLabel": "accountLabel",
                "region": "region"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_provider + '\' is too short"}}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_zones_too_long_parameter_provider_returns_400(self):
        self.client = Client()

        long_provider = '12345678911234'
        request_body = json.dumps(
            {
                "provider": long_provider,
                "accountLabel": "accountLabel",
                "region": "region"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_provider + '\' is too long"}}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_get_valid_zones_missing_parameter_accountLabel_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region"
            }
        )

        expected_response_body = '{"error": {"message": "\'accountLabel\' is a required property"}}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_zones_too_short_parameter_accountLabel_returns_400(self):
        self.client = Client()

        short_accountLabel = '1'
        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": short_accountLabel,
                "region": "region"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_accountLabel + '\' is too short"}}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_zones_too_long_parameter_accountLabel_returns_400(self):
        self.client = Client()

        long_accountLabel = '1' * 101
        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": long_accountLabel,
                "region": "region"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_accountLabel + '\' is too long"}}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_zones_missing_parameter_region_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": "accountLabel"
            }
        )

        expected_response_body = '{"error": {"message": "\'region\' is a required property"}}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_zones_too_short_parameter_region_returns_400(self):
        self.client = Client()

        short_region = '1'
        request_body = json.dumps(
            {
                "provider": "azure",
                "accountLabel": "accountLabel",
                "region": short_region
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_region + '\' is too short"}}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_zones_too_long_parameter_region_returns_400(self):
        self.client = Client()

        long_region = '123456789112345678911'
        request_body = json.dumps(
            {
                "provider": "azure",
                "accountLabel": "accountLabel",
                "region": long_region
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_region + '\' is too long"}}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_zones_invalid_provider_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "provi",
                "accountLabel": "accountLabel",
                "region": "region"
            }
        )
        expected_response_body = '{"error": {"message": "Invalid provider parameter."}}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_get_valid_zones_invalid_google_account_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": "accountLabel123",
                "region": "region"
            }
        )
        expected_response_body = '{"error": {"message": "Account does not exist."}}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_zones_invalid_aws_account_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "aws",
                "accountLabel": "accountLabel123",
                "region": "region"
            }
        )
        expected_response_body = '{"error": {"message": "Account does not exist."}}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_get_valid_zones_invalid_azure_account_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "azure",
                "accountLabel": "accountLabel123",
                "region": "region"
            }
        )
        expected_response_body = '{"error": {"message": "Account does not exist."}}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_zones_valid_google_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": "accountLabelGoogle",
                "region": "region"
            }
        )

        expected_response_body = '{"zones": ["zone"]}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)

    def test_get_valid_zones_valid_aws_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "aws",
                "accountLabel": "accountLabelAws",
                "region": "region"
            }
        )

        expected_response_body = '{"zones": ["zone"]}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)
    
    def test_get_valid_zones_valid_azure_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "azure",
                "accountLabel": "accountLabelAzure",
                "region": "region"
            }
        )

        expected_response_body = '{"zones": ["zone"]}'

        response = self.client.post('/getValidZones', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidZones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_zones')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class GetValidInstances(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        regions = '''[
            {
                "name": "region",
                "zones": [
                    {
                        "name": "zone",
                        "instances": [
                            {
                                "name": "instanceType",
                                "description": "description"
                            }
                        ]
                    }
                ]
            }
        ]'''

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        self.azure_account.save()

    def test_get_valid_instances_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/getValidInstances')

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(response.status_code, 401)

    def test_get_valid_instances_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/getValidInstances', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(response.status_code, 401)

    def test_get_valid_instances_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/getValidInstances', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_missing_parameter_provider_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "accountLabel": "accountLabel",
                "region": "region",
                "zone": "zone"
            }
        )

        expected_response_body = '{"error": {"message": "\'provider\' is a required property"}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_too_short_parameter_provider_returns_400(self):
        self.client = Client()

        short_provider = '1'
        request_body = json.dumps(
            {
                "provider": short_provider,
                "accountLabel": "accountLabel",
                "region": "region",
                "zone": "zone"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_provider + '\' is too short"}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_too_long_parameter_provider_returns_400(self):
        self.client = Client()

        long_provider = '12345678911234'
        request_body = json.dumps(
            {
                "provider": long_provider,
                "accountLabel": "accountLabel",
                "region": "region",
                "zone": "zone"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_provider + '\' is too long"}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_missing_parameter_accountLabel_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": "zone"
            }
        )

        expected_response_body = '{"error": {"message": "\'accountLabel\' is a required property"}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_too_short_parameter_accountLabel_returns_400(self):
        self.client = Client()

        short_accountLabel = '1'
        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": short_accountLabel,
                "region": "region",
                "zone": "zone"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_accountLabel + '\' is too short"}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_too_long_parameter_accountLabel_returns_400(self):
        self.client = Client()

        long_accountLabel = '1' * 101
        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": long_accountLabel,
                "region": "region",
                "zone": "zone"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_accountLabel + '\' is too long"}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_missing_parameter_region_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": "accountLabel",
                "zone": "zone"
            }
        )

        expected_response_body = '{"error": {"message": "\'region\' is a required property"}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_too_short_parameter_region_returns_400(self):
        self.client = Client()

        short_region = '1'
        request_body = json.dumps(
            {
                "provider": "azure",
                "accountLabel": "accountLabel",
                "region": short_region,
                "zone": "zone"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_region + '\' is too short"}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_too_long_parameter_region_returns_400(self):
        self.client = Client()

        long_region = '123456789112345678911'
        request_body = json.dumps(
            {
                "provider": "azure",
                "accountLabel": "accountLabel",
                "region": long_region,
                "zone": "zone"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_region + '\' is too long"}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_missing_parameter_zone_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": "accountLabel",
                "region": "region"
            }
        )

        expected_response_body = '{"error": {"message": "\'zone\' is a required property"}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_too_short_parameter_zone_returns_400(self):
        self.client = Client()

        short_zone = '1'
        request_body = json.dumps(
            {
                "provider": "azure",
                "accountLabel": "accountLabel",
                "region": "region",
                "zone": short_zone
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_zone + '\' is too short"}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_too_long_parameter_zone_returns_400(self):
        self.client = Client()

        long_zone = '12345678911234567891123456'
        request_body = json.dumps(
            {
                "provider": "azure",
                "accountLabel": "accountLabel",
                "region": "region",
                "zone": long_zone
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_zone + '\' is too long"}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_invalid_provider_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "provi",
                "accountLabel": "accountLabel",
                "region": "region",
                "zone": "zone"
            }
        )
        expected_response_body = '{"error": {"message": "Invalid provider parameter."}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_get_valid_instances_invalid_google_account_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": "accountLabel123",
                "region": "region",
                "zone": "zone"
            }
        )
        expected_response_body = '{"error": {"message": "Account does not exist."}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_invalid_aws_account_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "aws",
                "accountLabel": "accountLabel123",
                "region": "region",
                "zone": "zone"
            }
        )
        expected_response_body = '{"error": {"message": "Account does not exist."}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_invalid_azure_account_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "azure",
                "accountLabel": "accountLabel123",
                "region": "region",
                "zone": "zone"
            }
        )
        expected_response_body = '{"error": {"message": "Account does not exist."}}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_instances_valid_azure_edge_case_returns_200(self):
        self.client = Client()

        self.azure_account.azure_regions = '''[
            {
                "name": "Re Gion",
                "zones": [
                    {
                        "name": "Zo Ne",
                        "instances": [
                            {
                                "name": "instanceType",
                                "description": "description"
                            }
                        ]
                    }
                ]
            }
        ]'''
        self.azure_account.save()

        request_body = json.dumps(
            {
                "provider": "azure",
                "accountLabel": "accountLabel",
                "region": "region",
                "zone": "zone"
            }
        )

        expected_response_body = '{"instances": [{"name": "instanceType", "description": "description"}]}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)

    def test_get_valid_instances_valid_google_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": "accountLabel",
                "region": "region",
                "zone": "zone"
            }
        )

        expected_response_body = '{"instances": [{"name": "instanceType", "description": "description"}]}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)

    def test_get_valid_instances_valid_aws_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "aws",
                "accountLabel": "accountLabel",
                "region": "region",
                "zone": "zone"
            }
        )

        expected_response_body = '{"instances": [{"name": "instanceType", "description": "description"}]}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)

    def test_get_valid_instances_valid_azure_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "azure",
                "accountLabel": "accountLabel",
                "region": "region",
                "zone": "zone"
            }
        )

        expected_response_body = '{"instances": [{"name": "instanceType", "description": "description"}]}'

        response = self.client.post('/getValidInstances', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidInstances')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_instances')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class GetValidOperatingSystems(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        regions = '''[
            {
                "name": "region",
                "zones": [
                    {
                        "name": "zone",
                        "instances": [
                            {
                                "name": "instanceType",
                                "description": "description"
                            }
                        ]
                    }
                ]
            }
        ]'''

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        self.azure_account.save()
        self.onPremise_account = CloudAccount(
            provider = 'onpremise',
            label='accountLabel',
            user=self.user
        )
        self.onPremise_account.save()

        self.iotArm_account = CloudAccount(
            provider = 'iotarm',
            label='accountLabel',
            user=self.user
        )
        self.iotArm_account.save()

    def test_get_valid_operating_systems_no_authorization_headers(self):
        self.client = Client()

        parameters = '/' + 'testuser' + '/' + 'google' + '/' + 'accountLabel' + '/' + 'europe-west3'
        response = self.client.get('/getValidOperatingSystems' + parameters)

        resolver = resolve('/getValidOperatingSystems' + parameters)

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_operating_systems')
        self.assertEqual(response.status_code, 401)

    def test_get_valid_operating_systems_invalid_credentials(self):
        self.client = Client()

        parameters = '/' + 'testuser' + '/' + 'google' + '/' + 'accountLabel' + '/' + 'europe-west3'
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getValidOperatingSystems' + parameters)

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_operating_systems')
        self.assertEqual(response.status_code, 401)

    def test_get_valid_operating_systems_missing_parameter_username_returns_404(self):
        self.client = Client()

        parameters = '/' + 'google' + '/' + 'accountLabel' + '/' + 'europe-west3'
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')

        self.assertEqual(response.status_code, 404)

    def test_get_valid_operating_systems_missing_parameter_provider_returns_404(self):
        self.client = Client()

        parameters = '/' + 'testuser' + '/' + 'accountLabel' + '/' + 'europe-west3'
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')

        self.assertEqual(response.status_code, 404)

    def test_get_valid_operating_systems_too_short_parameter_provider_returns_400(self):
        self.client = Client()

        short_provider = '1'

        expected_response_body = '{"error": {"message": "\'' + short_provider + '\' is too short"}}'

        parameters = '/' + 'testuser' + '/' + short_provider + '/' + 'accountLabel' + '/' + 'europe-west3'
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidOperatingSystems' + parameters)

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_operating_systems')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_operating_systems_too_long_parameter_provider_returns_400(self):
        self.client = Client()

        long_provider = '12345678911234'

        expected_response_body = '{"error": {"message": "\'' + long_provider + '\' is too long"}}'

        parameters = '/' + 'testuser' + '/' + long_provider + '/' + 'accountLabel' + '/' + 'europe-west3'
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidOperatingSystems' + parameters)

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_operating_systems')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_operating_systems_missing_parameter_accountLabel_returns_400(self):
        self.client = Client()

        parameters = '/' + 'testuser' + '/' + 'google' + '/' + 'europe-west3'
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')

        self.assertEqual(response.status_code, 404)

    def test_get_valid_operating_systems_too_short_parameter_accountLabel_returns_400(self):
        self.client = Client()

        short_accountLabel = '1'

        expected_response_body = '{"error": {"message": "\'' + short_accountLabel + '\' is too short"}}'

        parameters = '/' + 'testuser' + '/' + 'google' + '/' + short_accountLabel + '/' + 'europe-west3'
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidOperatingSystems' + parameters)

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_operating_systems')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_operating_systems_too_long_parameter_accountLabel_returns_400(self):
        self.client = Client()

        long_accountLabel = '1' * 101

        expected_response_body = '{"error": {"message": "\'' + long_accountLabel + '\' is too long"}}'

        parameters = '/' + 'testuser' + '/' + 'google' + '/' + long_accountLabel + '/' + 'europe-west3'
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidOperatingSystems' + parameters)

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_operating_systems')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_operating_systems_missing_parameter_region_returns_400(self):
        self.client = Client()
        
        parameters = '/' + 'testuser' + '/' + 'google' + '/' + 'accountLabel'
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')

        self.assertEqual(response.status_code, 404)

    def test_get_valid_operating_systems_too_short_parameter_region_returns_400(self):
        self.client = Client()

        short_region = '1'

        expected_response_body = '{"error": {"message": "\'' + short_region + '\' is too short"}}'

        parameters = '/' + 'testuser' + '/' + 'google' + '/' + 'accountLabel' + '/' + short_region
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidOperatingSystems' + parameters)

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_operating_systems')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_operating_systems_too_long_parameter_region_returns_400(self):
        self.client = Client()

        long_region = '123456789112345678911'

        expected_response_body = '{"error": {"message": "\'' + long_region + '\' is too long"}}'

        parameters = '/' + 'testuser' + '/' + 'google' + '/' + 'accountLabel' + '/' + long_region
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidOperatingSystems' + parameters)

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_operating_systems')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_valid_operating_systems_invalid_provider_returns_400(self):
        self.client = Client()

        expected_response_body = '{"error": {"message": "Invalid provider parameter."}}'

        parameters = '/' + 'testuser' + '/' + 'provi' + '/' + 'accountLabel' + '/' + 'europe-west3'
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidOperatingSystems' + parameters)

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_operating_systems')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_get_valid_operating_systems_invalid_google_account_returns_500(self):
        self.client = Client()

        expected_response_body = '{"error": {"message": "Account does not exist."}}'

        parameters = '/' + 'testuser' + '/' + 'google' + '/' + 'accountLabel1' + '/' + 'europe-west3'
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidOperatingSystems' + parameters)

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_operating_systems')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_valid_operating_systems_invalid_aws_account_returns_500(self):
        self.client = Client()

        expected_response_body = '{"error": {"message": "Account does not exist."}}'

        parameters = '/' + 'testuser' + '/' + 'aws' + '/' + 'accountLabel1' + '/' + 'europe-west3'
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidOperatingSystems' + parameters)

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_operating_systems')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_valid_operating_systems_invalid_azure_account_returns_500(self):
        self.client = Client()

        expected_response_body = '{"error": {"message": "Account does not exist."}}'

        parameters = '/' + 'testuser' + '/' + 'azure' + '/' + 'accountLabel1' + '/' + 'europe-west3'
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidOperatingSystems' + parameters)

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_operating_systems')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_valid_operating_systems_valid_onPremise_returns_200(self):
        self.client = Client()

        expected_response_body = '{"operatingSystems": [{"os": "Canonical, Ubuntu, 18.04 LTS, amd64", "value": "ubuntu-1804-bionic"}, {"os": "Debian, Debian GNU/Linux, 9 (stretch), amd64", "value": "debian-9-stretch"}]}'

        parameters = '/' + 'testuser' + '/' + 'onpremise' + '/' + 'accountLabel' + '/' + 'europe-west3'
        response = self.client.get('/getValidOperatingSystems' + parameters, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getValidOperatingSystems' + parameters)

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_valid_operating_systems')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 200)


class GetServiceList(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        self.category = ServiceCategory(
            name="Database"
        )
        self.category.save()
        self.service = Service(
            name='mysql',
            description='description',
            logo_url='logo_url'
        )
        self.service.save()
        self.profile = self.user.profile
        self.profile.save()

    def test_get_service_list_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/getServiceList')

        resolver = resolve('/getServiceList')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_list')
        self.assertEqual(response.status_code, 401)

    def test_get_service_list_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/getServiceList', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getServiceList')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_list')
        self.assertEqual(response.status_code, 401)

    def test_get_service_list_valid_without_categories_returns_200(self):
        self.client = Client()

        expected_response_body = '{"serviceList": [{"name": "mysql", "logo_url": "logo_url", "description": "description", "categories": []}]}'

        response = self.client.post('/getServiceList', '', content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceList')

        
        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_list')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)

    def test_get_service_list_valid_with_categories_returns_200(self):
        self.client = Client()

        self.service.categories.add(self.category)
        self.service.save()

        expected_response_body = '{"serviceList": [{"name": "mysql", "logo_url": "logo_url", "description": "description", "categories": ["Database"]}]}'

        response = self.client.post('/getServiceList', '', content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceList')

        
        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_list')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class GetServiceValues(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        self.profile = self.user.profile
        self.profile.save()
        self.service_without_yaml = Service(
            name='mysql',
            description='description',
            logo_url='logo_url',
            options='{"yamlConfig": false}'
        )
        self.service_without_yaml.save()

        self.service_with_yaml = Service(
            name='mysql_with_yaml',
            description='description',
            logo_url='logo_url',
            options='{"yamlConfig": true}',
            values_file='values_file'
        )
        self.service_with_yaml.save()


    def test_get_service_values_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/getServiceValues')

        resolver = resolve('/getServiceValues')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_values')
        self.assertEqual(response.status_code, 401)

    def test_get_service_values_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/getServiceValues', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getServiceValues')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_values')
        self.assertEqual(response.status_code, 401)

    def test_get_service_values_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/getServiceValues', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceValues')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_values')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_values_missing_parameter_service_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "region": "region"
            }
        )

        expected_response_body = '{"error": {"message": "\'service\' is a required property"}}'

        response = self.client.post('/getServiceValues', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceValues')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_values')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_values_too_short_parameter_service_returns_400(self):
        self.client = Client()

        short_service = '1'
        request_body = json.dumps(
            {
                "service": short_service
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_service + '\' is too short"}}'

        response = self.client.post('/getServiceValues', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceValues')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_values')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_values_too_long_parameter_service_returns_400(self):
        self.client = Client()

        long_service = '12345678911234567891123456789112'
        request_body = json.dumps(
            {
                "service": long_service
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_service + '\' is too long"}}'

        response = self.client.post('/getServiceValues', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceValues')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_values')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_values_not_existing_service_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "service": "invalid_service"
            }
        )
        expected_response_body = '{"error": {"message": "Invalid parameter service."}}'

        response = self.client.post('/getServiceValues', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceValues')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_values')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_service_values_service_without_yamlconfig_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "service": self.service_without_yaml.name
            }
        )
        expected_response_body = '{"error": {"message": "Service does not support yamlConfig."}}'

        response = self.client.post('/getServiceValues', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceValues')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_values')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_service_values_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "service": self.service_with_yaml.name
            }
        )
        expected_response_body = '{"values": "values_file"}'

        response = self.client.post('/getServiceValues', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceValues')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_values')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class GetServiceConnectionInfo(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        self.cluster = Clusters(
            name='testCluster',
            user=self.user,
            type=1
        )
        self.cluster.save()
        self.service = ClusterService(
            cluster=self.cluster,
            name='name',
            namespace='namespace',
            connection_info='connection_info'
        )
        self.service.save()
        self.profile = self.user.profile
        self.profile.save()

    def test_get_service_connection_info_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/getServiceConnectionInfo')

        resolver = resolve('/getServiceConnectionInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_connection_info')
        self.assertEqual(response.status_code, 401)

    def test_get_service_connection_info_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/getServiceConnectionInfo', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getServiceConnectionInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_connection_info')
        self.assertEqual(response.status_code, 401)

    def test_get_service_connection_info_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/getServiceConnectionInfo', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceConnectionInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_connection_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_connection_info_missing_parameter_name_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "namespace": "namespace",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'name\' is a required property"}}'

        response = self.client.post('/getServiceConnectionInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceConnectionInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_connection_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_connection_info_too_short_parameter_name_returns_400(self):
        self.client = Client()

        short_name = '1'
        request_body = json.dumps(
            {
                "name": short_name,
                "namespace": "namespace",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + short_name + '\' is too short"}}'

        response = self.client.post('/getServiceConnectionInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceConnectionInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_connection_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_values_too_long_parameter_name_returns_400(self):
        self.client = Client()

        long_name = '12345678911234567891123456789112'
        request_body = json.dumps(
            {
                "name": long_name,
                "namespace": "namespace",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + long_name + '\' is too long"}}'

        response = self.client.post('/getServiceConnectionInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceConnectionInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_connection_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_connection_info_too_short_parameter_namespace_returns_400(self):
        self.client = Client()

        short_namespace = '1'
        request_body = json.dumps(
            {
                "name": "name",
                "namespace": short_namespace,
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + short_namespace + '\' is too short"}}'

        response = self.client.post('/getServiceConnectionInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceConnectionInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_connection_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_values_too_long_parameter_namespace_returns_400(self):
        self.client = Client()

        long_namespace = '12345678911234567891123456789112'
        request_body = json.dumps(
            {
                "name": "name",
                "namespace": long_namespace,
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + long_namespace + '\' is too long"}}'

        response = self.client.post('/getServiceConnectionInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceConnectionInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_connection_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_connection_info_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "name": "name",
                "serviceName": "serviceName",
                "namespace": "namespace",
                "configurationType": "configurationType",
                "valuesFile": "valuesFile",
                "cloudProviders": {
                    "alicloudSelected": False,
                    "awsSelected": False,
                    "googleSelected": False,
                    "azureSelected": False,
                    "onPremiseSelected": False,
                    "iotArmSelected": False
                }
            }   
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/getServiceConnectionInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceConnectionInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_connection_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_connection_info_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '1'
        request_body = json.dumps(
            {
                "name": "name",
                "namespace": "namespace",
                "clusterID": short_clusterID
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/getServiceConnectionInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceConnectionInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_connection_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_values_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '12345678911234567891123456789112345678'
        request_body = json.dumps(
            {
                "name": "name",
                "namespace": "namespace",
                "clusterID": long_clusterID
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/getServiceConnectionInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceConnectionInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_connection_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_connection_info_invalid_parameter_clusterID_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "name": "name",
                "namespace": "namespace",
                "clusterID": '123456789112345678911234567891123456'
            }   
        )

        expected_response_body = '{"error": {"message": "Invalid parameter clusterID"}}'

        response = self.client.post('/getServiceConnectionInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceConnectionInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_connection_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_service_connection_info_invalid_parameter_name_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "name": "invalid_name",
                "namespace": "namespace",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "Service does not exist."}}'

        response = self.client.post('/getServiceConnectionInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceConnectionInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_connection_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_service_connection_info_invalid_parameter_namespace_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "name": "name",
                "namespace": "invalid_namespace",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "Service does not exist."}}'

        response = self.client.post('/getServiceConnectionInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceConnectionInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_connection_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_service_connection_info_valid_returns_200(self):
        self.client = Client()

        expected_response_body = '{"connection_info": "connection_info"}'

        request_body = json.dumps(
            {
                "name": "name",
                "namespace": "namespace",
                "clusterID": str(self.cluster.id)
            }
        )

        response = self.client.post('/getServiceConnectionInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceConnectionInfo')

        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_connection_info')
        self.assertEqual(response.status_code, 200)


class getServiceOptions(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        self.service = Service(
            name='mysql',
            description='description',
            logo_url='logo_url',
            options='{"yamlConfig": true}',
            values_file='values_file'
        )
        self.service.save()
        self.profile = self.user.profile
        self.profile.save()

    def test_get_service_options_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/getServiceOptions')

        resolver = resolve('/getServiceOptions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_options')
        self.assertEqual(response.status_code, 401)

    def test_get_service_options_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/getServiceOptions', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getServiceOptions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_options')
        self.assertEqual(response.status_code, 401)

    def test_get_service_options_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/getServiceOptions', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceOptions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_options')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_options_missing_parameter_service_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "region": "region"
            }
        )

        expected_response_body = '{"error": {"message": "\'service\' is a required property"}}'

        response = self.client.post('/getServiceOptions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceOptions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_options')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_options_too_short_parameter_service_returns_400(self):
        self.client = Client()

        short_service = '1'
        request_body = json.dumps(
            {
                "service": short_service
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_service + '\' is too short"}}'

        response = self.client.post('/getServiceOptions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceOptions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_options')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_options_too_long_parameter_service_returns_400(self):
        self.client = Client()

        long_service = '12345678911234567891123456789112'
        request_body = json.dumps(
            {
                "service": long_service
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_service + '\' is too long"}}'

        response = self.client.post('/getServiceOptions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceOptions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_options')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_options_invalid_service_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "service": "invalid_service"
            }
        )
        expected_response_body = '{"error": {"message": "Invalid parameter service."}}'

        response = self.client.post('/getServiceOptions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceOptions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_options')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_service_options_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "service": "mysql"
            }
        )
        expected_response_body = '{"options": {"yamlConfig": true}}'

        response = self.client.post('/getServiceOptions', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getServiceOptions')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_service_options')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class GenerateClusterServiceDefaultName(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        self.cluster = Clusters(
            name='testCluster',
            user=self.user
        )
        self.cluster.save()
        self.service = Service(
            name='mysql'
        )
        self.service.save()
        self.profile = self.user.profile
        self.profile.save()

    def test_generate_cluster_service_default_name_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/generateClusterServiceDefaultName')

        resolver = resolve('/generateClusterServiceDefaultName')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.generate_cluster_service_default_name')
        self.assertEqual(response.status_code, 401)

    def test_generate_cluster_service_default_name_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/generateClusterServiceDefaultName', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/generateClusterServiceDefaultName')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.generate_cluster_service_default_name')
        self.assertEqual(response.status_code, 401)

    def test_generate_cluster_service_default_name_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/generateClusterServiceDefaultName', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/generateClusterServiceDefaultName')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.generate_cluster_service_default_name')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_generate_cluster_service_default_name_missing_parameter_service_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": str(self.cluster.id)
            }
        )

        expected_response_body = '{"error": {"message": "\'service\' is a required property"}}'

        response = self.client.post('/generateClusterServiceDefaultName', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/generateClusterServiceDefaultName')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.generate_cluster_service_default_name')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_generate_cluster_service_default_name_too_short_parameter_service_returns_400(self):
        self.client = Client()

        short_service = '1'
        request_body = json.dumps(
            {
                "service": short_service,
                "clusterID": str(self.cluster.id)
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_service + '\' is too short"}}'

        response = self.client.post('/generateClusterServiceDefaultName', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/generateClusterServiceDefaultName')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.generate_cluster_service_default_name')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_values_too_long_parameter_service_returns_400(self):
        self.client = Client()

        long_service = '12345678911234567891123456789112'
        request_body = json.dumps(
            {
                "service": long_service,
                "clusterID": str(self.cluster.id)
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_service + '\' is too long"}}'

        response = self.client.post('/generateClusterServiceDefaultName', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/generateClusterServiceDefaultName')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.generate_cluster_service_default_name')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_generate_cluster_service_default_name_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "service": "mysql"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/generateClusterServiceDefaultName', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/generateClusterServiceDefaultName')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.generate_cluster_service_default_name')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_generate_cluster_service_default_name_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '1'
        request_body = json.dumps(
            {
                "service": "mysql",
                "clusterID": short_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/generateClusterServiceDefaultName', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/generateClusterServiceDefaultName')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.generate_cluster_service_default_name')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_generate_cluster_service_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1234567891123456789112345678911234567'
        request_body = json.dumps(
            {
                "service": "mysql",
                "clusterID": long_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/generateClusterServiceDefaultName', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/generateClusterServiceDefaultName')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.generate_cluster_service_default_name')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_generate_cluster_service_invalid_parameter_clusterID_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "service": "mysql",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "Invalid parameter clusterID."}}'

        response = self.client.post('/generateClusterServiceDefaultName', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/generateClusterServiceDefaultName')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.generate_cluster_service_default_name')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_generate_cluster_service_invalid_parameter_service_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "service": "invalid",
                "clusterID": str(self.cluster.id)
            }
        )

        expected_response_body = '{"error": {"message": "Invalid parameter service."}}'

        response = self.client.post('/generateClusterServiceDefaultName', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/generateClusterServiceDefaultName')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.generate_cluster_service_default_name')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_generate_cluster_service_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "service": "mysql",
                "clusterID": str(self.cluster.id)
            }
        )

        expected_response_body = '{"defaultName": "mysql-0"}'

        response = self.client.post('/generateClusterServiceDefaultName', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/generateClusterServiceDefaultName')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.generate_cluster_service_default_name')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class UpdateUserInfo(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

    def test_update_user_info_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/updateUserInfo')

        resolver = resolve('/updateUserInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.update_user_info')
        self.assertEqual(response.status_code, 401)

    def test_update_user_info_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/updateUserInfo', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/updateUserInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.update_user_info')
        self.assertEqual(response.status_code, 401)

    def test_update_user_info_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/updateUserInfo', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/updateUserInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.update_user_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_update_user_info_too_short_parameter_first_name_returns_400(self):
        self.client = Client()

        short_first_name = 'a'
        request_body = json.dumps(
            {
                "first_name": short_first_name
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_first_name + '\' is too short"}}'

        response = self.client.post('/updateUserInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/updateUserInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.update_user_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_update_user_info_too_long_parameter_first_name_returns_400(self):
        self.client = Client()

        long_first_name = 'a'*101
        request_body = json.dumps(
            {
                "first_name": long_first_name
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_first_name + '\' is too long"}}'

        response = self.client.post('/updateUserInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/updateUserInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.update_user_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_update_user_info_too_short_parameter_timezone_returns_400(self):
        self.client = Client()

        short_timezone = 'a'
        request_body = json.dumps(
            {
                "timezone": short_timezone
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_timezone + '\' is too short"}}'

        response = self.client.post('/updateUserInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/updateUserInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.update_user_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_update_user_info_too_long_parameter_timezone_returns_400(self):
        self.client = Client()

        long_timezone = 'aa'*101
        request_body = json.dumps(
            {
                "timezone": long_timezone
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_timezone + '\' is too long"}}'

        response = self.client.post('/updateUserInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/updateUserInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.update_user_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)


    def test_update_user_info_too_invalid_timezone_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "timezone": 'testtt'
            }
        )

        expected_response_body = '{"error": {"message": "Invalid timezone"}}'

        response = self.client.post('/updateUserInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/updateUserInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.update_user_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_update_user_info_too_short_parameter_last_name_returns_400(self):
        self.client = Client()

        short_last_name = 'a'
        request_body = json.dumps(
            {
                "last_name": short_last_name
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_last_name + '\' is too short"}}'

        response = self.client.post('/updateUserInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/updateUserInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.update_user_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_update_user_info_too_long_parameter_last_name_returns_400(self):
        self.client = Client()

        long_last_name = 'a'*101
        request_body = json.dumps(
            {
                "last_name": long_last_name
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_last_name + '\' is too long"}}'

        response = self.client.post('/updateUserInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/updateUserInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.update_user_info')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_update_user_info_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "first_name": "firstname", "last_name": "lastname", "email": "emai@test.test"
            }
        )

        expected_response_body = ''

        response = self.client.post('/updateUserInfo', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/updateUserInfo')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.update_user_info')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class DeleteAccount(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabelGoogle',
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabelAli',
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabelAws',
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabelAzure',
            user=self.user
        )
        self.azure_account.save()
    
    def test_delete_account_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/deleteAccount')

        resolver = resolve('/deleteAccount')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_account')
        self.assertEqual(response.status_code, 401)

    def test_delete_account_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/deleteAccount', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/deleteAccount')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_account')
        self.assertEqual(response.status_code, 401)

    def test_delete_account_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/deleteAccount', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteAccount')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_account')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_account_missing_parameter_accountLabel_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'accountLabel\' is a required property"}}'

        response = self.client.post('/deleteAccount', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteAccount')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_account')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_account_too_short_parameter_accountLabel_returns_400(self):
        self.client = Client()

        short_accountLabel = ''
        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": short_accountLabel
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_accountLabel + '\' is too short"}}'

        response = self.client.post('/deleteAccount', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteAccount')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_account')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_account_too_long_parameter_accountLabel_returns_400(self):
        self.client = Client()

        long_accountLabel = '1' * 101
        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": long_accountLabel
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_accountLabel + '\' is too long"}}'

        response = self.client.post('/deleteAccount', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteAccount')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_account')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_account_invalid_parameter_account_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": "accountLabel1"
            }
        )

        expected_response_body = '{"error": {"message": "Account does not exist."}}'

        response = self.client.post('/deleteAccount', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteAccount')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_account')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_delete_account_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "accountLabel": "accountLabelGoogle"
            }
        )
        error = False

        expected_response_body = '{"submitted": true}'

        response = self.client.post('/deleteAccount', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        try:
            google_key = Profile.objects.filter(user=self.user)[0].google_accounts.all().filter(label='accountLabel')[0]
        except:
            error = True

        resolver = resolve('/deleteAccount')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_account')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(error, True)
        self.assertEqual(expected_response_body, response_body)


class GetInstallationStatus(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabelGoogle',
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabelAli',
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabelAws',
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabelAzure',
            user=self.user
        )
        self.azure_account.save()
        self.cluster1 = Clusters(
            title='testCluster1', installstep=3, type=1, user=self.user,
            providers='["Alicloud Cloud", "Amazon Web Services", "Google", "Azure"]'
        )
        self.cluster1.save()
    
    def test_get_installation_status_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/getInstallationStatus')

        resolver = resolve('/getInstallationStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_installation_status')
        self.assertEqual(response.status_code, 401)

    def test_get_installation_status_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/getInstallationStatus', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getInstallationStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_installation_status')
        self.assertEqual(response.status_code, 401)

    def test_get_installation_status_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/getInstallationStatus', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getInstallationStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_installation_status')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_installation_status_missing_parameter_ID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'ID\' is a required property"}}'

        response = self.client.post('/getInstallationStatus', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getInstallationStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_installation_status')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_installation_status_too_short_parameter_ID_returns_400(self):
        self.client = Client()

        short_ID = '132'
        request_body = json.dumps(
            {
                "ID": short_ID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_ID + '\' is too short"}}'

        response = self.client.post('/getInstallationStatus', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getInstallationStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_installation_status')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_installation_status_too_long_parameter_ID_returns_400(self):
        self.client = Client()

        long_ID = '1' * 101
        request_body = json.dumps(
            {
                "ID": long_ID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_ID + '\' is too long"}}'

        response = self.client.post('/getInstallationStatus', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getInstallationStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_installation_status')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_installation_status_invalid_parameter_ID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "ID": "1" * 36
            }
        )

        expected_response_body = '{"error": {"message": "Internal Server Error."}}'

        response = self.client.post('/getInstallationStatus', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getInstallationStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_installation_status')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_installation_status_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "ID": str(self.cluster1.id)
            }
        )

        expected_response_body = '{"installStep": 3}'

        response = self.client.post('/getInstallationStatus', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getInstallationStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_installation_status')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)

    def test_get_installation_status_valid_with_error_message_returns_200(self):
        self.client = Client()

        encoded_error_bytes = base64.b64encode('error_msg'.encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")
        cluster = Clusters.objects.filter(id=self.cluster1.id)[0]
        cluster.installstep = -3
        cluster.error_msg = encoded_error
        cluster.save()

        request_body = json.dumps(
            {
                "ID": str(self.cluster1.id)
            }
        )

        expected_response_body = '{"installStep": -3, "errorMsg": "ZXJyb3JfbXNn"}'

        response = self.client.post('/getInstallationStatus', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getInstallationStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_installation_status')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class GetResizeStatus(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabelGoogle',
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabelAli',
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabelAws',
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabelAzure',
            user=self.user
        )
        self.azure_account.save()
        self.cluster1 = Clusters(
            title='testCluster1', installstep=0, resizestep=3, type=1, user=self.user,
            providers='["Alicloud Cloud", "Amazon Web Services", "Google", "Azure"]'
        )
        self.cluster1.save()
    
    def test_get_resize_status_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/getResizeStatus')

        resolver = resolve('/getResizeStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_resize_status')
        self.assertEqual(response.status_code, 401)

    def test_get_resize_status_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/getResizeStatus', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getResizeStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_resize_status')
        self.assertEqual(response.status_code, 401)

    def test_get_resize_status_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/getResizeStatus', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getResizeStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_resize_status')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_resize_status_missing_parameter_ID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'ID\' is a required property"}}'

        response = self.client.post('/getResizeStatus', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getResizeStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_resize_status')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_resize_status_too_short_parameter_ID_returns_400(self):
        self.client = Client()

        short_ID = '132'
        request_body = json.dumps(
            {
                "ID": short_ID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_ID + '\' is too short"}}'

        response = self.client.post('/getResizeStatus', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getResizeStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_resize_status')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_resize_status_too_long_parameter_ID_returns_400(self):
        self.client = Client()

        long_ID = '1' * 101
        request_body = json.dumps(
            {
                "ID": long_ID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_ID + '\' is too long"}}'

        response = self.client.post('/getResizeStatus', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getResizeStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_resize_status')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_resize_status_invalid_parameter_ID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "ID": "1" * 36
            }
        )

        expected_response_body = '{"error": {"message": "Internal Server Error."}}'

        response = self.client.post('/getResizeStatus', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getResizeStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_resize_status')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_resize_status_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "ID": str(self.cluster1.id)
            }
        )

        expected_response_body = '{"resizeStep": 3}'

        response = self.client.post('/getResizeStatus', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getResizeStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_resize_status')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)

    def test_get_resize_status_valid_with_error_message_returns_200(self):
        self.client = Client()

        encoded_error_bytes = base64.b64encode('error_msg'.encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")
        cluster = Clusters.objects.filter(id=self.cluster1.id)[0]
        cluster.resizestep = -3
        cluster.error_msg = encoded_error
        cluster.save()
        request_body = json.dumps(
            {
                "ID": str(self.cluster1.id)
            }
        )

        expected_response_body = '{"resizeStep": -3, "errorMsg": "ZXJyb3JfbXNn"}'

        response = self.client.post('/getResizeStatus', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getResizeStatus')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_resize_status')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class GetClusterList(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        self.cluster1 = Clusters(
            title='testCluster1', installstep=0, type=1, user=self.user,
            providers='["Alicloud Cloud", "Amazon Web Services", "Google", "Azure"]'
        )
        self.cluster1.save()

        self.cluster2 = Clusters(
            title='testCluster2', installstep=0, type=2, user=self.user,
            providers='["Google"]'
        )
        self.cluster2.save()

    def test_get_cluster_list_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/getClusterList')

        resolver = resolve('/getClusterList')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_list')
        self.assertEqual(response.status_code, 401)

    def test_get_cluster_list_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/getClusterList', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getClusterList')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_list')
        self.assertEqual(response.status_code, 401)

    # def test_get_cluster_list_correct_no_users_returns_200(self):
    #     self.client = Client()

    #     expected_response_body = '''[
    #         {
    #             "id": "''' + str(self.cluster1.id) + '''", 
    #             "name": "testCluster1",
    #             "installstep": 0,
    #             "type": 1,
    #             "status": 0,
    #             "error_msg_delete": null,
    #             "providers": ''' + str(self.cluster1.providers) + ''',
    #             "created_at": "''' + str(self.cluster1.created_at) + '''"
    #         },
    #         {
    #             "id": "''' + str(self.cluster2.id) + '''",
    #             "name": "testCluster2",
    #             "installstep": 0,
    #             "type": 2,
    #             "status": 0,
    #             "error_msg_delete": null,
    #             "providers": ''' + str(self.cluster2.providers) + ''',
    #             "created_at": "''' + str(self.cluster2.created_at) + '''"
    #         }
    #     ]'''
    #     expected_response_body = str(json.loads(expected_response_body))

    #     response = self.client.post('/getClusterList', content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
    #     response_body = str(json.loads(response.content.decode()))

    #     resolver = resolve('/getClusterList')

    #     self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_list')
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(expected_response_body, response_body)


class CreateVMs(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        regions = '''[
            {
                "name": "region",
                "zones": [
                    {
                        "name": "zone",
                        "instances": [
                            {
                                "name": "instanceType",
                                "description": "description"
                            }
                        ]
                    }
                ]
            }
        ]'''

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        self.azure_account.save()

        self.cluster_with_same_name = Clusters(
            title='same_name', name='ctest', installstep=0, type=1, user=self.user
        )
        self.cluster_with_same_name.save()

    def test_create_VMs_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/createVMs')

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(response.status_code, 401)

    def test_create_VMs_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/createVMs', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(response.status_code, 401)

    def test_create_VMs_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/createVMs', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_missing_parameter_clusterName_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "alicloudSelected": True
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterName\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_too_short_parameter_clusterName_returns_400(self):
        self.client = Client()

        short_clusterName = ''
        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": short_clusterName,
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "alicloud": {
                    "region": "region",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterName + '\' is too short"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_too_long_parameter_clusterName_returns_400(self):
        self.client = Client()

        long_clusterName = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": long_clusterName,
                "alicloudSelected": True,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "alicloud": {
                    "region": "region",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterName + '\' is too long"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_no_provider_is_selected_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False
            }
        )

        expected_response_body = '{"error": {"message": "No provider is selected."}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_aws_is_selected_no_region_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'region\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_aws_is_selected_no_zone_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'zone\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_aws_is_selected_no_instanceType_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'instanceType\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_aws_is_selected_no_nodes_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'nodes\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_aws_is_selected_no_vpcCidr_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'vpcCidr\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_aws_is_selected_no_account_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'account\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_aws_is_selected_no_operating_system_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'operatingSystem\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_google_is_selected_no_region_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'region\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_google_is_selected_no_zone_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'zone\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_google_is_selected_no_instanceType_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'instanceType\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_google_is_selected_no_nodes_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'nodes\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_google_is_selected_no_vpcCidr_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'vpcCidr\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_google_is_selected_no_account_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'account\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_google_is_selected_no_operating_system_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'operatingSystem\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_azure_is_selected_no_region_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'region\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_azure_is_selected_no_zone_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'zone\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_azure_is_selected_no_instanceType_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'instanceType\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_azure_is_selected_no_nodes_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'nodes\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_azure_is_selected_no_vpcCidr_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'vpcCidr\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_azure_is_selected_no_account_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'account\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_azure_is_selected_no_operating_system_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'operatingSystem\' is a required property"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_occupied_name_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "same_name",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "Environment with that name already exists."}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_invalid_region_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region1",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "Provider region is not legal"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_invalid_zone_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone1",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "Provider zone is not legal"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_invalid_instanceType_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType1",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "Provider instanceType is not legal"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_invalid_account_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType1",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel123",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "Account does not exist"}}'

        response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_VMs_valid_returns_200(self):
        self.client = Client()

        expected_call_args1 = '''call({'internal_dns_zone': 'test.test', 'clusterName': 'clusterName', 'kubernetesConfiguration': {'version': 'v1.19.7', 'serviceAddresses': '192.168.0.0/24', 'podsSubnet': '192.168.1.0/24', 'networkPlugin': 'flannel'}, 'alicloudSelected': False, 'awsSelected': False, 'googleSelected': False, 'azureSelected': True, 'onPremiseSelected': False, 'iotArmSelected': False, 'azure': {'region': 'region', 'zone': 'zone', 'instanceType': 'instanceType', 'nodes': 1, 'vpcCidr': '10.0.0.0/16', 'account': 'accountLabel', 'operatingSystem': 'Ubuntu 18.04'}},'''
        expected_call_args2 = '\'), 1)'

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        with patch.object(tasks.worker_create_vms, 'delay') as mock:
            with patch.object(authorization_service, 'Authorize') as authorize_mock:
                authorize_mock.side_effect = func_returns_none
                mock.side_effect = func_worker_validate_credentials

                response = self.client.post('/createVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
                response_body = response.content.decode()

                resolver = resolve('/createVMs')

                mock.assert_called()

                self.assertEqual(str(mock.call_args_list[0]).startswith(expected_call_args1), True)
                self.assertEqual(str(mock.call_args_list[0]).endswith(expected_call_args2), True)
                self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_VMs')
                self.assertEqual(response.status_code, 200)


class AddService(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        self.cluster = Clusters(
            name='testCluster',
            user=self.user,
            type=1,
            tfconfig=''
        )
        self.cluster.save()
        self.profile = self.user.profile
        self.clusterID = self.cluster.id
        self.profile.save()

        self.service_without_yaml = Service(
            id=1,
            name='mysql',
            description='description',
            logo_url='logo_url',
            options='{"name":{"choice":"custom","type":"string"},"service_type":{"choice":"single","values":["ClusterIP","LoadBalancer"],"default":"ClusterIP"},"cloud_providers":{"choice":"multiple","values":["google","aws","azure","alicloud"]},"yamlConfig":false}'
        )
        self.service_without_yaml.save()

        self.service_with_yaml = Service(
            id=2,
            name='mysql_with_yaml',
            description='description',
            logo_url='logo_url',
            options='{"yamlConfig": true}',
            values_file='values_file'
        )
        self.service_with_yaml.save()

    def test_add_service_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/addService')

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(response.status_code, 401)

    def test_add_service_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/addService', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(response.status_code, 401)

    def test_add_service_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/addService', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_missing_parameter_serviceName_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "configurationType": "configurationType",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'serviceName\' is a required property"}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_too_short_parameter_serviceName_returns_400(self):
        self.client = Client()

        short_serviceName = '1'
        request_body = json.dumps(
            {
                "serviceName": short_serviceName,
                "configurationType": "configurationType",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + short_serviceName + '\' is too short"}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_too_long_parameter_serviceName_returns_400(self):
        self.client = Client()

        long_serviceName = '12345678911234567891123456789112'
        request_body = json.dumps(
            {
                "serviceName": long_serviceName,
                "configurationType": "configurationType",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + long_serviceName + '\' is too long"}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_missing_parameter_configurationType_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'configurationType\' is a required property"}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_too_short_parameter_configurationType_returns_400(self):
        self.client = Client()

        short_configurationType = '1'
        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "configurationType": short_configurationType,
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + short_configurationType + '\' is too short"}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_too_long_parameter_configurationType_returns_400(self):
        self.client = Client()

        long_configurationType = '12345678911234567891123456789112'
        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "configurationType": long_configurationType,
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + long_configurationType + '\' is too long"}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "configurationType": "configurationType"
            }   
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '1'
        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "configurationType": "simpleConfig",
                "clusterID": short_clusterID
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '12345678911234567891123456789112345678'
        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "configurationType": "simpleConfig",
                "clusterID": long_clusterID
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_invalid_parameter_configurationType_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "configurationType": "yamllconfig",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "configurationType is invalid."}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_invalid_parameter_clusterID_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "configurationType": "simpleConfig",
                "clusterID": '123456789112345678911234567891123456'
            }   
        )

        expected_response_body = '{"error": {"message": "Invalid parameter clusterID"}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_add_service_cluster_not_running_returns_500(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.status = 10
        cluster.save()
        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "configurationType": "simpleConfig",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "Cluster is not running."}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_add_service_invalid_service_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "serviceName": "mysql1",
                "configurationType": "simpleConfig",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "Service does not exist."}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_add_service_unsupported_yamlconfig_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "configurationType": "yamlConfig",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "Service does not support yamlConfig."}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_add_service_invalid_valuesFile_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "serviceName": "mysql_with_yaml",
                "configurationType": "yamlConfig",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "valuesFile is invalid."}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_missing_parameter_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "configurationType": "simpleConfig",
                "service_type": "ClusterIP",
                "cloud_providers": [
                    'aws',
                    'google'
                ],
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "name parameter is missing."}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_invalid_custom_parameter_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "name": "",
                "configurationType": "simpleConfig",
                "service_type": "ClusterIP",
                "cloud_providers": [
                    'aws',
                    'google'
                ],
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "name parameter is invalid."}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_invalid_single_parameter_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "name": "name",
                "namespace": "namespace",
                "configurationType": "simpleConfig",
                "service_type": "invalid",
                "cloud_providers": [
                    'aws',
                    'google'
                ],
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "service_type parameter is invalid."}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_multiple_parameter_not_a_list_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "name": "name",
                "namespace": "namespace",
                "configurationType": "simpleConfig",
                "service_type": "ClusterIP",
                "cloud_providers": "not_a_list",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "cloud_providers parameter is invalid."}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_invalid_multiple_parameter_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "name": "name",
                "namespace": "namespace",
                "configurationType": "simpleConfig",
                "service_type": "ClusterIP",
                "cloud_providers": [
                    'aws',
                    'invalid'
                ],
                "clusterID": str(self.cluster.id)
            }  
        )

        expected_response_body = '{"error": {"message": "cloud_providers parameter is invalid."}}'

        response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_service_valid_simpleConfig_returns_200(self):
        self.client = Client()

        expected_call_args1 = 'call(\'mysql\', \'simpleConfig\', {\'name\': \'name\','
        expected_call_args1 += ' \'service_type\': \'ClusterIP\', \'cloud_providers\': [\'aws\', \'google\']}'
        expected_call_args1 += ', UUID(\''
        expected_call_args2 = '\'))'

        request_body = json.dumps(
            {
                "serviceName": "mysql",
                "name": "name",
                "configurationType": "simpleConfig",
                "service_type": "ClusterIP",
                "cloud_providers": [
                    'aws',
                    'google'
                ],
                "clusterID": str(self.cluster.id)
            }
        )

        with patch.object(tasks.worker_add_service_kubernetes_cluster, 'delay') as mock:
            with patch.object(authorization_service, 'Authorize') as authorize_mock:
                authorize_mock.side_effect = func_returns_none
                mock.side_effect = func_worker_validate_credentials

                response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
                response_body = response.content.decode()

                resolver = resolve('/addService')

                mock.assert_called()
                self.assertEqual(str(mock.call_args_list[0]).startswith(expected_call_args1), True)
                self.assertEqual(str(mock.call_args_list[0]).endswith(expected_call_args2), True)
                self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
                self.assertEqual(response.status_code, 200)

    def test_add_service_valid_advancedConfig_returns_200(self):
        self.client = Client()

        expected_call_args1 = 'call(\'mysql_with_yaml\', \'yamlConfig\', \''
        expected_call_args1 += 'valuesFile\', UUID(\''
        expected_call_args2 = '\'))'

        request_body = json.dumps(
            {
                "serviceName": "mysql_with_yaml",
                "configurationType": "yamlConfig",
                "valuesFile": "valuesFile",
                "clusterID": str(self.cluster.id)
            }
        )

        with patch.object(tasks.worker_add_service_kubernetes_cluster, 'delay') as mock:
            with patch.object(authorization_service, 'Authorize') as authorize_mock:
                authorize_mock.side_effect = func_returns_none
                mock.side_effect = func_worker_validate_credentials

                response = self.client.post('/addService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
                response_body = response.content.decode()

                resolver = resolve('/addService')

                mock.assert_called()

                self.assertEqual(str(mock.call_args_list[0]).startswith(expected_call_args1), True)
                self.assertEqual(str(mock.call_args_list[0]).endswith(expected_call_args2), True)
                self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_service')
                self.assertEqual(response.status_code, 200)


class DeleteService(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        self.cluster = Clusters(
            name='testCluster',
            user=self.user,
            type=1
        )
        self.cluster.save()
        self.service = ClusterService(
            cluster=self.cluster,
            name='name',
            namespace='namespace'
        )
        self.service.save()
        self.clusterID = self.cluster.id
        self.profile = self.user.profile
        self.profile.save()

    def test_delete_service_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/deleteService')

        resolver = resolve('/deleteService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
        self.assertEqual(response.status_code, 401)

    def test_delete_service_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/deleteService', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/deleteService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
        self.assertEqual(response.status_code, 401)

    def test_delete_service_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/deleteService', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_service_missing_parameter_name_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "namespace": "namespace",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'name\' is a required property"}}'

        response = self.client.post('/deleteService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_service_too_short_parameter_name_returns_400(self):
        self.client = Client()

        short_name = '1'
        request_body = json.dumps(
            {
                "name": short_name,
                "namespace": "namespace",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + short_name + '\' is too short"}}'

        response = self.client.post('/deleteService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_values_too_long_parameter_name_returns_400(self):
        self.client = Client()

        long_name = '12345678911234567891123456789112'
        request_body = json.dumps(
            {
                "name": long_name,
                "namespace": "namespace",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + long_name + '\' is too long"}}'

        response = self.client.post('/deleteService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_service_too_short_parameter_namespace_returns_400(self):
        self.client = Client()

        short_namespace = '1'
        request_body = json.dumps(
            {
                "name": "name",
                "namespace": short_namespace,
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + short_namespace + '\' is too short"}}'

        response = self.client.post('/deleteService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_values_too_long_parameter_namespace_returns_400(self):
        self.client = Client()

        long_namespace = '12345678911234567891123456789112'
        request_body = json.dumps(
            {
                "name": "name",
                "namespace": long_namespace,
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + long_namespace + '\' is too long"}}'

        response = self.client.post('/deleteService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_service_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "name": "name",
                "serviceName": "serviceName",
                "namespace": "namespace",
                "configurationType": "configurationType",
                "valuesFile": "valuesFile",
                "cloudProviders": {
                    "alicloudSelected": False,
                    "awsSelected": False,
                    "googleSelected": False,
                    "azureSelected": False,
                    "onPremiseSelected": False,
                    "iotArmSelected": False
                }
            }   
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/deleteService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_service_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '1'
        request_body = json.dumps(
            {
                "name": "name",
                "namespace": "namespace",
                "clusterID": short_clusterID
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/deleteService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_service_values_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '12345678911234567891123456789112345678'
        request_body = json.dumps(
            {
                "name": "name",
                "namespace": "namespace",
                "clusterID": long_clusterID
            }   
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/deleteService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_service_invalid_parameter_clusterID_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "name": "name",
                "namespace": "namespace",
                "clusterID": '123456789112345678911234567891123456'
            }   
        )

        expected_response_body = '{"error": {"message": "Invalid parameter clusterID"}}'

        response = self.client.post('/deleteService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)
    
    def test_delete_service_not_running_cluster_returns_500(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.status = 10
        cluster.save()
        request_body = json.dumps(
            {
                "name": "name",
                "namespace": "namespace",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "Cluster is not running."}}'

        response = self.client.post('/deleteService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_delete_service_invalid_parameter_name_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "name": "invalid_name",
                "namespace": "namespace",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "Service does not exist."}}'

        response = self.client.post('/deleteService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_delete_service_invalid_parameter_namespace_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "name": "name",
                "namespace": "invalid_namespace",
                "clusterID": str(self.cluster.id)
            }   
        )

        expected_response_body = '{"error": {"message": "Service does not exist."}}'

        response = self.client.post('/deleteService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteService')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_delete_service_valid_returns_200(self):
        self.client = Client()

        expected_call_args1 = 'call(\'name\', \'namespace\', '
        expected_call_args1 += '\''
        expected_call_args2 = '\')'

        request_body = json.dumps(
            {
                "name": "name",
                "namespace": "namespace",
                "clusterID": str(self.cluster.id)
            }
        )

        with patch.object(tasks.worker_delete_service_kubernetes_cluster, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials

            response = self.client.post('/deleteService', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            resolver = resolve('/deleteService')

            mock.assert_called()
            self.assertEqual(str(mock.call_args_list[0]).startswith(expected_call_args1), True)
            self.assertEqual(str(mock.call_args_list[0]).endswith(expected_call_args2), True)
            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_service')
            self.assertEqual(response.status_code, 200)

class GetClusterKubeconfig(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            user=self.user
        )
        self.azure_account.save()

        tfconfig = {
            "alicloudSelected": False, 
            "awsSelected": False, 
            "googleSelected": False, 
            "azureSelected": True,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "azure": {
                "account": "",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }
        }
        self.cluster = Clusters(
            title='name', name='ctest', installstep=0, type=1, user=self.user,
            tfconfig=json.dumps(tfconfig),
            kubeconfig="kubeconfig"
        )
        self.cluster.save()
        self.clusterID =  str(self.cluster.id)
    
    def test_get_cluster_kubeconfig_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/getClusterKubeconfig')

        resolver = resolve('/getClusterKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_kubeconfig')
        self.assertEqual(response.status_code, 401)

    def test_get_cluster_kubeconfig_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/getClusterKubeconfig', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getClusterKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_kubeconfig')
        self.assertEqual(response.status_code, 401)

    def test_get_cluster_kubeconfig_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/getClusterKubeconfig', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_kubeconfig')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_cluster_kubeconfig_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "username": "username"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/getClusterKubeconfig', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_kubeconfig')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_cluster_kubeconfig_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID,
                "username": "username"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/getClusterKubeconfig', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_kubeconfig')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_cluster_kubeconfig_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1' * 40
        request_body = json.dumps(
            {
                "clusterID": long_clusterID,
                "username": "username"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/getClusterKubeconfig', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_kubeconfig')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_cluster_kubeconfig_invalid_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": 'a'*36,
                "username": "username"
            }
        )

        expected_response_body = '{"error": {"message": "Cluster doesn\'t exist."}}'

        response = self.client.post('/getClusterKubeconfig', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_kubeconfig')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_cluster_kubeconfig_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"kubeconfig": "kubeconfig"}'

        response = self.client.post('/getClusterKubeconfig', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getClusterKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_cluster_kubeconfig')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class GetUserKubeconfig(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            user=self.user
        )
        self.azure_account.save()

        tfconfig = {
            "alicloudSelected": False, 
            "awsSelected": False, 
            "googleSelected": False, 
            "azureSelected": True,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "azure": {
                "account": "",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }
        }
        self.cluster = Clusters(
            title='name', name='ctest', installstep=0, type=1, user=self.user,
            tfconfig=json.dumps(tfconfig)
        )
        self.cluster.save()
        self.clusterID =  str(self.cluster.id)
        self.cluster_user = ClusterUser(
            cluster=self.cluster,
            username='username',
            kubeconfig='kubeconfig',
            kubernetes_user=True
        )
        self.cluster_user.save()
    
    def test_get_user_kubeconfig_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/getUserKubeconfig')

        resolver = resolve('/getUserKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_kubeconfig')
        self.assertEqual(response.status_code, 401)

    def test_get_user_kubeconfig_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/getUserKubeconfig', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/getUserKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_kubeconfig')
        self.assertEqual(response.status_code, 401)

    def test_get_user_kubeconfig_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/getUserKubeconfig', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getUserKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_kubeconfig')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_user_kubeconfig_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "username": "username"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/getUserKubeconfig', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getUserKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_kubeconfig')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_user_kubeconfig_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID,
                "username": "username"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/getUserKubeconfig', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getUserKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_kubeconfig')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_user_kubeconfig_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1' * 40
        request_body = json.dumps(
            {
                "clusterID": long_clusterID,
                "username": "username"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/getUserKubeconfig', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getUserKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_kubeconfig')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_user_kubeconfig_missing_parameter_username_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'username\' is a required property"}}'

        response = self.client.post('/getUserKubeconfig', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getUserKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_kubeconfig')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_get_user_kubeconfig_invalid_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": 'a'*36,
                "username": "username"
            }
        )

        expected_response_body = '{"error": {"message": "Cluster doesn\'t exist."}}'

        response = self.client.post('/getUserKubeconfig', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getUserKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_kubeconfig')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)
    
    def test_get_user_kubeconfig_invalid_username_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "username": "ivalid"
            }
        )

        expected_response_body = '{"error": {"message": "Cluster user doesn\'t exist."}}'

        response = self.client.post('/getUserKubeconfig', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getUserKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_kubeconfig')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_get_user_kubeconfig_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "username": "username"   
            }
        )

        expected_response_body = '{"kubeconfig": "kubeconfig"}'

        response = self.client.post('/getUserKubeconfig', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getUserKubeconfig')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_kubeconfig')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class RenameCluster(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        self.cluster = Clusters(
            title='name', name='ctest', installstep=0, type=2, user=self.user)
        self.cluster.save()
        self.clusterID =  str(self.cluster.id)
    
    def test_rename_cluster_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/renameCluster')

        resolver = resolve('/renameCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.rename_cluster')
        self.assertEqual(response.status_code, 401)

    def test_rename_cluster_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/renameCluster', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/renameCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.rename_cluster')
        self.assertEqual(response.status_code, 401)

    def test_rename_cluster_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/renameCluster', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/renameCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.rename_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_rename_cluster_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "name"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/renameCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/renameCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.rename_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_rename_cluster_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID,
                "clusterName": "name"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/renameCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/renameCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.rename_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_rename_cluster_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1' * 40
        request_body = json.dumps(
            {
                "clusterID": long_clusterID,
                "clusterName": "name"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/renameCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/renameCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.rename_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_rename_cluster_invalid_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": 'a'*36,
                "clusterName": "name"
            }
        )

        expected_response_body = '{"error": {"message": "Cluster doesn\'t exist."}}'

        response = self.client.post('/renameCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/renameCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.rename_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_rename_cluster_missing_parameter_clusterName_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterName\' is a required property"}}'

        response = self.client.post('/renameCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/renameCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.rename_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_rename_cluster_too_short_parameter_clusterName_returns_400(self):
        self.client = Client()

        short_clusterName = ''
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "clusterName": short_clusterName
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterName + '\' is too short"}}'

        response = self.client.post('/renameCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/renameCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.rename_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_rename_cluster_too_long_parameter_clusterName_returns_400(self):
        self.client = Client()

        long_clusterName = '1' * 1025
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "clusterName": long_clusterName
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterName + '\' is too long"}}'

        response = self.client.post('/renameCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/renameCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.rename_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_rename_cluster_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "clusterName": "name"
            }
        )

        with patch.object(tasks.worker_delete_resources, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials

            response = self.client.post('/renameCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')

            resolver = resolve('/renameCluster')

            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.rename_cluster')
            self.assertEqual(response.status_code, 200)


class DeleteCluster(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            user=self.user
        )
        self.azure_account.save()

        tfconfig = {
            "alicloudSelected": False, 
            "awsSelected": False, 
            "googleSelected": False, 
            "azureSelected": True,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "azure": {
                "account": "",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }
        }
        self.cluster = Clusters(
            title='name', name='ctest', installstep=0, type=2, user=self.user,
            tfconfig=json.dumps(tfconfig)
        )
        self.cluster.save()
        self.clusterID =  str(self.cluster.id)
    
    def test_delete_cluster_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/deleteCluster')

        resolver = resolve('/deleteCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_cluster')
        self.assertEqual(response.status_code, 401)

    def test_delete_cluster_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/deleteCluster', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/deleteCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_cluster')
        self.assertEqual(response.status_code, 401)

    def test_delete_cluster_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/deleteCluster', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_cluster_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/deleteCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_cluster_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/deleteCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_cluster_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1' * 40
        request_body = json.dumps(
            {
                "clusterID": long_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/deleteCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_cluster_invalid_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": 'a'*36
            }
        )

        expected_response_body = '{"error": {"message": "Cluster doesn\'t exist."}}'

        response = self.client.post('/deleteCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/deleteCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_delete_cluster_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        with patch.object(tasks.worker_delete_resources, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials

            response = self.client.post('/deleteCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            celerytask = models.CeleryTask.objects.filter(id=json.loads(response_body)['taskId'])[0]
            expected_response_body = '{"taskId": "' + str(celerytask.id) + '"}'

            resolver = resolve('/deleteCluster')

            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_cluster')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(expected_response_body, response_body)


class StopCluster(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            user=self.user
        )
        self.azure_account.save()

        tfconfig = {
            "alicloudSelected": False, 
            "awsSelected": False, 
            "googleSelected": False, 
            "azureSelected": True,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "azure": {
                "account": "",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }
        }
        self.cluster = Clusters(
            title='name', name='ctest', installstep=0, type=2, user=self.user,
            tfconfig=json.dumps(tfconfig)
        )
        self.cluster.save()
        self.clusterID =  str(self.cluster.id)
    
    def test_stop_cluster_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/stopCluster')

        resolver = resolve('/stopCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_cluster')
        self.assertEqual(response.status_code, 401)

    def test_stop_cluster_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/stopCluster', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/stopCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_cluster')
        self.assertEqual(response.status_code, 401)

    def test_stop_cluster_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/stopCluster', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_cluster_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/stopCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_cluster_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/stopCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_cluster_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1' * 40
        request_body = json.dumps(
            {
                "clusterID": long_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/stopCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_cluster_invalid_parameter_clusterID_returns_400(self):
        self.client = Client()

        invalid_clusterID = '1' * 36
        request_body = json.dumps(
            {
                "clusterID": invalid_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster doesn\'t exist."}}'

        response = self.client.post('/stopCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_cluster_not_installed_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.installstep = 5
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster is not ready."}}'

        response = self.client.post('/stopCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_cluster_is_stopped_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.status = 10
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster is stopped/stopping."}}'

        response = self.client.post('/stopCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_cluster_is_stopping_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.status = 2
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster is stopped/stopping."}}'

        response = self.client.post('/stopCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_cluster_is_restarting_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.status = 3
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster is stopped/stopping."}}'

        response = self.client.post('/stopCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_cluster_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        with patch.object(tasks.worker_stop_cluster, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials

            response = self.client.post('/stopCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            celerytask = models.CeleryTask.objects.filter(id=json.loads(response_body)['taskId'])[0]

            expected_response_body = '{"taskId": "' + str(celerytask.id) + '"}'

            resolver = resolve('/stopCluster')

            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_cluster')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(expected_response_body, response_body)

class StartCluster(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            user=self.user
        )
        self.azure_account.save()

        tfconfig = {
            "alicloudSelected": False, 
            "awsSelected": False, 
            "googleSelected": False, 
            "azureSelected": True,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "azure": {
                "account": "",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }
        }
        self.cluster = Clusters(
            title='name', name='ctest', installstep=0, type=2, user=self.user, status=10,
            tfconfig=json.dumps(tfconfig)
        )
        self.cluster.save()
        self.clusterID =  str(self.cluster.id)
    
    def test_start_cluster_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/startCluster')

        resolver = resolve('/startCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_cluster')
        self.assertEqual(response.status_code, 401)

    def test_start_cluster_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/startCluster', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/startCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_cluster')
        self.assertEqual(response.status_code, 401)

    def test_start_cluster_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/startCluster', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_cluster_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/startCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_cluster_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/startCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_cluster_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1' * 40
        request_body = json.dumps(
            {
                "clusterID": long_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/startCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_cluster_invalid_parameter_clusterID_returns_400(self):
        self.client = Client()

        invalid_clusterID = '1' * 36
        request_body = json.dumps(
            {
                "clusterID": invalid_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster doesn\'t exist."}}'

        response = self.client.post('/startCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_start_cluster_not_installed_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.installstep = 5
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster is not ready."}}'

        response = self.client.post('/startCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_cluster_is_started_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.status = 0
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster is running/starting."}}'

        response = self.client.post('/startCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_cluster_is_starting_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.status = 1
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster is running/starting."}}'

        response = self.client.post('/startCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_cluster_is_restarting_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.status = 3
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster is running/starting."}}'

        response = self.client.post('/startCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_cluster_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        with patch.object(tasks.worker_start_cluster, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials

            response = self.client.post('/startCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            celerytask = models.CeleryTask.objects.filter(id=json.loads(response_body)['taskId'])[0]
            expected_response_body = '{"taskId": "' + str(celerytask.id) + '"}'

            resolver = resolve('/startCluster')

            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_cluster')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(expected_response_body, response_body)

class RestartCluster(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            user=self.user
        )
        self.azure_account.save()

        tfconfig = {
            "alicloudSelected": False, 
            "awsSelected": False, 
            "googleSelected": False, 
            "azureSelected": True,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "azure": {
                "account": "",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }
        }
        self.cluster = Clusters(
            title='name', name='ctest', installstep=0, type=2, user=self.user, status=10,
            tfconfig=json.dumps(tfconfig)
        )
        self.cluster.save()
        self.clusterID =  str(self.cluster.id)
    
    def test_restart_cluster_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/restartCluster')

        resolver = resolve('/restartCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_cluster')
        self.assertEqual(response.status_code, 401)

    def test_restart_cluster_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/restartCluster', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/restartCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_cluster')
        self.assertEqual(response.status_code, 401)

    def test_restart_cluster_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/restartCluster', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_cluster_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/restartCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_cluster_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/restartCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_cluster_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1' * 40
        request_body = json.dumps(
            {
                "clusterID": long_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/restartCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_cluster_invalid_parameter_clusterID_returns_400(self):
        self.client = Client()

        invalid_clusterID = '1' * 36
        request_body = json.dumps(
            {
                "clusterID": invalid_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster doesn\'t exist."}}'

        response = self.client.post('/restartCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_restart_cluster_not_installed_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.installstep = 5
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster is not ready."}}'

        response = self.client.post('/restartCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_cluster_is_not_started_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.status = 10
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster is not running."}}'

        response = self.client.post('/restartCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_cluster_valid_returns_200(self):
        self.client = Client()
        
        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.status = 0
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        with patch.object(tasks.worker_restart_cluster, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials

            response = self.client.post('/restartCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            celerytask = models.CeleryTask.objects.filter(id=json.loads(response_body)['taskId'])[0]
            expected_response_body = '{"taskId": "' + str(celerytask.id) + '"}'

            resolver = resolve('/restartCluster')

            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_cluster')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(expected_response_body, response_body)

class StopMachine(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            user=self.user
        )
        self.azure_account.save()

        tfconfig = {
            "alicloudSelected": False, 
            "awsSelected": False, 
            "googleSelected": False, 
            "azureSelected": True,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "azure": {
                "account": "",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }
        }
        self.cluster = Clusters(
            title='name', name='ctest', installstep=0, type=2, user=self.user, status=10,
            tfconfig=json.dumps(tfconfig)
        )
        self.cluster.save()
        self.clusterID = str(self.cluster.id)
        self.machine = Machine(
            name='baa54d9e67-node-01.gcp.daiteap.internal', provider='google', cluster_id=self.clusterID
        )
        self.machine.save()
        self.machineID = str(self.machine.id)
    
    def test_stop_machine_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/stopMachine')

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(response.status_code, 401)

    def test_stop_machine_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/stopMachine', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(response.status_code, 401)

    def test_stop_machine_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/stopMachine', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_machine_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_machine_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_machine_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1' * 40
        request_body = json.dumps(
            {
                "clusterID": long_clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_machine_missing_parameter_machineName_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'machineName\' is a required property"}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_machine_too_short_parameter_machineName_returns_400(self):
        self.client = Client()

        short_machineName = '123'
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": short_machineName,
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_machineName + '\' is too short"}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_machine_too_long_parameter_machineName_returns_400(self):
        self.client = Client()

        long_machineName = '1' * 151
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": long_machineName,
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_machineName + '\' is too long"}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_machine_missing_parameter_machineProvider_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal"
            }
        )

        expected_response_body = '{"error": {"message": "\'machineProvider\' is a required property"}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_machine_too_short_parameter_machineProvider_returns_400(self):
        self.client = Client()

        short_machineProvider = '12'
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": short_machineProvider
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_machineProvider + '\' is too short"}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_machine_too_long_parameter_machineProvider_returns_400(self):
        self.client = Client()

        long_machineProvider = '1' * 150
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": long_machineProvider
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_machineProvider + '\' is too long"}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_machine_invalid_parameter_clusterID_returns_400(self):
        self.client = Client()

        invalid_clusterID = '1' * 36
        request_body = json.dumps(
            {
                "clusterID": invalid_clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Cluster doesn\'t exist."}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_stop_machine_not_installed_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.installstep = 5
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Cluster is not ready."}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_machine_invalid_parameter_machineName_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.installstep = 0
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-ode-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Machine doesn\'t exist."}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_stop_machine_invalid_parameter_machineProvider_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.installstep = 0
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "googe"
            }
        )

        expected_response_body = '{"error": {"message": "Machine doesn\'t exist."}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_machine_is_stopped_returns_400(self):
        self.client = Client()

        machine = Machine.objects.filter(id=self.machineID)[0]
        machine.status = 10
        machine.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Machine is stopped/stopping."}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_machine_is_stopping_returns_400(self):
        self.client = Client()

        machine = Machine.objects.filter(id=self.machineID)[0]
        machine.status = 2
        machine.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Machine is stopped/stopping."}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_stop_machine_is_restarting_returns_400(self):
        self.client = Client()

        machine = Machine.objects.filter(id=self.machineID)[0]
        machine.status = 3
        machine.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Machine is stopped/stopping."}}'

        response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/stopMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_stop_machine_valid_returns_200(self):
        self.client = Client()
        
        machine = Machine.objects.filter(id=self.machineID)[0]
        machine.status = 0
        machine.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        with patch.object(tasks.worker_stop_machine, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials

            response = self.client.post('/stopMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            resolver = resolve('/stopMachine')

            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.stop_machine')
            self.assertEqual(response.status_code, 200)
            self.assertTrue('taskId' in response_body)


class StartMachine(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            user=self.user
        )
        self.azure_account.save()

        tfconfig = {
            "alicloudSelected": False, 
            "awsSelected": False, 
            "googleSelected": False, 
            "azureSelected": True,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "azure": {
                "account": "",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }
        }
        self.cluster = Clusters(
            title='name', name='ctest', installstep=0, type=2, user=self.user, status=10,
            tfconfig=json.dumps(tfconfig)
        )
        self.cluster.save()
        self.clusterID = str(self.cluster.id)
        self.machine = Machine(
            name='baa54d9e67-node-01.gcp.daiteap.internal', provider='google', cluster_id=self.clusterID
        )
        self.machine.save()
        self.machineID = str(self.machine.id)
    
    def test_start_machine_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/startMachine')

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(response.status_code, 401)

    def test_start_machine_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/startMachine', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(response.status_code, 401)

    def test_start_machine_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/startMachine', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_machine_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_machine_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_machine_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1' * 40
        request_body = json.dumps(
            {
                "clusterID": long_clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_machine_missing_parameter_machineName_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'machineName\' is a required property"}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_machine_too_short_parameter_machineName_returns_400(self):
        self.client = Client()

        short_machineName = '123'
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": short_machineName,
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_machineName + '\' is too short"}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_machine_too_long_parameter_machineName_returns_400(self):
        self.client = Client()

        long_machineName = '1' * 151
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": long_machineName,
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_machineName + '\' is too long"}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_machine_missing_parameter_machineProvider_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal"
            }
        )

        expected_response_body = '{"error": {"message": "\'machineProvider\' is a required property"}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_machine_too_short_parameter_machineProvider_returns_400(self):
        self.client = Client()

        short_machineProvider = '12'
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": short_machineProvider
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_machineProvider + '\' is too short"}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_machine_too_long_parameter_machineProvider_returns_400(self):
        self.client = Client()

        long_machineProvider = '1' * 150
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": long_machineProvider
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_machineProvider + '\' is too long"}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_machine_invalid_parameter_clusterID_returns_400(self):
        self.client = Client()

        invalid_clusterID = '1' * 36
        request_body = json.dumps(
            {
                "clusterID": invalid_clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Cluster doesn\'t exist."}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_start_machine_not_installed_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.installstep = 5
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Cluster is not ready."}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_machine_invalid_parameter_machineName_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.installstep = 0
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-ode-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Machine doesn\'t exist."}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_start_machine_invalid_parameter_machineProvider_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.installstep = 0
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "googe"
            }
        )

        expected_response_body = '{"error": {"message": "Machine doesn\'t exist."}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_machine_is_running_returns_400(self):
        self.client = Client()

        machine = Machine.objects.filter(id=self.machineID)[0]
        machine.status = 0
        machine.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Machine is running/starting."}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_machine_is_starting_returns_400(self):
        self.client = Client()

        machine = Machine.objects.filter(id=self.machineID)[0]
        machine.status = 1
        machine.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Machine is running/starting."}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_start_machine_is_restarting_returns_400(self):
        self.client = Client()

        machine = Machine.objects.filter(id=self.machineID)[0]
        machine.status = 3
        machine.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Machine is running/starting."}}'

        response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/startMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_start_machine_valid_returns_200(self):
        self.client = Client()

        machine = Machine.objects.filter(id=self.machineID)[0]
        machine.status = 10
        machine.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        with patch.object(tasks.worker_start_machine, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials

            response = self.client.post('/startMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            resolver = resolve('/startMachine')

            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.start_machine')
            self.assertEqual(response.status_code, 200)
            self.assertTrue('taskId' in response_body)


class RestartMachine(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            user=self.user
        )
        self.azure_account.save()

        tfconfig = {
            "alicloudSelected": False, 
            "awsSelected": False, 
            "googleSelected": False, 
            "azureSelected": True,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "azure": {
                "account": "",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }
        }
        self.cluster = Clusters(
            title='name', name='ctest', installstep=0, type=2, user=self.user, status=10,
            tfconfig=json.dumps(tfconfig)
        )
        self.cluster.save()
        self.clusterID = str(self.cluster.id)
        self.machine = Machine(
            name='baa54d9e67-node-01.gcp.daiteap.internal', provider='google', cluster_id=self.clusterID
        )
        self.machine.save()
        self.machineID = str(self.machine.id)
    
    def test_restart_machine_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/restartMachine')

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(response.status_code, 401)

    def test_restart_machine_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/restartMachine', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(response.status_code, 401)

    def test_restart_machine_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/restartMachine', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_machine_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/restartMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_machine_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/restartMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_machine_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1' * 40
        request_body = json.dumps(
            {
                "clusterID": long_clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/restartMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_machine_missing_parameter_machineName_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'machineName\' is a required property"}}'

        response = self.client.post('/restartMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_machine_too_short_parameter_machineName_returns_400(self):
        self.client = Client()

        short_machineName = '123'
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": short_machineName,
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_machineName + '\' is too short"}}'

        response = self.client.post('/restartMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_machine_too_long_parameter_machineName_returns_400(self):
        self.client = Client()

        long_machineName = '1' * 151
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": long_machineName,
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_machineName + '\' is too long"}}'

        response = self.client.post('/restartMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_machine_missing_parameter_machineProvider_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal"
            }
        )

        expected_response_body = '{"error": {"message": "\'machineProvider\' is a required property"}}'

        response = self.client.post('/restartMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_machine_too_short_parameter_machineProvider_returns_400(self):
        self.client = Client()

        short_machineProvider = '12'
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": short_machineProvider
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_machineProvider + '\' is too short"}}'

        response = self.client.post('/restartMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_machine_too_long_parameter_machineProvider_returns_400(self):
        self.client = Client()

        long_machineProvider = '1' * 150
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": long_machineProvider
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_machineProvider + '\' is too long"}}'

        response = self.client.post('/restartMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_machine_invalid_parameter_clusterID_returns_400(self):
        self.client = Client()

        invalid_clusterID = '1' * 36
        request_body = json.dumps(
            {
                "clusterID": invalid_clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Cluster doesn\'t exist."}}'

        response = self.client.post('/restartMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_restart_machine_not_installed_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.installstep = 5
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Cluster is not ready."}}'

        response = self.client.post('/restartMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_machine_invalid_parameter_machineName_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.installstep = 0
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-ode-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Machine doesn\'t exist."}}'

        response = self.client.post('/restartMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_restart_machine_invalid_parameter_machineProvider_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.installstep = 0
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "googe"
            }
        )

        expected_response_body = '{"error": {"message": "Machine doesn\'t exist."}}'

        response = self.client.post('/restartMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_machine_is_not_running_returns_400(self):
        self.client = Client()

        machine = Machine.objects.filter(id=self.machineID)[0]
        machine.status = 10
        machine.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "Machine is not running."}}'

        response = self.client.post('/restartMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/restartMachine')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_restart_machine_valid_returns_200(self):
        self.client = Client()
        
        machine = Machine.objects.filter(id=self.machineID)[0]
        machine.status = 0
        machine.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID,
                "machineName": "baa54d9e67-node-01.gcp.daiteap.internal",
                "machineProvider": "google"
            }
        )

        with patch.object(tasks.worker_restart_machine, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials

            response = self.client.post('/restartMachine', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            celerytask = models.CeleryTask.objects.filter(id=json.loads(response_body)['taskId'])[0]
            expected_response_body = '{"taskId": "' + str(celerytask.id) + '"}'

            resolver = resolve('/restartMachine')

            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.restart_machine')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(expected_response_body, response_body)

class CreateKubernetesCluster(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        regions = '''[
            {
                "name": "region",
                "zones": [
                    {
                        "name": "zone",
                        "instances": [
                            {
                                "name": "instanceType",
                                "description": "description"
                            }
                        ]
                    }
                ]
            }
        ]'''

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        self.azure_account.save()

        self.cluster_with_same_name = Clusters(
            title='same_name', name='ctest', installstep=0, type=1, user=self.user
        )
        self.cluster_with_same_name.save()

    def test_create_kubernetes_cluster_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/createKubernetesCluster')

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(response.status_code, 401)

    def test_create_kubernetes_cluster_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/createKubernetesCluster', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(response.status_code, 401)

    def test_create_kubernetes_cluster_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/createKubernetesCluster', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_missing_parameter_clusterName_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "alicloudSelected": True
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterName\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_too_short_parameter_clusterName_returns_400(self):
        self.client = Client()

        short_clusterName = ''
        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": short_clusterName,
                "alicloudSelected": True,
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "alicloud": {
                    "region": "region",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterName + '\' is too short"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_too_long_parameter_clusterName_returns_400(self):
        self.client = Client()

        long_clusterName = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": long_clusterName,
                "alicloudSelected": True,
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "alicloud": {
                    "region": "region",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterName + '\' is too long"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_no_provider_is_selected_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False
            }
        )

        expected_response_body = '{"error": {"message": "No provider is selected."}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_aws_is_selected_no_region_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'region\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_aws_is_selected_no_zone_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'zone\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_aws_is_selected_no_instanceType_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'instanceType\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_aws_is_selected_no_nodes_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'nodes\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_aws_is_selected_no_vpcCidr_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'vpcCidr\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_create_kubernetes_cluster_aws_is_selected_no_account_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'account\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_aws_is_selected_no_operating_system_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'operatingSystem\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_google_is_selected_no_region_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'region\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_google_is_selected_no_zone_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'zone\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_google_is_selected_no_instanceType_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'instanceType\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_google_is_selected_no_nodes_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'nodes\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_create_kubernetes_cluster_google_is_selected_no_vpcCidr_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'vpcCidr\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_google_is_selected_no_account_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'account\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_google_is_selected_no_operating_system_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "account": "accountLabel",
                    "vpcCidr": '10.0.0.0/16'
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'operatingSystem\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_azure_is_selected_no_region_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'region\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_azure_is_selected_no_zone_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'zone\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_azure_is_selected_no_instanceType_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'instanceType\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_azure_is_selected_no_nodes_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'nodes\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_azure_is_selected_no_vpcCidr_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'vpcCidr\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_azure_is_selected_no_account_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "vpcCidr": "10.0.0.0/16",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'account\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_azure_is_selected_no_operating_system_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "account": "accountLabel",
                    "vpcCidr": "10.0.0.0/16"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'operatingSystem\' is a required property"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_occupied_name_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "same_name",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": "10.0.0.0/16",
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "Environment with that name already exists."}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_invalid_region_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region1",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "Provider region is not legal"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_invalid_zone_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone1",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "Provider zone is not legal"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_invalid_instanceType_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType1",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "Provider instanceType is not legal"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_invalid_account_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType1",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel123",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        expected_response_body = '{"error": {"message": "Account does not exist"}}'

        response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/createKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_create_kubernetes_cluster_valid_returns_200(self):
        self.client = Client()

        expected_call_args1 = '''call({'internal_dns_zone': 'test.test', 'clusterName': 'clusterName', 'kubernetesConfiguration': {'version': 'v1.19.7', 'serviceAddresses': '192.168.0.0/24', 'podsSubnet': '192.168.1.0/24', 'networkPlugin': 'flannel'}, 'alicloudSelected': False, 'awsSelected': False, 'googleSelected': False, 'azureSelected': True, 'onPremiseSelected': False, 'iotArmSelected': False, 'azure': {'region': 'region', 'zone': 'zone', 'instanceType': 'instanceType', 'nodes': 1, 'vpcCidr': '10.0.0.0/16', 'account': 'accountLabel', 'operatingSystem': 'Ubuntu 18.04'}},'''
        expected_call_args2 = '\'), 1)'

        request_body = json.dumps(
            {
                "internal_dns_zone": "test.test",
                "clusterName": "clusterName",
                "kubernetesConfiguration": {
                    "version": "v1.19.7",
                    "serviceAddresses": "192.168.0.0/24",
                    "podsSubnet": "192.168.1.0/24",
                    "networkPlugin": "flannel"
                },
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": "10.0.0.0/16",
                    "account": "accountLabel",
                    "operatingSystem": "Ubuntu 18.04"
                }
            }
        )

        with patch.object(tasks.worker_create_kubernetes_cluster, 'delay') as mock:
            with patch.object(authorization_service, 'Authorize') as authorize_mock:
                authorize_mock.side_effect = func_returns_none
                mock.side_effect = func_worker_validate_credentials

                response = self.client.post('/createKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
                response_body = response.content.decode()

                resolver = resolve('/createKubernetesCluster')

                mock.assert_called()
                self.assertEqual(str(mock.call_args_list[0]).startswith(expected_call_args1), True)
                self.assertEqual(str(mock.call_args_list[0]).endswith(expected_call_args2), True)
                self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.create_kubernetes_cluster')
                self.assertEqual(response.status_code, 200)


class RetryCreateKubernetesCluster(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel'
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel'
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel'
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel'
        )
        self.azure_account.save()

        tfconfig = {
            "alicloudSelected": False, 
            "awsSelected": False, 
            "googleSelected": False, 
            "azureSelected": True,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "azure": {
                "account": "",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }
        }
        self.cluster = Clusters(
            title='name', name='ctest', installstep=-2, type=2, user=self.user,
            tfconfig=json.dumps(tfconfig)
        )
        self.cluster.save()
        self.clusterID =  str(self.cluster.id)
    
    def test_retry_create_kubernetes_cluster_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/retryCreateKubernetesCluster')

        resolver = resolve('/retryCreateKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_create_kubernetes_cluster')
        self.assertEqual(response.status_code, 401)

    def test_retry_create_kubernetes_cluster_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/retryCreateKubernetesCluster', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/retryCreateKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_create_kubernetes_cluster')
        self.assertEqual(response.status_code, 401)

    def test_retry_create_kubernetes_cluster_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/retryCreateKubernetesCluster', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryCreateKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_create_kubernetes_cluster_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/retryCreateKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryCreateKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_create_kubernetes_cluster_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/retryCreateKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryCreateKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_create_kubernetes_cluster_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1' * 40
        request_body = json.dumps(
            {
                "clusterID": long_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/retryCreateKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryCreateKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_create_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_create_kubernetes_cluster_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        with patch.object(tasks.worker_create_kubernetes_cluster, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials
            response = self.client.post('/retryCreateKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            celerytask = models.CeleryTask.objects.filter(id=json.loads(response_body)['taskId'])[0]
            expected_response_body = '{"taskId": "' + str(celerytask.id) + '", "ID": \"' + self.clusterID + '\"}'

            resolver = resolve('/retryCreateKubernetesCluster')

            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_create_kubernetes_cluster')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(expected_response_body, response_body)


class RetryCreateVMs(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            user=self.user
        )
        self.azure_account.save()

        tfconfig = {
            "alicloudSelected": False, 
            "awsSelected": False, 
            "googleSelected": False, 
            "azureSelected": True,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "azure": {
                "account": "",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }
        }
        self.cluster = Clusters(
            title='name', name='ctest', installstep=0, type=2, user=self.user,
            tfconfig=json.dumps(tfconfig)
        )
        self.cluster.save()
        self.clusterID =  str(self.cluster.id)
    
    def test_retry_create_vms_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/retryCreateVMs')

        resolver = resolve('/retryCreateVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_create_vms')
        self.assertEqual(response.status_code, 401)

    def test_retry_create_vms_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/retryCreateVMs', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/retryCreateVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_create_vms')
        self.assertEqual(response.status_code, 401)

    def test_retry_create_vms_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/retryCreateVMs', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryCreateVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_create_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_create_vms_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/retryCreateVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryCreateVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_create_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_create_vms_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/retryCreateVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryCreateVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_create_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_create_vms_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1' * 40
        request_body = json.dumps(
            {
                "clusterID": long_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/retryCreateVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryCreateVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_create_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_create_vms_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        with patch.object(tasks.worker_create_vms, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials
            response = self.client.post('/retryCreateVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            celerytask = models.CeleryTask.objects.filter(id=json.loads(response_body)['taskId'])[0]

            expected_response_body = '{"taskId": "' + str(celerytask.id) + '", "ID": \"' + self.clusterID + '\"}'

            resolver = resolve('/retryCreateVMs')

            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_create_vms')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(expected_response_body, response_body)

class RetryResizeKubernetesCluster(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel'
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel'
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel'
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel'
        )
        self.azure_account.save()

        tfconfig = {
            "alicloudSelected": False, 
            "awsSelected": False, 
            "googleSelected": False, 
            "azureSelected": True,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "azure": {
                "account": "",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }
        }
        self.cluster = Clusters(
            title='name', name='ctest', installstep=0, resizestep=-1, type=2, user=self.user,
            tfconfig=json.dumps(tfconfig)
        )
        self.cluster.save()
        self.clusterID =  str(self.cluster.id)
    
    def test_retry_resize_kubernetes_cluster_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/retryResizeKubernetesCluster')

        resolver = resolve('/retryResizeKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_kubernetes_cluster')
        self.assertEqual(response.status_code, 401)

    def test_retry_resize_kubernetes_cluster_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/retryResizeKubernetesCluster', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/retryResizeKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_kubernetes_cluster')
        self.assertEqual(response.status_code, 401)

    def test_retry_resize_kubernetes_cluster_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/retryResizeKubernetesCluster', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryResizeKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_resize_kubernetes_cluster_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/retryResizeKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryResizeKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_resize_kubernetes_cluster_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/retryResizeKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryResizeKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_resize_kubernetes_cluster_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1' * 40
        request_body = json.dumps(
            {
                "clusterID": long_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/retryResizeKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryResizeKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_resize_kubernetes_cluster_invalid_parameter_clusterID_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": '1' * 36
            }
        )

        expected_response_body = '{"error": {"message": "Invalid parameter clusterID"}}'

        response = self.client.post('/retryResizeKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryResizeKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_retry_resize_kubernetes_cluster_retry_not_allowed_returns_500(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.resizestep = 3
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster status does not allow retry"}}'

        response = self.client.post('/retryResizeKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryResizeKubernetesCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_kubernetes_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_retry_resize_kubernetes_cluster_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        with patch.object(tasks.worker_add_machines_to_kubernetes, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials
            response = self.client.post('/retryResizeKubernetesCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            celerytask = models.CeleryTask.objects.filter(id=json.loads(response_body)['taskId'])[0]
            expected_response_body = '{"taskId": "' + str(celerytask.id) + '", "ID": \"' + self.clusterID + '\"}'

            resolver = resolve('/retryResizeKubernetesCluster')

            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_kubernetes_cluster')
            self.assertEqual(response.status_code, 200)
            self.assertTrue(self.clusterID in response_body)
            self.assertEqual(expected_response_body, response_body)

class RetryResizeVMsCluster(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel'
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel'
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel'
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel'
        )
        self.azure_account.save()

        tfconfig = {
            "alicloudSelected": False, 
            "awsSelected": False, 
            "googleSelected": False, 
            "azureSelected": True,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "azure": {
                "account": "",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }
        }
        self.cluster = Clusters(
            title='name', name='ctest', installstep=0, resizestep=-1, type=2, user=self.user,
            tfconfig=json.dumps(tfconfig)
        )
        self.cluster.save()
        self.clusterID =  str(self.cluster.id)
    
    def test_retry_resize_vms_cluster_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/retryResizeVMsCluster')

        resolver = resolve('/retryResizeVMsCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_vms_cluster')
        self.assertEqual(response.status_code, 401)

    def test_retry_resize_vms_cluster_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/retryResizeVMsCluster', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/retryResizeVMsCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_vms_cluster')
        self.assertEqual(response.status_code, 401)

    def test_retry_resize_vms_cluster_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/retryResizeVMsCluster', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryResizeVMsCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_vms_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_resize_vms_cluster_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google"
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/retryResizeVMsCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryResizeVMsCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_vms_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_resize_vms_cluster_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = '123'
        request_body = json.dumps(
            {
                "clusterID": short_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/retryResizeVMsCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryResizeVMsCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_vms_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_resize_vms_cluster_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '1' * 40
        request_body = json.dumps(
            {
                "clusterID": long_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/retryResizeVMsCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryResizeVMsCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_vms_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_retry_resize_vms_cluster_invalid_parameter_clusterID_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": '1' * 36
            }
        )

        expected_response_body = '{"error": {"message": "Invalid parameter clusterID"}}'

        response = self.client.post('/retryResizeVMsCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryResizeVMsCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_vms_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_retry_resize_vms_cluster_retry_not_allowed_returns_500(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.resizestep = 3
        cluster.save()
        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster status does not allow retry"}}'

        response = self.client.post('/retryResizeVMsCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/retryResizeVMsCluster')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_vms_cluster')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_retry_resize_vms_cluster_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterID": self.clusterID
            }
        )

        with patch.object(tasks.worker_add_machines_to_vms, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials
            response = self.client.post('/retryResizeVMsCluster', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            celerytask = models.CeleryTask.objects.filter(id=json.loads(response_body)['taskId'])[0]
            expected_response_body = '{"taskId": "' + str(celerytask.id) + '", "ID": \"' + self.clusterID + '\"}'

            resolver = resolve('/retryResizeVMsCluster')

            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.retry_resize_vms_cluster')
            self.assertEqual(response.status_code, 200)
            self.assertTrue(self.clusterID in response_body)
            self.assertEqual(expected_response_body, response_body)

class PlanCreateResources(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        self.profile = self.user.profile
        self.profile.save()

        self.cluster_with_same_name = Clusters(
            title='same_name', name='ctest', installstep=0, type=1, user=self.user
        )
        self.cluster_with_same_name.save()

    def test_plan_create_resources_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/planCreateResources')

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(response.status_code, 401)

    def test_plan_create_resources_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/planCreateResources', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(response.status_code, 401)

    def test_plan_create_resources_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/planCreateResources', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_no_provider_is_selected_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False
            }
        )

        expected_response_body = '{"error": {"message": "No provider is selected."}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_aws_is_selected_no_region_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'region\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_aws_is_selected_no_zone_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'zone\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_aws_is_selected_no_instanceType_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'instanceType\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_aws_is_selected_no_nodes_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'nodes\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_aws_is_selected_no_vpcCidr_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'vpcCidr\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_aws_is_selected_no_account_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": True,
                "googleSelected": False,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "aws": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16'
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'account\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_google_is_selected_no_region_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'region\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_google_is_selected_no_zone_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'zone\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_google_is_selected_no_instanceType_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'instanceType\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_google_is_selected_no_nodes_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'nodes\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_plan_create_resources_google_is_selected_no_vpcCidr_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'vpcCidr\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_google_is_selected_no_account_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": True,
                "azureSelected": False,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "google": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16'
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'account\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_azure_is_selected_no_region_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'region\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_azure_is_selected_no_zone_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'zone\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_azure_is_selected_no_instanceType_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'instanceType\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_azure_is_selected_no_nodes_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "account": "accountLabel",
                    "vpcCidr": '10.0.0.0/16'
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'nodes\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_azure_is_selected_no_vpcCidr_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "account": "accountLabel"
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'vpcCidr\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_azure_is_selected_no_account_for_it_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "nodes": 1,
                    "instanceType": "instanceType",
                    "vpcCidr": '10.0.0.0/16'
                }
            }
        )

        expected_response_body = '{"error": {"message": "\'account\' is a required property"}}'

        response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/planCreateResources')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_plan_create_resources_valid_returns_200(self):
        self.client = Client()

        expected_call_args1 = '''call({'clusterName': 'clustername', 'internal_dns_zone': 'dns.internal', 'alicloudSelected': False, 'awsSelected': False, 'googleSelected': False, 'azureSelected': True, 'onPremiseSelected': False, 'iotArmSelected': False, 'azure': {'region': 'region', 'zone': 'zone', 'instanceType': 'instanceType', 'nodes': 1, 'vpcCidr': '10.0.0.0/16', 'operatingSystem': 'ubuntu-os-cloud/ubuntu-1804-bionic-v20210315a', 'account': 'accountLabel'}}, 1)'''

        request_body = json.dumps(
            {
                "clusterName": "clustername",
                "internal_dns_zone": "dns.internal",
                "alicloudSelected": False,
                "awsSelected": False,
                "googleSelected": False,
                "azureSelected": True,
                "onPremiseSelected": False,
                "iotArmSelected": False,
                "azure": {
                    "region": "region",
                    "zone": "zone",
                    "instanceType": "instanceType",
                    "nodes": 1,
                    "vpcCidr": '10.0.0.0/16',
                    "operatingSystem": "ubuntu-os-cloud/ubuntu-1804-bionic-v20210315a",
                    "account": "accountLabel"
                }
            }
        )

        with patch.object(tasks.worker_plan_create_resources, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials

            response = self.client.post('/planCreateResources', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')

            response_body = response.content.decode()
            resolver = resolve('/planCreateResources')

            mock.assert_called()
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args1)
            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.plan_create_resources')
            self.assertEqual(response.status_code, 200)


class AddMachinesToVms(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        regions = '''[
            {
                "name": "region",
                "zones": [
                    {
                        "name": "zone",
                        "instances": [
                            {
                                "name": "instanceType",
                                "description": "description"
                            }
                        ]
                    }
                ]
            }
        ]'''

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        self.azure_account.save()

        tfconfig = {
            "alicloudSelected": False, 
            "awsSelected": False, 
            "googleSelected": False, 
            "azureSelected": True, 
            "azure": {
                "account": "accountLabel",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }
        }
        self.cluster = Clusters(
            title='name', name='ctest', installstep=0, type=2, user=self.user,
            tfconfig=json.dumps(tfconfig)
        )
        self.cluster.save()
        self.clusterID =  str(self.cluster.id)
        self.invalid_cluster = Clusters(
            title='name', name='ctest', installstep=2, type=2, user=self.user,
            tfconfig=json.dumps(tfconfig)
        )
        self.invalid_cluster.save()
        self.invalid_clusterID =  str(self.invalid_cluster.id)

    def test_add_machines_to_vms_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/addMachinesToVMs')

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(response.status_code, 401)

    def test_add_machines_to_vms_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/addMachinesToVMs', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(response.status_code, 401)

    def test_add_machines_to_vms_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/addMachinesToVMs', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_missing_parameter_provider_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'provider\' is a required property"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_too_short_parameter_provider_returns_400(self):
        self.client = Client()

        short_provider = 'a'
        request_body = json.dumps(
            {
                "provider": short_provider,
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_provider + '\' is too short"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_too_long_parameter_provider_returns_400(self):
        self.client = Client()

        long_provider = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "provider": long_provider,
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_provider + '\' is too long"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_missing_parameter_region_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'region\' is a required property"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_too_short_parameter_region_returns_400(self):
        self.client = Client()

        short_region = 'a'
        request_body = json.dumps(
            {
                "provider": "google",
                "region": short_region,
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_region + '\' is too short"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_too_long_parameter_region_returns_400(self):
        self.client = Client()

        long_region = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "provider": "google",
                "region": long_region,
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_region + '\' is too long"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_missing_parameter_zone_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'zone\' is a required property"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_too_short_parameter_zone_returns_400(self):
        self.client = Client()

        short_zone = 'a'
        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": short_zone,
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_zone + '\' is too short"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_too_long_parameter_zone_returns_400(self):
        self.client = Client()

        long_zone = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": long_zone,
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_zone + '\' is too long"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_missing_parameter_nodes_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": "zone",
                "instanceType": "instanceType",
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'nodes\' is a required property"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_missing_parameter_instanceType_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'instanceType\' is a required property"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_too_short_parameter_instanceType_returns_400(self):
        self.client = Client()

        short_instanceType = 'a'
        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": short_instanceType,
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_instanceType + '\' is too short"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_too_long_parameter_instanceType_returns_400(self):
        self.client = Client()

        long_instanceType = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": long_instanceType,
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_instanceType + '\' is too long"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = 'a'
        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": short_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": long_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_invalid_parameter_provider_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "invalid",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "Invalid provider parameter."}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_add_machines_to_vms_invalid_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "azure",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "Invalid parameter clusterID"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_add_machines_to_vms_invalid_cluster_status_returns_400(self):
        self.client = Client()
        
        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.status = 10
        cluster.save()

        request_body = json.dumps(
            {
                "provider": "azure",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster is not running."}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_add_machines_to_vms_invalid_cluster_installstep_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.installstep = -3
        cluster.save()

        request_body = json.dumps(
            {
                "provider": "azure",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster status does not permit adding machines."}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)
    
    def test_add_machines_to_vms_wrong_cluster_type_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.type = 1
        cluster.save()

        request_body = json.dumps(
            {
                "provider": "azure",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "Invalid parameter clusterID"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_add_machines_to_vms_invalid_cluster_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "azure",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": self.invalid_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster status does not permit adding machines."}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_add_machines_to_vms_invalid_instanceType_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
        {
                "provider": "azure",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType123",
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Provider instanceType is not legal"}}'

        response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToVMs')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_vms_valid_returns_200(self):
        self.client = Client()

        expected_call_args = 'call({\'provider\': \'azure\', \'region\': \'region\', \'zone\': '
        expected_call_args += '\'zone\', \'nodes\': 5, \'vpcCidr\': \'10.0.0.0/16\', \'instanceType\': \'instanceType\', \'clusterID\': \''
        expected_call_args += str(self.clusterID)
        expected_call_args += '\'}, 1)'

        request_body = json.dumps(
        {
                "provider": "azure",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": self.clusterID
            }
        )

        with patch.object(tasks.worker_add_machines_to_vms, 'delay') as mock:
            with patch.object(authorization_service, 'Authorize') as authorize_mock:
                authorize_mock.side_effect = func_returns_none
                mock.side_effect = func_worker_validate_credentials

                response = self.client.post('/addMachinesToVMs', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
                response_body = response.content.decode()

                resolver = resolve('/addMachinesToVMs')

                mock.assert_called()
                self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
                self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_vms')
                self.assertEqual(response.status_code, 200)


class AddMachinesToKubernetes(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True
        self.maxDiff = None

        self.user = User.objects.create_user(username='testuser', password='12345', id=1)
        regions = '''[
            {
                "name": "region",
                "zones": [
                    {
                        "name": "zone",
                        "instances": [
                            {
                                "name": "instanceType",
                                "description": "description"
                            }
                        ]
                    }
                ]
            }
        ]'''

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabel',
            regions=regions,
            user=self.user
        )
        self.azure_account.save()

        tfconfig = {
            "alicloudSelected": False, 
            "awsSelected": False, 
            "googleSelected": False, 
            "azureSelected": True, 
            "azure": {
                "account": "accountLabel",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }, 
            "google": {
                "account": "accountLabel",
                "region": "region", 
                "zone": "zone", 
                "instances": ["instanceType"]
            }
        }
        self.cluster = Clusters(
            title='name', name='ctest', installstep=0, type=1, user=self.user,
            tfconfig=json.dumps(tfconfig)
        )
        self.cluster.save()
        self.clusterID =  str(self.cluster.id)
        self.invalid_cluster = Clusters(
            title='name', name='ctest', installstep=2, type=1, user=self.user,
            tfconfig=json.dumps(tfconfig)
        )
        self.invalid_cluster.save()
        self.invalid_clusterID =  str(self.invalid_cluster.id)

    def test_add_machines_to_kubernetes_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/addMachinesToKubernetes')

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(response.status_code, 401)

    def test_add_machines_to_kubernetes_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/addMachinesToKubernetes', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(response.status_code, 401)

    def test_add_machines_to_kubernetes_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/addMachinesToKubernetes', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_missing_parameter_provider_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'provider\' is a required property"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_too_short_parameter_provider_returns_400(self):
        self.client = Client()

        short_provider = 'a'
        request_body = json.dumps(
            {
                "provider": short_provider,
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_provider + '\' is too short"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_too_long_parameter_provider_returns_400(self):
        self.client = Client()

        long_provider = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "provider": long_provider,
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_provider + '\' is too long"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_missing_parameter_region_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'region\' is a required property"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_too_short_parameter_region_returns_400(self):
        self.client = Client()

        short_region = 'a'
        request_body = json.dumps(
            {
                "provider": "google",
                "region": short_region,
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_region + '\' is too short"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_too_long_parameter_region_returns_400(self):
        self.client = Client()

        long_region = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "provider": "google",
                "region": long_region,
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_region + '\' is too long"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_missing_parameter_zone_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'zone\' is a required property"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_too_short_parameter_zone_returns_400(self):
        self.client = Client()

        short_zone = 'a'
        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": short_zone,
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_zone + '\' is too short"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_too_long_parameter_zone_returns_400(self):
        self.client = Client()

        long_zone = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": long_zone,
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_zone + '\' is too long"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_missing_parameter_nodes_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": "zone",
                "instanceType": "instanceType",
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'nodes\' is a required property"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_missing_parameter_instanceType_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'instanceType\' is a required property"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_too_short_parameter_instanceType_returns_400(self):
        self.client = Client()

        short_instanceType = 'a'
        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": short_instanceType,
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_instanceType + '\' is too short"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_too_long_parameter_instanceType_returns_400(self):
        self.client = Client()

        long_instanceType = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": long_instanceType,
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_instanceType + '\' is too long"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_missing_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterID\' is a required property"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_too_short_parameter_clusterID_returns_400(self):
        self.client = Client()

        short_clusterID = 'a'
        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": short_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterID + '\' is too short"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_too_long_parameter_clusterID_returns_400(self):
        self.client = Client()

        long_clusterID = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "provider": "google",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": long_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterID + '\' is too long"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_invalid_parameter_provider_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "invalid",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "Invalid provider parameter."}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_add_machines_to_kubernetes_invalid_parameter_clusterID_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "azure",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "Invalid parameter clusterID"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)
    
    def test_add_machines_to_kubernetes_invalid_cluster_status_returns_400(self):
        self.client = Client()
        
        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.status = 10
        cluster.save()

        request_body = json.dumps(
            {
                "provider": "azure",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster is not running."}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_add_machines_to_kubernetes_invalid_cluster_installstep_returns_400(self):
        self.client = Client()
        
        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.installstep = -3
        cluster.save()

        request_body = json.dumps(
            {
                "provider": "azure",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster status does not permit adding machines."}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_add_machines_to_kubernetes_wrong_cluster_type_returns_400(self):
        self.client = Client()

        cluster = Clusters.objects.filter(id=self.clusterID)[0]
        cluster.type = 2
        cluster.save()

        request_body = json.dumps(
            {
                "provider": "azure",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": "123456789112345678911234567891123456"
            }
        )

        expected_response_body = '{"error": {"message": "Invalid parameter clusterID"}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_add_machines_to_kubernetes_invalid_cluster_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "azure",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": self.invalid_clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Cluster status does not permit adding machines."}}'

        response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 500)

    def test_add_machines_to_kubernetes_invalid_instanceType_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
        {
                "provider": "azure",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType123",
                "clusterID": self.clusterID
            }
        )

        expected_response_body = '{"error": {"message": "Provider instanceType is not legal"}}'

        with patch.object(tasks.worker_add_machines_to_kubernetes, 'delay') as mock:
            with patch.object(authorization_service, 'Authorize') as authorize_mock:
                authorize_mock.side_effect = func_returns_none
                mock.side_effect = func_no_return
                response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/addMachinesToKubernetes')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_add_machines_to_kubernetes_valid_returns_200(self):
        self.client = Client()

        expected_call_args = 'call({\'provider\': \'azure\', \'region\': \'region\', \'zone\': '
        expected_call_args += '\'zone\', \'nodes\': 5, \'vpcCidr\': \'10.0.0.0/16\', \'instanceType\': \'instanceType\', \'clusterID\': \''
        expected_call_args += str(self.clusterID)
        expected_call_args += '\'}, 1)'

        request_body = json.dumps(
        {
                "provider": "azure",
                "region": "region",
                "zone": "zone",
                "nodes": 5,
                "vpcCidr": '10.0.0.0/16',
                "instanceType": "instanceType",
                "clusterID": self.clusterID
            }
        )

        with patch.object(tasks.worker_add_machines_to_kubernetes, 'delay') as mock:
            with patch.object(authorization_service, 'Authorize') as authorize_mock:
                authorize_mock.side_effect = func_returns_none
                mock.side_effect = func_worker_validate_credentials

                response = self.client.post('/addMachinesToKubernetes', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
                response_body = response.content.decode()

                resolver = resolve('/addMachinesToKubernetes')

                mock.assert_called()
                self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
                self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.add_machines_to_kubernetes')
                self.assertEqual(response.status_code, 200)


class IsClusterNameFree(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        self.cluster_with_same_name = Clusters(
            title='same_name', name='ctest', installstep=0, type=1, user=self.user
        )
        self.cluster_with_same_name.save()

    def test_is_cluster_name_free_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/isClusterNameFree')

        resolver = resolve('/isClusterNameFree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_cluster_name_free')
        self.assertEqual(response.status_code, 401)

    def test_is_cluster_name_free_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/isClusterNameFree', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/isClusterNameFree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_cluster_name_free')
        self.assertEqual(response.status_code, 401)

    def test_is_cluster_name_free_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/isClusterNameFree', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/isClusterNameFree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_cluster_name_free')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_is_cluster_name_free_missing_parameter_clusterName_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "alicloudSelected": True
            }
        )

        expected_response_body = '{"error": {"message": "\'clusterName\' is a required property"}}'

        response = self.client.post('/isClusterNameFree', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/isClusterNameFree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_cluster_name_free')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_is_cluster_name_free_too_short_parameter_clusterName_returns_400(self):
        self.client = Client()

        short_clusterName = ''
        request_body = json.dumps(
            {
                "clusterName": short_clusterName
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_clusterName + '\' is too short"}}'

        response = self.client.post('/isClusterNameFree', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/isClusterNameFree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_cluster_name_free')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_is_cluster_name_free_too_long_parameter_clusterName_returns_400(self):
        self.client = Client()

        long_clusterName = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "clusterName": long_clusterName
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_clusterName + '\' is too long"}}'

        response = self.client.post('/isClusterNameFree', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/isClusterNameFree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_cluster_name_free')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_is_cluster_name_free_occupied_name_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "same_name"
            }
        )

        expected_response_body = '{"free": false}'

        response = self.client.post('/isClusterNameFree', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/isClusterNameFree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_cluster_name_free')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)

    def test_is_cluster_name_free_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "clusterName": "clusterName"

           }
        )

        expected_response_body = '{"free": true}'

        response = self.client.post('/isClusterNameFree', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/isClusterNameFree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_cluster_name_free')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)


class ValidateCredentials(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        google_account = CloudAccount(
            provider = 'google',
            label='accountLabelG',
            credentials=json.dumps({'google_key': ''}),
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='accountLabelAli',
            credentials=json.dumps({
            'alicloud_access_key': '',
            'alicloud_secret_key': '',
            }),
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='accountLabelAWS',
            credentials=json.dumps({
            'aws_access_key_id': '',
            'aws_secret_access_key': '',
            }),
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='accountLabelAzure',
            credentials=json.dumps({
            'azure_tenant_id': '',
            'azure_subscription_id': '',
            'azure_client_id': '',
            'azure_client_secret': '',
            }),
            user=self.user
        )
        self.azure_account.save()
        self.onPremise_account = CloudAccount(
            provider = 'onpremise',
            label='accountLabel4',
            credentials=json.dumps({
            'gw_public_ip': '',
            'gw_private_ip': '',
            'admin_username': '',
            'admin_private_key': '',
            }),
            user=self.user
        )
        self.onPremise_account.save()

        self.iotArm_account = CloudAccount(
            provider = 'iotarm',
            label='accountLabel4',
            credentials=json.dumps({
            'gw_public_ip': '',
            'gw_private_ip': '',
            'admin_username': '',
            'admin_private_key': '',
            }),
            user=self.user
        )
        self.azure_account.save()

    def test_validate_credentials_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/validateCredentials')

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(response.status_code, 401)

    def test_validate_credentials_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/validateCredentials', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(response.status_code, 401)

    def test_validate_credentials_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/validateCredentials', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_validate_credentials_missing_parameter_account_label_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "provider": "aws"
            }
        )

        expected_response_body = '{"error": {"message": "\'account_label\' is a required property"}}'

        response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_validate_credentials_too_short_parameter_account_label_returns_400(self):
        self.client = Client()

        short_account_label = 'a' * 1
        request_body = json.dumps(
            {
                "account_label": short_account_label
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_account_label + '\' is too short"}}'

        response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_validate_credentials_too_long_parameter_account_label_returns_400(self):
        self.client = Client()

        long_account_label = 'a' * 150
        request_body = json.dumps(
            {
                "account_label": long_account_label
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_account_label + '\' is too long"}}'

        response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_validate_credentials_invalid_parameter_account_label_returns_400(self):
        self.client = Client()

        invalid_account_label = 'accountLabel'
        request_body = json.dumps(
            {
                "account_label": invalid_account_label
            }
        )

        expected_response_body = '{"error": {"message": "Invalid account_label parameter"}}'

        response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    # Google
    def test_validate_cloud_credentials_invalid_google_key_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "account_label": 'accountLabelG'
            }
        )

        expected_response_body = '{"error": {"message": "Invalid google_key parameter"}}'

        response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_validate_cloud_credentials_valid_google_key_returns_200(self):
        self.client = Client()
        expected_call_args = 'call({\'google_key\': \'{"project_id": "testvalue"}\', \'google\': True, \'id\': 1}, 1)'

        account = CloudAccount.objects.filter(label='accountLabelG',user=self.user)[0]
        account.credentials = json.dumps({'google_key': '{"project_id": "testvalue"}'})
        account.provider = 'google'
        account.save()

        request_body = json.dumps(
            {
                "account_label": 'accountLabelG'
            }
        )

        expected_response_body = '123-456-789'

        with patch.object(tasks.worker_validate_credentials, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials

            response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            resolver = resolve('/validateCredentials')

            celerytask = models.CeleryTask.objects.filter(id=json.loads(response_body)['taskId'])[0]

            mock.assert_called()

            self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(celerytask.task_id, expected_response_body)

    # aws
    def test_validate_cloud_credentials_invalid_aws_parameters_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "account_label": 'accountLabelAWS'
            }
        )

        expected_response_body = '{"error": {"message": "Invalid aws_access_key_id/aws_secret_access_key parameter"}}'

        response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_validate_cloud_credentials_invalid_parameter_aws_access_key_returns_400(self):
        self.client = Client()

        account = CloudAccount.objects.filter(label='accountLabelAWS',user=self.user)[0]
        account.credentials = json.dumps({'aws_access_key_id': 'a' * 151, 'aws_secret_access_key': 'a' * 10})
        account.save()
        request_body = json.dumps(
            {
                "account_label": 'accountLabelAWS'
            }
        )

        expected_response_body = '{"error": {"message": "Invalid parameter aws_access_key_id"}}'

        response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_validate_cloud_credentials_invalid_parameter_aws_secret_access_key_returns_400(self):
        self.client = Client()

        account = CloudAccount.objects.filter(label='accountLabelAWS',user=self.user)[0]
        account.credentials = json.dumps({'aws_access_key_id': 'a' * 20, 'aws_secret_access_key': 'a' * 151})
        account.save()
        request_body = json.dumps(
            {
                "account_label": 'accountLabelAWS'
            }
        )

        expected_response_body = '{"error": {"message": "Invalid parameter aws_secret_access_key"}}'

        response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(response.status_code, 400)

        self.assertEqual(expected_response_body, response_body)

    def test_validate_cloud_credentials_valid_aws_credentials_returns_200(self):
        self.client = Client()
        expected_call_args = 'call({\'aws_access_key_id\': \'AKIAQQMEPZJR3OXAE3UZ\', \'aws_secret_access_key\': \'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\', \'id\': 3, \'aws\': True}, 1)'

        account = CloudAccount.objects.filter(label='accountLabelAWS',user=self.user)[0]
        account.credentials = json.dumps({'aws_access_key_id': 'AKIAQQMEPZJR3OXAE3UZ', 'aws_secret_access_key': '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'})
        account.save()
        request_body = json.dumps(
            {
                "account_label": 'accountLabelAWS'
            }
        )

        expected_response_body = '123-456-789'

        with patch.object(tasks.worker_validate_credentials, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials

            response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            resolver = resolve('/validateCredentials')

            celerytask = models.CeleryTask.objects.filter(id=json.loads(response_body)['taskId'])[0]

            mock.assert_called()

            self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(celerytask.task_id, expected_response_body)

    # azure
    def test_validate_cloud_credentials_invalid_azure_parameters_returns_500(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "account_label": 'accountLabelAzure'
            }
        )

        expected_response_body = '{"error": {"message": "Invalid azure parameter"}}'

        response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_validate_cloud_credentials_invalid_parameter_azure_tenant_id_returns_400(self):
        self.client = Client()

        account = CloudAccount.objects.filter(label='accountLabelAzure',user=self.user)[0]
        azure_credentials = {}
        azure_credentials['azure_tenant_id'] = 'a' * 35
        azure_credentials['azure_subscription_id'] = 'a' * 36
        azure_credentials['azure_client_id'] = 'a' * 36
        azure_credentials['azure_client_secret'] = 'a' * 10
        account.credentials = json.dumps(azure_credentials)
        account.save()
        request_body = json.dumps(
            {
                "account_label": 'accountLabelAzure'
            }
        )

        expected_response_body = '{"error": {"message": "Invalid parameter azure_tenant_id"}}'

        response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_validate_cloud_credentials_invalid_parameter_azure_subscription_id_returns_400(self):
        self.client = Client()

        account = CloudAccount.objects.filter(label='accountLabelAzure',user=self.user)[0]
        azure_credentials = {}
        azure_credentials['azure_tenant_id'] = 'a' * 36
        azure_credentials['azure_subscription_id'] = 'a' * 35
        azure_credentials['azure_client_id'] = 'a' * 36
        azure_credentials['azure_client_secret'] = 'a' * 10
        account.credentials = json.dumps(azure_credentials)
        account.save()
        request_body = json.dumps(
            {
                "account_label": 'accountLabelAzure'
            }
        )

        expected_response_body = '{"error": {"message": "Invalid parameter azure_subscription_id"}}'

        response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_validate_cloud_credentials_invalid_parameter_azure_client_id_returns_400(self):
        self.client = Client()

        account = CloudAccount.objects.filter(label='accountLabelAzure',user=self.user)[0]
        azure_credentials = {}
        azure_credentials['azure_tenant_id'] = 'a' * 36
        azure_credentials['azure_subscription_id'] = 'a' * 36
        azure_credentials['azure_client_id'] = 'a' * 35
        azure_credentials['azure_client_secret'] = 'a' * 10
        account.credentials = json.dumps(azure_credentials)
        account.save()
        request_body = json.dumps(
            {
                "account_label": 'accountLabelAzure'
            }
        )

        expected_response_body = '{"error": {"message": "Invalid parameter azure_client_id"}}'

        response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)
    
    def test_validate_cloud_credentials_invalid_parameter_azure_client_secret_returns_400(self):
        self.client = Client()

        account = CloudAccount.objects.filter(label='accountLabelAzure',user=self.user)[0]
        azure_credentials = {}
        azure_credentials['azure_tenant_id'] = 'a' * 36
        azure_credentials['azure_subscription_id'] = 'a' * 36
        azure_credentials['azure_client_id'] = 'a' * 36
        azure_credentials['azure_client_secret'] = 'a' * 3
        account.credentials = json.dumps(azure_credentials)
        account.save()
        request_body = json.dumps(
            {
                "account_label": 'accountLabelAzure'
            }
        )

        expected_response_body = '{"error": {"message": "Invalid parameter azure_client_secret"}}'

        response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/validateCredentials')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_validate_cloud_credentials_valid_azure_credentials_returns_200(self):
        self.client = Client()
        expected_call_args = 'call({\'azure_tenant_id\': \'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\', \'azure_subscription_id\': \'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\', \'azure_client_id\': \'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\', \'azure_client_secret\': \'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\', \'id\': 4, \'azure\': True}, 1)'

        account = CloudAccount.objects.filter(label='accountLabelAzure',user=self.user)[0]
        azure_credentials = {}
        azure_credentials['azure_tenant_id'] = 'a' * 36
        azure_credentials['azure_subscription_id'] = 'a' * 36
        azure_credentials['azure_client_id'] = 'a' * 36
        azure_credentials['azure_client_secret'] = 'a' * 36
        account.credentials = json.dumps(azure_credentials)
        account.save()
        request_body = json.dumps(
            {
                "account_label": 'accountLabelAzure'
            }
        )

        expected_response_body = '123-456-789'

        with patch.object(tasks.worker_validate_credentials, 'delay') as mock:
            mock.side_effect = func_worker_validate_credentials

            response = self.client.post('/validateCredentials', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()

            resolver = resolve('/validateCredentials')

            celerytask = models.CeleryTask.objects.filter(id=json.loads(response_body)['taskId'])[0]

            mock.assert_called()

            self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.validate_credentials')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(celerytask.task_id, expected_response_body)


class GetUserProfilePicture(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        self.profile = self.user.profile

    def test_get_user_profile_picture_invalid_credentials_returns_401(self):
        self.client = Client()

        response = self.client.get('/getuserprofilepicture', content_type='application/json', HTTP_AUTHORIZATION='Basic dGVlc3R1c2VyOjEyMzQ1')

        resolver = resolve('/getuserprofilepicture')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_profile_picture')
        self.assertEqual(response.status_code, 401)

    def test_get_user_profile_picture_invalid_method_returns_405(self):
        self.client = Client()

        expected_response_body = '{"detail":"Method \\"POST\\" not allowed."}'

        response = self.client.post('/getuserprofilepicture', content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getuserprofilepicture')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_profile_picture')
        self.assertEqual(response.status_code, 405)
        self.assertEqual(expected_response_body, response_body)

    def test_get_user_profile_picture_no_picture_success_returns_200(self):
        self.client = Client()

        response = self.client.get('/getuserprofilepicture', content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getuserprofilepicture')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_profile_picture')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response_body, ('{"location": ""}'))

    def test_get_user_profile_picture_success_returns_200(self):
        self.client = Client()

        self.profile.picture = 'cloudcluster/test/test_media/test.jpg'
        self.profile.save()

        response = self.client.get('/getuserprofilepicture', content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/getuserprofilepicture')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_user_profile_picture')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response_body, '{"location": "cloudcluster/test/test_media/test.jpg"}')

class UpdateUserProfilePicture(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)
        self.profile = self.user.profile

        self.profile.picture = 'cloudcluster/test/test_media/test.jpg'
        self.profile.save()

    def test_update_user_profile_picture_invalid_credentials_returns_401(self):
        with tempfile.NamedTemporaryFile() as f:
            self.client = Client()

            form = {
                "picture": f
            }

            response = self.client.post('/updateuserprofilepicture', data=form, HTTP_AUTHORIZATION='Basic dGVzdHR1c2VyOjEyMzQ1')
            response_body = response.content.decode()
            print(response_body)

            resolver = resolve('/updateuserprofilepicture')

            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.update_user_profile_picture')
            self.assertEqual(response.status_code, 401)

    def test_update_user_profile_picture_invalid_request_data_returns_400(self):
        with tempfile.NamedTemporaryFile() as f:
            self.client = Client()

            expected_response_body = '{"error": {"message": "Missing form parameter \\"picture\\""}}'

            form = {}

            response = self.client.post('/updateuserprofilepicture', data=form, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()
            print(response_body)

            resolver = resolve('/updateuserprofilepicture')

            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.update_user_profile_picture')
            self.assertEqual(response.status_code, 400)
            self.assertEqual(expected_response_body, response_body)

    def test_update_user_profile_picture_invalid_file_returns_400(self):
        with tempfile.NamedTemporaryFile() as f:
            print(str(f))
            self.client = Client()

            expected_response_body = '{"error": {"message": "cannot identify image file <InMemoryUploadedFile: ' + f.name.split('/')[-1] + ' (application/octet-stream)>"}}'

            form = {
                "picture": f
            }

            response = self.client.post('/updateuserprofilepicture', data=form, HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
            response_body = response.content.decode()
            print(response_body)

            resolver = resolve('/updateuserprofilepicture')

            self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.update_user_profile_picture')
            self.assertEqual(response.status_code, 400)
            self.assertEqual(expected_response_body, response_body)


class IsEnvironmentTemplateNameFree(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        tfconfig = {
            "kubernetesConfiguration": {
                "version": "v1.19.7",
                "serviceAddresses": "10.233.0.0/18",
                "podsSubnet": "10.233.64.0/18",
                "networkPlugin": "flannel"
            },
            "internal_dns_zone": "daiteap.internal",
            "alicloudSelected": False,
            "awsSelected": False,
            "googleSelected": True,
            "azureSelected": False,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "load_balancer_integration": "google",
            "google": {
                "region": "europe-west2",
                "zone": "europe-west2-a",
                "instances": [
                    "n2d-standard-2"
                ],
                "instanceType": "n2d-standard-2",
                "operatingSystem": "ubuntu-os-cloud/ubuntu-1804-bionic-v20210315a",
                "nodes": "1",
                "vpcCidr": "10.30.0.0/16",
                "account": "google-oauth-cloudcluster-261712"
            }
        }

        self.environment_template_with_same_name = EnvironmentTemplate(
            name='same_name', 
            config=json.dumps(tfconfig),
            providers='[\"Google\"]',
            type=1, 
            user=self.user
        )
        self.environment_template_with_same_name.save()

    def test_is_environment_template_name_free_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/environmenttemplates/isnamefree')

        resolver = resolve('/environmenttemplates/isnamefree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_environment_template_name_free')
        self.assertEqual(response.status_code, 401)

    def test_is_environment_template_name_free_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/environmenttemplates/isnamefree', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/environmenttemplates/isnamefree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_environment_template_name_free')
        self.assertEqual(response.status_code, 401)

    def test_is_environment_template_name_free_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/environmenttemplates/isnamefree', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/isnamefree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_environment_template_name_free')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_is_environment_template_name_free_missing_parameter_EnvironmentTemplateName_returns_400(self):
        self.client = Client()

        request_body = json.dumps({'test': 'test'})

        expected_response_body = '{"error": {"message": "\'name\' is a required property"}}'

        response = self.client.post('/environmenttemplates/isnamefree', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/isnamefree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_environment_template_name_free')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_is_environment_template_name_free_too_short_parameter_EnvironmentTemplateName_returns_400(self):
        self.client = Client()

        short_EnvironmentTemplateName = ''
        request_body = json.dumps(
            {
                "name": short_EnvironmentTemplateName
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_EnvironmentTemplateName + '\' is too short"}}'

        response = self.client.post('/environmenttemplates/isnamefree', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/isnamefree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_environment_template_name_free')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_is_environment_template_name_free_too_long_parameter_EnvironmentTemplateName_returns_400(self):
        self.client = Client()

        long_EnvironmentTemplateName = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "name": long_EnvironmentTemplateName
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_EnvironmentTemplateName + '\' is too long"}}'

        response = self.client.post('/environmenttemplates/isnamefree', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/isnamefree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_environment_template_name_free')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_is_environment_template_name_free_occupied_name_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "name": "same_name"
            }
        )

        expected_response_body = '{"free": false}'

        response = self.client.post('/environmenttemplates/isnamefree', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/isnamefree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_environment_template_name_free')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(expected_response_body, response_body)

    def test_is_environment_template_name_free_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "name": "name"
            }
        )

        expected_response_body = '{"free": true}'

        response = self.client.post('/environmenttemplates/isnamefree', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/isnamefree')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.is_environment_template_name_free')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 200)

class SaveEnvironmentTemplate(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1)

        self.test_cluster = Clusters(
            title='name', name='ctest', installstep=0, type=1, user=self.user
        )
        self.test_cluster.save()

        tfconfig = {
            "kubernetesConfiguration": {
                "version": "v1.19.7",
                "serviceAddresses": "10.233.0.0/18",
                "podsSubnet": "10.233.64.0/18",
                "networkPlugin": "flannel"
            },
            "internal_dns_zone": "daiteap.internal",
            "alicloudSelected": False,
            "awsSelected": False,
            "googleSelected": True,
            "azureSelected": False,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "load_balancer_integration": "google",
            "google": {
                "region": "europe-west2",
                "zone": "europe-west2-a",
                "instances": [
                    "n2d-standard-2"
                ],
                "instanceType": "n2d-standard-2",
                "operatingSystem": "ubuntu-os-cloud/ubuntu-1804-bionic-v20210315a",
                "nodes": "1",
                "vpcCidr": "10.30.0.0/16",
                "account": "google-oauth-cloudcluster-261712"
            }
        }

        self.environment_template_with_same_name = EnvironmentTemplate(
            name='same_name', 
            config=json.dumps(tfconfig),
            providers='[\"Google\"]',
            type=1, 
            user=self.user
        )
        self.environment_template_with_same_name.save()

        self.test_cluster = Clusters(
            title='test', name='ctest', installstep=0, type=1, user=self.user
        )
        self.test_cluster.save()

    def test_save_environment_template_no_authorization_headers(self):
        self.client = Client()

        response = self.client.post('/environmenttemplates/save')

        resolver = resolve('/environmenttemplates/save')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.save_environment_template')
        self.assertEqual(response.status_code, 401)

    def test_save_environment_template_invalid_credentials(self):
        self.client = Client()

        response = self.client.post('/environmenttemplates/save', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/environmenttemplates/save')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.save_environment_template')
        self.assertEqual(response.status_code, 401)

    def test_save_environment_template_missing_header_content_type_returns_400(self):
        self.client = Client()
        expected_response_body = 'Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n'

        response = self.client.post('/environmenttemplates/save', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/save')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.save_environment_template')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_save_environment_template_missing_parameter_environmentId_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "name": "test"
            }
        )

        expected_response_body = '{"error": {"message": "\'environmentId\' is a required property"}}'

        response = self.client.post('/environmenttemplates/save', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/save')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.save_environment_template')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_save_environment_template_too_short_parameter_environmentId_returns_400(self):
        self.client = Client()

        short_environmentId = ''
        request_body = json.dumps(
            {
                "environmentId": short_environmentId,
                "name": "test"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_environmentId + '\' is too short"}}'

        response = self.client.post('/environmenttemplates/save', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/save')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.save_environment_template')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_save_environment_template_too_long_parameter_environmentId_returns_400(self):
        self.client = Client()

        long_environmentId = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "environmentId": long_environmentId,
                "name": "test"
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_environmentId + '\' is too long"}}'

        response = self.client.post('/environmenttemplates/save', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/save')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.save_environment_template')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_save_environment_template_missing_parameter_name_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "environmentId": "111111111111111111111111111111111"
            }
        )

        expected_response_body = '{"error": {"message": "\'name\' is a required property"}}'

        response = self.client.post('/environmenttemplates/save', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/save')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.save_environment_template')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_save_environment_template_too_short_parameter_name_returns_400(self):
        self.client = Client()

        short_name = ''
        request_body = json.dumps(
            {
                "environmentId": "111111111111111111111111111111111",
                "name": short_name
            }
        )

        expected_response_body = '{"error": {"message": "\'' + short_name + '\' is too short"}}'

        response = self.client.post('/environmenttemplates/save', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/save')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.save_environment_template')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_save_environment_template_too_long_parameter_name_returns_400(self):
        self.client = Client()

        long_name = '123456789112345678911234567891123456789112345678911123456789112345678911234567891123456789112345678911' * 15
        request_body = json.dumps(
            {
                "environmentId": "111111111111111111111111111111111",
                "name": long_name
            }
        )

        expected_response_body = '{"error": {"message": "\'' + long_name + '\' is too long"}}'

        response = self.client.post('/environmenttemplates/save', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/save')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.save_environment_template')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_save_environment_template_occupied_name_returns_400(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "environmentId": "111111111111111111111111111111111",
                "name": "same_name"
            }
        )

        expected_response_body = '{"error": {"message": "Environment template with that name already exists"}}'

        response = self.client.post('/environmenttemplates/save', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/save')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.save_environment_template')
        self.assertEqual(expected_response_body, response_body)
        self.assertEqual(response.status_code, 400)

    def test_save_environment_template_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
            {
                "environmentId": str(self.test_cluster.id),
                "name": "test"
            }
        )

        response = self.client.post('/environmenttemplates/save', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')

        resolver = resolve('/environmenttemplates/save')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.save_environment_template')
        self.assertEqual(response.status_code, 201)

class DeleteEnvironmentTemplate(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1,
            first_name='first_name', last_name='last_name')

        tfconfig = {
            "kubernetesConfiguration": {
                "version": "v1.19.7",
                "serviceAddresses": "10.233.0.0/18",
                "podsSubnet": "10.233.64.0/18",
                "networkPlugin": "flannel"
            },
            "internal_dns_zone": "daiteap.internal",
            "alicloudSelected": False,
            "awsSelected": False,
            "googleSelected": True,
            "azureSelected": False,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "load_balancer_integration": "google",
            "google": {
                "region": "europe-west2",
                "zone": "europe-west2-a",
                "instances": [
                    "n2d-standard-2"
                ],
                "instanceType": "n2d-standard-2",
                "operatingSystem": "ubuntu-os-cloud/ubuntu-1804-bionic-v20210315a",
                "nodes": "1",
                "vpcCidr": "10.30.0.0/16",
                "account": "google-oauth-cloudcluster-261712"
            }
        }

        self.environment_template = EnvironmentTemplate(
            name='name',
            config=json.dumps(tfconfig),
            providers='[\"Google\"]',
            type=1,
            user=self.user
        )
        self.environment_template.save()


    def test_delete_environment_template_no_authorization_headers(self):
        self.client = Client()

        request_body = json.dumps(
                {
                    "environmentTemplateId": str(self.environment_template.id)
                }
        )

        response = self.client.post('/environmenttemplates/delete', request_body, content_type='application/json')

        resolver = resolve('/environmenttemplates/delete')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_environment_template')
        self.assertEqual(response.status_code, 401)

    def test_delete_environment_template_invalid_credentials(self):
        self.client = Client()

        request_body = json.dumps(
                {
                    "environmentTemplateId": str(self.environment_template.id)
                }
        )

        response = self.client.post('/environmenttemplates/delete', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/environmenttemplates/delete')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_environment_template')
        self.assertEqual(response.status_code, 401)

    def test_delete_environment_template_valid_returns_200(self):
        self.client = Client()

        request_body = json.dumps(
                {
                    "environmentTemplateId": str(self.environment_template.id)
                }
        )

        expected_response_body = '{"submitted": true}'
        response = self.client.post('/environmenttemplates/delete', request_body, content_type='application/json', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/delete')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.delete_environment_template')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response_body, expected_response_body)


class ListEnvironmentTemplates(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1,
            first_name='first_name', last_name='last_name')

        tfconfig = {
            "kubernetesConfiguration": {
                "version": "v1.19.7",
                "serviceAddresses": "10.233.0.0/18",
                "podsSubnet": "10.233.64.0/18",
                "networkPlugin": "flannel"
            },
            "internal_dns_zone": "daiteap.internal",
            "alicloudSelected": False,
            "awsSelected": False,
            "googleSelected": True,
            "azureSelected": False,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "load_balancer_integration": "google",
            "google": {
                "region": "europe-west2",
                "zone": "europe-west2-a",
                "instances": [
                    "n2d-standard-2"
                ],
                "instanceType": "n2d-standard-2",
                "operatingSystem": "ubuntu-os-cloud/ubuntu-1804-bionic-v20210315a",
                "nodes": "1",
                "vpcCidr": "10.30.0.0/16",
                "account": "google-oauth-cloudcluster-261712"
            }
        }

        self.environment_template = EnvironmentTemplate(
            name='name', 
            config=json.dumps(tfconfig),
            providers='[\"Google\"]',
            type=1, 
            user=self.user
        )
        self.environment_template.save()


    def test_list_environment_templates_no_authorization_headers(self):
        self.client = Client()

        response = self.client.get('/environmenttemplates/list')

        resolver = resolve('/environmenttemplates/list')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.list_environment_templates')
        self.assertEqual(response.status_code, 401)

    def test_list_environment_templates_invalid_credentials(self):
        self.client = Client()

        response = self.client.get('/environmenttemplates/list', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/environmenttemplates/list')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.list_environment_templates')
        self.assertEqual(response.status_code, 401)

    def test_list_environment_templates_valid_returns_200(self):
        self.client = Client()

        expected_response_body1 = '{"environmentTemplates": [{"name": "name", "id": "' + str(self.environment_template.id) + '", "created_at": "' 
        expected_response_body2 =  '", "type": 1, "providers": "[\\"Google\\"]"}]}'

        response = self.client.get('/environmenttemplates/list', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/list')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.list_environment_templates')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(True, response_body.startswith(expected_response_body1))
        self.assertEqual(True, response_body.endswith(expected_response_body2))

class GetEnvironmentTemplate(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1,
            first_name='first_name', last_name='last_name')

        tfconfig = {
            "kubernetesConfiguration": {
                "version": "v1.19.7",
                "serviceAddresses": "10.233.0.0/18",
                "podsSubnet": "10.233.64.0/18",
                "networkPlugin": "flannel"
            },
            "internal_dns_zone": "daiteap.internal",
            "alicloudSelected": False,
            "awsSelected": False,
            "googleSelected": True,
            "azureSelected": False,
            "onPremiseSelected": False,
            "iotArmSelected": False,
            "load_balancer_integration": "google",
            "google": {
                "region": "europe-west2",
                "zone": "europe-west2-a",
                "instances": [
                    "n2d-standard-2"
                ],
                "instanceType": "n2d-standard-2",
                "operatingSystem": "ubuntu-os-cloud/ubuntu-1804-bionic-v20210315a",
                "nodes": "1",
                "vpcCidr": "10.30.0.0/16",
                "account": "google-oauth-cloudcluster-261712"
            }
        }

        self.environment_template = EnvironmentTemplate(
            name='name', 
            config=json.dumps(tfconfig),
            providers='[\"Google\"]',
            type=1, 
            user=self.user
        )
        self.environment_template.save()


    def test_get_environment_template_no_authorization_headers(self):
        self.client = Client()

        response = self.client.get('/environmenttemplates/get/' + str(self.environment_template))

        resolver = resolve('/environmenttemplates/get/' + str(self.environment_template))

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_environment_template')
        self.assertEqual(response.status_code, 401)

    def test_get_environment_template_invalid_credentials(self):
        self.client = Client()

        response = self.client.get('/environmenttemplates/get/' + str(self.environment_template), HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/environmenttemplates/get/' + str(self.environment_template))

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_environment_template')
        self.assertEqual(response.status_code, 401)

    def test_get_environment_template_valid_returns_200(self):
        self.client = Client()

        expected_response_body1 = '{"name": "name", "id": "' + str(self.environment_template.id) + '", "created_at": "' 
        expected_response_body2 =  '", "type": 1, "providers": "[\\"Google\\"]", "config": {"kubernetesConfiguration": {"version": "v1.19.7", "serviceAddresses": "10.233.0.0/18", "podsSubnet": "10.233.64.0/18", "networkPlugin": "flannel"}, "internal_dns_zone": "daiteap.internal", "alicloudSelected": false, "awsSelected": false, "googleSelected": true, "azureSelected": false, "onPremiseSelected": false, "iotArmSelected": false, "load_balancer_integration": "google", "google": {"region": "europe-west2", "zone": "europe-west2-a", "instances": ["n2d-standard-2"], "instanceType": "n2d-standard-2", "operatingSystem": "ubuntu-os-cloud/ubuntu-1804-bionic-v20210315a", "nodes": "1", "vpcCidr": "10.30.0.0/16", "account": "google-oauth-cloudcluster-261712"}}}',


        response = self.client.get('/environmenttemplates/get/' + str(self.environment_template.id), HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/environmenttemplates/get/' + str(self.environment_template.id))

        print(response_body)

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_environment_template')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(True, response_body.startswith(expected_response_body1))
        self.assertEqual(True, response_body.endswith(expected_response_body2))

class GetTimezones(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True


        self.user = User.objects.create_user(
            username='testuser', password='12345', id=1,
            first_name='first_name', last_name='last_name')

    def test_get_timezones_no_authorization_headers(self):
        self.client = Client()

        response = self.client.get('/gettimezones')

        resolver = resolve('/gettimezones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_timezones')
        self.assertEqual(response.status_code, 401)

    def test_get_timezones_invalid_credentials(self):
        self.client = Client()

        response = self.client.get('/gettimezones', HTTP_AUTHORIZATION='Basic MTIzNDU2OjEyMzQ1Ng=')

        resolver = resolve('/gettimezones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_timezones')
        self.assertEqual(response.status_code, 401)

    def test_get_timezones_valid_returns_200(self):
        self.client = Client()

        response = self.client.get('/gettimezones', HTTP_AUTHORIZATION='Basic dGVzdHVzZXI6MTIzNDU=')
        response_body = response.content.decode()

        resolver = resolve('/gettimezones')

        self.assertEqual(resolver.view_name, 'cloudcluster.' + VERSION + '.views.get_timezones')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(True, 'UTC' in response_body)
