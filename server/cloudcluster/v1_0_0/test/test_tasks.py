import base64
import json

from json.decoder import JSONDecodeError

from .. import mailgun
from ..tasks import worker_create_kubernetes_cluster
from cloudcluster.models import Clusters, User, CloudAccount
from mock import MagicMock, patch
from django.test import TestCase
import logging
from .mock_funcs import func_no_return

class WorkerCreateKubernetesCluster(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

        self.user = User.objects.create_user(
            username='testuser', password='12345')
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
            label='account',
            regions=regions,
            credentials=json.dumps({'google_key': json.dumps({"type": "type","project_id": "project_id","private_key_id": "private_key_id"})}),
            user=self.user
        )
        google_account.save()
        alicloud_account = CloudAccount(
            provider = 'alicloud',
            label='account',
            regions=regions,
            credentials=json.dumps({
            'alicloud_access_key': 'alicloud_access_key',
            'alicloud_secret_key': 'alicloud_secret_key',
            }),
            user=self.user
        )
        alicloud_account.save()
        aws_account = CloudAccount(
            provider = 'aws',
            label='account',
            regions=regions,
            credentials=json.dumps({
            'aws_access_key_id': 'AKIAQQMEPZJR3OXAE3UZ',
            'aws_secret_access_key': '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',
            }),
            user=self.user
        )
        aws_account.save()
        self.azure_account = CloudAccount(
            provider = 'azure',
            label='account',
            regions=regions,
            credentials=json.dumps({
            'azure_tenant_id': 'a' * 36,
            'azure_subscription_id': 'a' * 36,
            'azure_client_id': 'a' * 36,
            'azure_client_secret': 'a' * 10,
            }),
            user=self.user
        )
        self.azure_account.save()
        self.onPremise_account = CloudAccount(
            provider = 'onpremise',
            label='account',
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
            label='account',
            credentials=json.dumps({
            'gw_public_ip': 'gw_public_ip',
            'gw_private_ip': 'gw_private_ip',
            'admin_username': 'admin_username',
            'admin_private_key': 'admin_private_key',
            }),
            user=self.user
        )
        self.iotArm_account.save()

        tfconfig = json.dumps({
            "internal_dns_zone": 'test.test',
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

        self.cluster = Clusters(
            name='testCluster',
            user=self.user,
            type=1,
            installstep=1,
            title='title',
            tfconfig=tfconfig,
            resources=('{"google compute address": 1, "google compute firewall": 1, "google compute instance": 1,' + 
            ' "google compute network": 1, "google compute subnetwork": 1}')
        )
        self.cluster.save()

    def test_worker_create_kubernetes_cluster_missing_key_resources_google_region_throws_error(self):
        cluster_id = Clusters.objects.filter()[0].id
        resources = {'internal_dns_zone': 'test.test', 'googleSelected': True, 'google': {'account': 'account'}, 'onPremiseSelected': False, 'iotArmSelected': False}
        user_id = self.user.id

        expected_exception = str(KeyError('region'))
        expected_call_args = 'call(1, \'title\')'

        with patch.object(mailgun.mailgun_client.MailgunClient, 'email_environment_creation_failed') as mock:
            mock.side_effect = func_no_return

            worker_create_kubernetes_cluster(resources=resources, cluster_id=cluster_id, user_id=user_id)

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            mock.assert_called()
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
            self.assertEqual(cluster.installstep, -1)
            self.assertEqual(base64.b64decode(cluster.error_msg).decode("utf-8"), expected_exception)


    def test_worker_create_kubernetes_cluster_missing_key_resources_google_zone_throws_error(self):
        cluster_id = Clusters.objects.filter()[0].id
        resources = {'internal_dns_zone': 'test.test', 'googleSelected': True, 'google': {'region': 'test', 'account': 'account'}, 'onPremiseSelected': False, 'iotArmSelected': False}
        user_id = self.user.id

        expected_exception = str(KeyError('zone'))
        expected_call_args = 'call(1, \'title\')'

        with patch.object(mailgun.mailgun_client.MailgunClient, 'email_environment_creation_failed') as mock:
            mock.side_effect = func_no_return

            worker_create_kubernetes_cluster(resources=resources, cluster_id=cluster_id, user_id=user_id)

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            mock.assert_called()
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
            self.assertEqual(cluster.installstep, -1)
            self.assertEqual(base64.b64decode(cluster.error_msg).decode("utf-8"), expected_exception)

    def test_worker_create_kubernetes_cluster_missing_key_resources_google_nodes_throws_error(self):
        cluster_id = Clusters.objects.filter()[0].id
        resources = {'internal_dns_zone': 'test.test', 'googleSelected': True, 'google': {'region': 'test', 'zone': 'test', 'vpcCidr': '10.0.0.0/16', 'account': 'account', 'operatingSystem': 'operatingSystem/operatingSystem'}, 'onPremiseSelected': False, 'iotArmSelected': False}
        user_id = self.user.id

        expected_exception = str(KeyError('nodes'))
        expected_call_args = 'call(1, \'title\')'

        with patch.object(mailgun.mailgun_client.MailgunClient, 'email_environment_creation_failed') as mock:
            mock.side_effect = func_no_return

            worker_create_kubernetes_cluster(resources=resources, cluster_id=cluster_id, user_id=user_id)

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            mock.assert_called()
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
            self.assertEqual(cluster.installstep, -1)
            self.assertEqual(base64.b64decode(cluster.error_msg).decode("utf-8"), expected_exception)


    def test_worker_create_kubernetes_cluster_missing_key_resources_google_instancetypes_throws_error(self):
        cluster_id = Clusters.objects.filter()[0].id
        resources = {'internal_dns_zone': 'test.test', 'googleSelected': True, 'google': {'region': 'test', 'zone': 'test', 'nodes': '2', 'vpcCidr': '10.0.0.0/16', 'account': 'account', 'operatingSystem': 'operatingSystem/operatingSystem'}, 'onPremiseSelected': False, 'iotArmSelected': False}
        user_id = self.user.id

        expected_exception = str(KeyError('instanceType'))
        expected_call_args = 'call(1, \'title\')'

        with patch.object(mailgun.mailgun_client.MailgunClient, 'email_environment_creation_failed') as mock:
            mock.side_effect = func_no_return

            worker_create_kubernetes_cluster(resources=resources, cluster_id=cluster_id, user_id=user_id)

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            mock.assert_called()
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
            self.assertEqual(cluster.installstep, -1)
            self.assertEqual(base64.b64decode(cluster.error_msg).decode("utf-8"), expected_exception)

    def test_worker_create_kubernetes_cluster_missing_key_resources_aws_region_throws_error(self):
        cluster_id = Clusters.objects.filter()[0].id
        resources = {'internal_dns_zone': 'test.test', 'aws': {'vpcCidr': '10.0.0.0/16', 'account': 'account'}, 'awsSelected': True, 'alicloudSelected': False, 'googleSelected': False, 'onPremiseSelected': False, 'iotArmSelected': False}
        user_id = self.user.id

        expected_exception = str(KeyError('region'))
        expected_call_args = 'call(1, \'title\')'

        with patch.object(mailgun.mailgun_client.MailgunClient, 'email_environment_creation_failed') as mock:
            mock.side_effect = func_no_return

            worker_create_kubernetes_cluster(resources=resources, cluster_id=cluster_id, user_id=user_id)

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            mock.assert_called()
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
            self.assertEqual(cluster.installstep, -1)
            self.assertEqual(base64.b64decode(cluster.error_msg).decode("utf-8"), expected_exception)


    def test_worker_create_kubernetes_cluster_missing_key_resources_aws_nodes_throws_error(self):
        cluster_id = Clusters.objects.filter()[0].id
        resources = {'internal_dns_zone': 'test.test', 'aws': {'region': 'test', 'vpcCidr': '10.0.0.0/16', 'account': 'account', 'operatingSystem': 'operatingSystem/operatingSystem'}, 'awsSelected': True, 'alicloudSelected': False, 'googleSelected': False, 'onPremiseSelected': False, 'iotArmSelected': False}
        user_id = self.user.id

        expected_exception = str(KeyError('nodes'))
        expected_call_args = 'call(1, \'title\')'

        with patch.object(mailgun.mailgun_client.MailgunClient, 'email_environment_creation_failed') as mock:
            mock.side_effect = func_no_return

            worker_create_kubernetes_cluster(resources=resources, cluster_id=cluster_id, user_id=user_id)

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            mock.assert_called()
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
            self.assertEqual(cluster.installstep, -1)
            self.assertEqual(base64.b64decode(cluster.error_msg).decode("utf-8"), expected_exception)

    def test_worker_create_kubernetes_cluster_missing_key_resources_aws_instanceType_throws_error(self):
        cluster_id = Clusters.objects.filter()[0].id
        resources = {'internal_dns_zone': 'test.test', 'aws': {'region': 'test', 'nodes': '2', 'vpcCidr': '10.0.0.0/16', 'account': 'account', 'operatingSystem': 'operatingSystem/operatingSystem'}, 'awsSelected': True, 'alicloudSelected': False, 'googleSelected': False, 'onPremiseSelected': False, 'iotArmSelected': False}
        user_id = self.user.id

        expected_exception = str(KeyError('instanceType'))
        expected_call_args = 'call(1, \'title\')'

        with patch.object(mailgun.mailgun_client.MailgunClient, 'email_environment_creation_failed') as mock:
            mock.side_effect = func_no_return

            worker_create_kubernetes_cluster(resources=resources, cluster_id=cluster_id, user_id=user_id)

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            mock.assert_called()
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
            self.assertEqual(cluster.installstep, -1)
            self.assertEqual(base64.b64decode(cluster.error_msg).decode("utf-8"), expected_exception)

    def test_worker_create_kubernetes_cluster_missing_key_resources_azure_region_throws_error(self):
        cluster_id = Clusters.objects.filter()[0].id
        resources = {'internal_dns_zone': 'test.test', 'azureSelected': True, 'azure': {'vpcCidr': '10.0.0.0/16', 'account': 'account'}, 'awsSelected': False, 'alicloudSelected': False, 'googleSelected': False, 'onPremiseSelected': False, 'iotArmSelected': False}
        user_id = self.user.id

        expected_exception = str(KeyError('region'))
        expected_call_args = 'call(1, \'title\')'

        with patch.object(mailgun.mailgun_client.MailgunClient, 'email_environment_creation_failed') as mock:
            mock.side_effect = func_no_return

            worker_create_kubernetes_cluster(resources=resources, cluster_id=cluster_id, user_id=user_id)

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            mock.assert_called()
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
            self.assertEqual(cluster.installstep, -1)
            self.assertEqual(base64.b64decode(cluster.error_msg).decode("utf-8"), expected_exception)

    def test_worker_create_kubernetes_cluster_missing_key_resources_azure_nodes_throws_error(self):
        cluster_id = Clusters.objects.filter()[0].id
        resources = {'internal_dns_zone': 'test.test', 'azureSelected': True, 'azure': {'region': 'test', 'vpcCidr': '10.0.0.0/16', 'operatingSystem': 'credativ/Debian/9/9.20210129.0', 'account': 'account'}, 'awsSelected': False, 'alicloudSelected': False, 'googleSelected': False, 'onPremiseSelected': False, 'iotArmSelected': False}
        user_id = self.user.id

        expected_exception = str(KeyError('nodes'))
        expected_call_args = 'call(1, \'title\')'

        with patch.object(mailgun.mailgun_client.MailgunClient, 'email_environment_creation_failed') as mock:
            mock.side_effect = func_no_return

            worker_create_kubernetes_cluster(resources=resources, cluster_id=cluster_id, user_id=user_id)

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            mock.assert_called()
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
            self.assertEqual(cluster.installstep, -1)
            self.assertEqual(base64.b64decode(cluster.error_msg).decode("utf-8"), expected_exception)


    def test_worker_create_kubernetes_cluster_missing_key_resources_azure_instance_type_throws_error(self):
        cluster_id = Clusters.objects.filter()[0].id
        resources = {'internal_dns_zone': 'test.test', 'azureSelected': True, 'azure': {'region': 'test', 'nodes': '2', 'operatingSystem': 'credativ/Debian/9/9.20210129.0', 'vpcCidr': '10.0.0.0/16', 'account': 'account'}, 'awsSelected': False, 'alicloudSelected': False, 'googleSelected': False, 'onPremiseSelected': False, 'iotArmSelected': False}
        user_id = self.user.id

        expected_exception = str(KeyError('instanceType'))
        expected_call_args = 'call(1, \'title\')'

        with patch.object(mailgun.mailgun_client.MailgunClient, 'email_environment_creation_failed') as mock:
            mock.side_effect = func_no_return

            worker_create_kubernetes_cluster(resources=resources, cluster_id=cluster_id, user_id=user_id)

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            mock.assert_called()
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
            self.assertEqual(cluster.installstep, -1)
            self.assertEqual(base64.b64decode(cluster.error_msg).decode("utf-8"), expected_exception)
    
    def test_worker_create_kubernetes_cluster_missing_key_resources_azure_operatingSystem_throws_error(self):
        cluster_id = Clusters.objects.filter()[0].id
        resources = {'internal_dns_zone': 'test.test', 'azureSelected': True, 'azure': {'region': 'test', 'nodes': '2', 'vpcCidr': '10.0.0.0/16', 'account': 'account'}, 'awsSelected': False, 'alicloudSelected': False, 'googleSelected': False, 'onPremiseSelected': False, 'iotArmSelected': False}
        user_id = self.user.id

        expected_exception = str(KeyError('operatingSystem'))
        expected_call_args = 'call(1, \'title\')'

        with patch.object(mailgun.mailgun_client.MailgunClient, 'email_environment_creation_failed') as mock:
            mock.side_effect = func_no_return

            worker_create_kubernetes_cluster(resources=resources, cluster_id=cluster_id, user_id=user_id)

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            mock.assert_called()
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
            self.assertEqual(cluster.installstep, -1)
            self.assertEqual(base64.b64decode(cluster.error_msg).decode("utf-8"), expected_exception)
