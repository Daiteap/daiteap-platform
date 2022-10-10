import logging

from django.test import TestCase
from mock import MagicMock, patch

from environment_providers.aws.services.api_client import delete_k8s_loadbalancer_resources, delete_k8s_volume_resources


class DeleteK8sLoadbalancerResources(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

    def test_delete_k8s_loadbalancer_resources_invalid_parameter_aws_access_key_id_returns_error(self):
        aws_access_key_id = ''
        aws_secret_access_key = 'test'
        region = 'test'
        vpc_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter aws_access_key_id')

        try:
            delete_k8s_loadbalancer_resources(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region=region,
                vpc_name=vpc_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_k8s_loadbalancer_resources_invalid_parameter_aws_access_key_id_none_returns_error(self):
        aws_access_key_id = None
        aws_secret_access_key = 'test'
        region = 'test'
        vpc_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter aws_access_key_id')

        try:
            delete_k8s_loadbalancer_resources(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region=region,
                vpc_name=vpc_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_k8s_loadbalancer_resources_invalid_parameter_aws_secret_access_key_returns_error(self):
        aws_access_key_id = 'test'
        aws_secret_access_key = ''
        region = 'test'
        vpc_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter aws_secret_access_key')

        try:
            delete_k8s_loadbalancer_resources(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region=region,
                vpc_name=vpc_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_k8s_loadbalancer_resources_invalid_parameter_aws_secret_access_key_none_returns_error(self):
        aws_access_key_id = 'test'
        aws_secret_access_key = None
        region = 'test'
        vpc_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter aws_secret_access_key')

        try:
            delete_k8s_loadbalancer_resources(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region=region,
                vpc_name=vpc_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_k8s_loadbalancer_resources_invalid_parameter_region_returns_error(self):
        aws_access_key_id = 'test'
        aws_secret_access_key = 'test'
        region = ''
        vpc_name = 'test'

        expected_exception = AttributeError('Invalid input parameter region')

        try:
            delete_k8s_loadbalancer_resources(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region=region,
                vpc_name=vpc_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_k8s_loadbalancer_resources_invalid_parameter_region_none_returns_error(self):
        aws_access_key_id = 'test'
        aws_secret_access_key = 'test'
        region = None
        vpc_name = 'test'

        expected_exception = AttributeError('Invalid input parameter region')

        try:
            delete_k8s_loadbalancer_resources(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region=region,
                vpc_name=vpc_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_k8s_loadbalancer_resources_invalid_parameter_vpc_name_returns_error(self):
        aws_access_key_id = 'test'
        aws_secret_access_key = 'test'
        region = 'test'
        vpc_name = ''

        expected_exception = AttributeError('Invalid input parameter vpc_name')

        try:
            delete_k8s_loadbalancer_resources(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region=region,
                vpc_name=vpc_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_k8s_loadbalancer_resources_invalid_parameter_vpc_name_none_returns_error(self):
        aws_access_key_id = 'test'
        aws_secret_access_key = 'test'
        region = 'test'
        vpc_name = None

        expected_exception = AttributeError('Invalid input parameter vpc_name')

        try:
            delete_k8s_loadbalancer_resources(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region=region,
                vpc_name=vpc_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    @patch('boto3.client')
    def test_delete_k8s_loadbalancer_resources_vpc_not_found_returns_false(self, client_mock):
        aws_access_key_id = 'test'
        aws_secret_access_key = 'test'
        region = 'test'
        vpc_name = 'test'

        client_mock_obj = MagicMock()
        client_mock_obj.describe_vpcs = MagicMock(
            return_value={'Vpcs': [{'Tags': [{'Key': 'Name', 'Value': ''}]}]}
        )

        client_mock.return_value = client_mock_obj

        result = delete_k8s_loadbalancer_resources(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region=region,
            vpc_name=vpc_name
        )

        self.assertFalse(result)
        client_mock.assert_called_once()
        client_mock_obj.describe_vpcs.assert_called_once()

    @patch('boto3.client')
    def test_delete_k8s_loadbalancer_resources_missing_VPCId_key_returns_error(self, client_mock):
        aws_access_key_id = 'test'
        aws_secret_access_key = 'test'
        region = 'test'
        vpc_name = 'testname'

        client_mock_obj = MagicMock()
        client_mock_obj.describe_vpcs = MagicMock(
            return_value={'VpcId': 'testvpcid', 'Vpcs': [
                {'Tags': [{'Key': 'Name', 'Value': 'test'}]}
            ]}
        )
        client_mock_obj.describe_security_groups = MagicMock(
            return_value={}
        )
        client_mock_obj.describe_load_balancers = MagicMock(
            return_value={'LoadBalancerDescriptions': [
                {'LoadBalancerName': 'testlbname'}
            ]}
        )

        client_mock.returns_value = client_mock_obj

        result = delete_k8s_loadbalancer_resources(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region=region,
            vpc_name=vpc_name
        )

        self.assertFalse(result)
        client_mock.assert_called_once()

    @patch('boto3.client')
    @patch('boto3.resource')
    def test_delete_k8s_loadbalancer_resources_success_returns_True(self, resource_mock, client_mock):
        aws_access_key_id = 'test'
        aws_secret_access_key = 'test'
        region = 'test'
        vpc_name = 'testname'

        client_mock_obj = MagicMock()

        client_mock_obj.describe_vpcs = MagicMock(
            return_value={
                'Vpcs': [{'VpcId': 'testvpcid', 'Tags': [{'Key': 'Name', 'Value': 'testname'}]}]}
        )
        client_mock_obj.describe_security_groups = MagicMock(
            return_value={'SecurityGroups': [
                {'GroupName': 'tsg-default', 'VpcId': 'testvpcid',
                    'GroupId': 'sg-default'},
                {'GroupName': 'k8s-elb-test',
                    'VpcId': 'testvpcid', 'GroupId': 'sg-test'}
            ]}
        )
        client_mock_obj.describe_load_balancers = MagicMock(
            return_value={'LoadBalancerDescriptions': [
                {'VPCId': 'testvpcid', 'LoadBalancerName': 'testlbname'}
            ]}
        )
        client_mock_obj.delete_load_balancer = MagicMock()
        client_mock_obj.revoke_ingress = MagicMock()
        client_mock_obj.delete_security_group = MagicMock()

        resource_mock_obj = MagicMock()
        resource_mock_obj.SecurityGroup = MagicMock()

        client_mock.return_value = client_mock_obj
        resource_mock.return_value = resource_mock_obj

        result = delete_k8s_loadbalancer_resources(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region=region,
            vpc_name=vpc_name
        )

        self.assertTrue(result)
        self.assertEqual(client_mock.call_count, 2)
        self.assertEqual(resource_mock.call_count, 1)
        self.assertEqual(resource_mock_obj.SecurityGroup.call_count, 1)
        self.assertEqual(client_mock_obj.describe_vpcs.call_count, 1)
        self.assertTrue(client_mock_obj.describe_security_groups)
        self.assertTrue(client_mock_obj.describe_load_balancers)
        self.assertTrue(client_mock_obj.SecurityGroup)
        self.assertTrue(client_mock_obj.delete_load_balancer)
        self.assertTrue(client_mock_obj.revoke_ingress)
        self.assertTrue(client_mock_obj.delete_security_group)


class DeleteK8sVolumeResources(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

    def test_delete_k8s_volume_resources_invalid_parameter_aws_access_key_id_returns_error(self):
        aws_access_key_id = ''
        aws_secret_access_key = 'test'
        region = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter aws_access_key_id')

        try:
            delete_k8s_volume_resources(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region=region
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_k8s_volume_resources_invalid_parameter_aws_access_key_id_none_returns_error(self):
        aws_access_key_id = None
        aws_secret_access_key = 'test'
        region = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter aws_access_key_id')

        try:
            delete_k8s_volume_resources(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region=region
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_k8s_volume_resources_invalid_parameter_aws_secret_access_key_returns_error(self):
        aws_access_key_id = 'test'
        aws_secret_access_key = ''
        region = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter aws_secret_access_key')

        try:
            delete_k8s_volume_resources(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region=region
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_k8s_volume_resources_invalid_parameter_aws_secret_access_key_none_returns_error(self):
        aws_access_key_id = 'test'
        aws_secret_access_key = None
        region = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter aws_secret_access_key')

        try:
            delete_k8s_volume_resources(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region=region
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_k8s_volume_resources_invalid_parameter_region_returns_error(self):
        aws_access_key_id = 'test'
        aws_secret_access_key = 'test'
        region = ''

        expected_exception = AttributeError('Invalid input parameter region')

        try:
            delete_k8s_volume_resources(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region=region
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_k8s_volume_resources_invalid_parameter_region_none_returns_error(self):
        aws_access_key_id = 'test'
        aws_secret_access_key = 'test'
        region = None

        expected_exception = AttributeError('Invalid input parameter region')

        try:
            delete_k8s_volume_resources(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region=region
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    @patch('boto3.client')
    def test_delete_k8s_volume_resources_missing_Volumes_key_returns_error(self, client_mock):
        aws_access_key_id = 'test'
        aws_secret_access_key = 'test'
        region = 'test'

        client_mock_obj = MagicMock()
        client_mock_obj.describe_volumes = MagicMock(
            return_value={}
        )

        client_mock.return_value = client_mock_obj

        result = delete_k8s_volume_resources(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region=region
        )

        self.assertFalse(result)
        client_mock.assert_called_once()
        self.assertEqual(client_mock_obj.describe_volumes.call_count, 1)

    @patch('boto3.client')
    def test_delete_k8s_volume_resources_success_returns_True(self, client_mock):
        aws_access_key_id = 'test'
        aws_secret_access_key = 'test'
        region = 'test'

        client_mock_obj = MagicMock()
        client_mock_obj.describe_volumes = MagicMock(
            return_value={'Volumes': [{'VolumeId': 'test','Tags': [{'Key': 'CSIVolumeName', 'Value': 'pv-disk-daiteap-test'}]}]}
        )
        client_mock_obj.delete_volume = MagicMock(return_value='is currently attached to')

        client_mock.return_value = client_mock_obj

        result = delete_k8s_volume_resources(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region=region
        )

        self.assertTrue(result)
        self.assertEqual(client_mock.call_count, 1)
        self.assertEqual(client_mock_obj.describe_volumes.call_count, 1)
        self.assertEqual(client_mock_obj.delete_volume.call_count, 1)