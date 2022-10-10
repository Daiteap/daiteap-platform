import logging
from django.test import TestCase
from mock import MagicMock, patch
from environment_providers.google.services.api_client import delete_loadbalancer_resources, delete_disk_resources



class DeleteLoadbalancerResources(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

    def test_delete_loadbalancer_missing_input_google_key_returns_error(self):
        google_key = ''
        region = 'test'
        vpc_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter google_key')

        try:
            delete_loadbalancer_resources(
                google_key=google_key,
                region=region,
                vpc_name=vpc_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_loadbalancer_missing_input_region_returns_error(self):
        google_key = 'test'
        region = ''
        vpc_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter region')

        try:
            delete_loadbalancer_resources(
                google_key=google_key,
                region=region,
                vpc_name=vpc_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_loadbalancer_missing_input_vpc_name_returns_error(self):
        google_key = 'test'
        region = 'test'
        vpc_name = ''

        expected_exception = AttributeError(
            'Invalid input parameter vpc_name')

        try:
            delete_loadbalancer_resources(
                google_key=google_key,
                region=region,
                vpc_name=vpc_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_loadbalancer_invalid_input_google_key_returns_error(self):
        google_key = None
        region = 'test'
        vpc_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter google_key')

        try:
            delete_loadbalancer_resources(
                google_key=google_key,
                region=region,
                vpc_name=vpc_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_loadbalancer_invalid_input_region_returns_error(self):
        google_key = 'test'
        region = None
        vpc_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter region'
        )

        try:
            delete_loadbalancer_resources(
                google_key=google_key,
                region=region,
                vpc_name=vpc_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_loadbalancer_invalid_input_vpc_name_returns_error(self):
        google_key = 'test'
        region = 'test'
        vpc_name = None

        expected_exception = AttributeError(
            'Invalid input parameter vpc_name')

        try:
            delete_loadbalancer_resources(
                google_key=google_key,
                region=region,
                vpc_name=vpc_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    @patch('googleapiclient.discovery.build')
    @patch('google.oauth2.service_account.Credentials.from_service_account_info')
    def test_delete_loadbalancer_missing_forwarding_rules_list_key_returns_false(self, credentials_mock, discovery_mock):
        google_key = '{"project_id": "testkey"}'
        region = 'test'
        vpc_name = 'test'

        forwarding_rules_execute = MagicMock()
        forwarding_rules_execute.execute = MagicMock(
            return_value={'items': []})

        forwarding_rules = MagicMock()
        forwarding_rules.list = MagicMock(
            return_value=forwarding_rules_execute)

        service_mock = MagicMock()
        service_mock.forwardingRules = MagicMock(return_value=forwarding_rules)

        discovery_mock.return_value = service_mock
        credentials_mock.return_value = 'test'

        result = delete_loadbalancer_resources(
            google_key=google_key,
            region=region,
            vpc_name=vpc_name
        )

        self.assertFalse(result)
        self.assertEqual(credentials_mock.call_count, 1)
        self.assertEqual(discovery_mock.call_count, 1)
        self.assertEqual(service_mock.forwardingRules.call_count, 1)
        self.assertEqual(forwarding_rules_execute.execute.call_count, 1)
        self.assertEqual(forwarding_rules.list.call_count, 1)

    @patch('googleapiclient.discovery.build')
    @patch('google.oauth2.service_account.Credentials.from_service_account_info')
    def test_delete_loadbalancer_missing_targetPools_items_key_returns_false(self, credentials_mock, discovery_mock):
        google_key = '{"project_id": "testkey"}'
        region = 'test'
        vpc_name = 'test'

        forwarding_rules_execute = MagicMock()
        forwarding_rules_execute.execute = MagicMock(
            return_value={'items': []})

        forwarding_rules = MagicMock()
        forwarding_rules.list = MagicMock(
            return_value=forwarding_rules_execute)

        target_pools_execute = MagicMock()
        target_pools_execute.execute = MagicMock(return_value={})

        target_pools = MagicMock()
        target_pools.list = MagicMock(return_value=target_pools_execute)

        service_mock = MagicMock()
        service_mock.forwardingRules = MagicMock(return_value=forwarding_rules)
        service_mock.targetPools = MagicMock(return_value=target_pools)

        discovery_mock.return_value = service_mock
        credentials_mock.return_value = 'test'

        result = delete_loadbalancer_resources(
            google_key=google_key,
            region=region,
            vpc_name=vpc_name
        )

        self.assertFalse(result)
        self.assertEqual(credentials_mock.call_count, 1)
        self.assertEqual(discovery_mock.call_count, 1)
        self.assertEqual(service_mock.forwardingRules.call_count, 1)
        self.assertEqual(forwarding_rules_execute.execute.call_count, 1)
        self.assertEqual(forwarding_rules.list.call_count, 1)
        self.assertEqual(target_pools_execute.execute.call_count, 1)
        self.assertEqual(target_pools.list.call_count, 1)

    @patch('googleapiclient.discovery.build')
    @patch('google.oauth2.service_account.Credentials.from_service_account_info')
    def test_delete_loadbalancer_missing_firewall_rules_items_key_returns_false(self, credentials_mock, discovery_mock):
        google_key = '{"project_id": "testkey"}'
        region = 'test'
        vpc_name = 'test'

        firewall_rules_execute = MagicMock()
        firewall_rules_execute.execute = MagicMock(return_value={})
        firewall_rules = MagicMock()
        firewall_rules.list = MagicMock(return_value=firewall_rules_execute)

        forwarding_rules_execute = MagicMock()
        forwarding_rules_execute.execute = MagicMock(
            return_value={'items': []})
        forwarding_rules = MagicMock()
        forwarding_rules.list = MagicMock(
            return_value=forwarding_rules_execute)
        forwarding_rules.delete = MagicMock()

        target_pools_execute = MagicMock()
        target_pools_execute.execute = MagicMock(
            return_value={'items': [{'instances': ['test'], 'id': 'test', 'name': 'test'}]})
        target_pools = MagicMock()
        target_pools.list = MagicMock(return_value=target_pools_execute)

        service_mock = MagicMock()
        service_mock.forwardingRules = MagicMock(return_value=forwarding_rules)
        service_mock.targetPools = MagicMock(return_value=target_pools)
        service_mock.firewalls = MagicMock(return_value=firewall_rules)

        discovery_mock.return_value = service_mock
        credentials_mock.return_value = 'test'

        result = delete_loadbalancer_resources(
            google_key=google_key,
            region=region,
            vpc_name=vpc_name
        )

        self.assertFalse(result)
        self.assertEqual(credentials_mock.call_count, 1)
        self.assertEqual(discovery_mock.call_count, 1)
        self.assertEqual(service_mock.forwardingRules.call_count, 1)
        self.assertEqual(forwarding_rules_execute.execute.call_count, 1)
        self.assertEqual(forwarding_rules.list.call_count, 1)
        self.assertEqual(forwarding_rules.delete.call_count, 1)
        self.assertEqual(target_pools_execute.execute.call_count, 1)
        self.assertEqual(target_pools.list.call_count, 1)
        self.assertEqual(firewall_rules_execute.execute.call_count, 1)
        self.assertEqual(firewall_rules.list.call_count, 1)

    @patch('googleapiclient.discovery.build')
    @patch('google.oauth2.service_account.Credentials.from_service_account_info')
    def test_delete_loadbalancer_success_returns_true(self, credentials_mock, discovery_mock):
        google_key = '{"project_id": "testkey"}'
        region = 'test'
        vpc_name = 'test'

        firewall_rules_execute = MagicMock()
        firewall_rules_execute.execute = MagicMock(
            return_value={'items': [{'targetTags': ['test'], 'id': 'test'}]})
        firewall_rules = MagicMock()
        firewall_rules.list = MagicMock(return_value=firewall_rules_execute)

        forwarding_rules_execute = MagicMock()
        forwarding_rules_execute.execute = MagicMock(
            return_value={'items': []})
        forwarding_rules = MagicMock()
        forwarding_rules.delete = MagicMock()
        forwarding_rules.list = MagicMock(
            return_value=forwarding_rules_execute)
        forwarding_rules.delete = MagicMock()

        target_pools_execute = MagicMock()
        target_pools_execute.execute = MagicMock(
            return_value={'items': [{'instances': ['test'], 'id': 'test', 'name': 'test'}]})
        target_pools = MagicMock()
        target_pools.list = MagicMock(return_value=target_pools_execute)

        service_mock = MagicMock()
        service_mock.forwardingRules = MagicMock(return_value=forwarding_rules)
        service_mock.targetPools = MagicMock(return_value=target_pools)
        service_mock.firewalls = MagicMock(return_value=firewall_rules)

        discovery_mock.return_value = service_mock
        credentials_mock.return_value = 'test'

        result = delete_loadbalancer_resources(
            google_key=google_key,
            region=region,
            vpc_name=vpc_name
        )

        self.assertTrue(result)
        self.assertEqual(credentials_mock.call_count, 1)
        self.assertEqual(discovery_mock.call_count, 1)
        self.assertEqual(service_mock.forwardingRules.call_count, 1)
        self.assertEqual(forwarding_rules_execute.execute.call_count, 1)
        self.assertEqual(forwarding_rules.list.call_count, 1)
        self.assertEqual(target_pools_execute.execute.call_count, 1)
        self.assertEqual(target_pools.list.call_count, 1)
        self.assertEqual(firewall_rules_execute.execute.call_count, 1)
        self.assertEqual(firewall_rules.list.call_count, 1)
        self.assertEqual(firewall_rules.delete.call_count, 1)


class DeleteDiskResources(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

    def test_delete_disk_missing_input_google_key_returns_error(self):
        google_key = ''
        zone = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter google_key')

        try:
            delete_disk_resources(
                google_key=google_key,
                zone=zone
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_disk_invalid_input_google_key_returns_error(self):
        google_key = None
        zone = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter google_key')

        try:
            delete_disk_resources(
                google_key=google_key,
                zone=zone
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_disk_missing_input_zone_returns_error(self):
        google_key = 'test'
        zone = ''

        expected_exception = AttributeError(
            'Invalid input parameter zone')

        try:
            delete_disk_resources(
                google_key=google_key,
                zone=zone
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_disk_invalid_input_zone_returns_error(self):
        google_key = 'test'
        zone = None

        expected_exception = AttributeError(
            'Invalid input parameter zone')

        try:
            delete_disk_resources(
                google_key=google_key,
                zone=zone
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    @patch('googleapiclient.discovery.build')
    @patch('google.oauth2.service_account.Credentials.from_service_account_info')
    def test_delete_disk_missing_disks_list_key_returns_false(self, credentials_mock, discovery_mock):
        google_key = '{"project_id": "testkey"}'
        zone = 'test'

        disks_execute = MagicMock()
        disks_execute.execute = MagicMock(
            return_value={})

        disks = MagicMock()
        disks.list = MagicMock(
            return_value=disks_execute)

        service_mock = MagicMock()
        service_mock.disks = MagicMock(return_value=disks)

        discovery_mock.return_value = service_mock
        credentials_mock.return_value = 'test'

        result = delete_disk_resources(
            google_key=google_key,
            zone=zone
        )

        self.assertFalse(result)
        self.assertEqual(credentials_mock.call_count, 1)
        self.assertEqual(discovery_mock.call_count, 1)
        self.assertEqual(service_mock.disks.call_count, 1)
        self.assertEqual(disks_execute.execute.call_count, 1)
        self.assertEqual(disks.list.call_count, 1)

    @patch('googleapiclient.discovery.build')
    @patch('google.oauth2.service_account.Credentials.from_service_account_info')
    def test_delete_disks_success_returns_true(self, credentials_mock, discovery_mock):
        google_key = '{"project_id": "testkey"}'
        zone = 'zone'

        disks_execute = MagicMock()
        disks_execute.execute = MagicMock(
            return_value={'items': [{
                'instances': ['test'],
                'id': 'test',
                'name': 'pv-disk-daiteap-test',
                'description': 'Disk created by GCE-PD CSI Driver'
            }]}
        )
        disks = MagicMock()
        disks.delete = MagicMock()
        disks.list = MagicMock(return_value=disks_execute)
        disks.delete = MagicMock()

        service_mock = MagicMock()
        service_mock.disks = MagicMock(return_value=disks)

        discovery_mock.return_value = service_mock
        credentials_mock.return_value = 'test'

        result = delete_disk_resources(
            google_key=google_key,
            zone=zone
        )

        self.assertTrue(result)
        self.assertEqual(credentials_mock.call_count, 1)
        self.assertEqual(discovery_mock.call_count, 1)
        self.assertEqual(service_mock.disks.call_count, 2)
        self.assertEqual(disks_execute.execute.call_count, 1)
        self.assertEqual(disks.list.call_count, 1)
