import logging

from django.test import TestCase
from mock import MagicMock, patch

from environment_providers.azure.services.api_client import delete_load_balancers


class DeleteLoadbalancers(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

    def test_delete_loadbalancer_missing_parameter_azure_tenant_id_returns_error(self):
        azure_tenant_id = ''
        azure_subscription_id = 'test'
        azure_client_id = 'test'
        azure_client_secret = 'test'
        resource_group_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter azure_tenant_id')

        try:
            delete_load_balancers(
                azure_tenant_id=azure_tenant_id,
                azure_subscription_id=azure_subscription_id,
                azure_client_id=azure_client_id,
                azure_client_secret=azure_client_secret,
                resource_group_name=resource_group_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_loadbalancer_invalid_parameter_azure_tenant_id_returns_error(self):
        azure_tenant_id = None
        azure_subscription_id = 'test'
        azure_client_id = 'test'
        azure_client_secret = 'test'
        resource_group_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter azure_tenant_id')

        try:
            delete_load_balancers(
                azure_tenant_id=azure_tenant_id,
                azure_subscription_id=azure_subscription_id,
                azure_client_id=azure_client_id,
                azure_client_secret=azure_client_secret,
                resource_group_name=resource_group_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_loadbalancer_missing_parameter_azure_subscription_id_returns_error(self):
        azure_tenant_id = 'test'
        azure_subscription_id = ''
        azure_client_id = 'test'
        azure_client_secret = 'test'
        resource_group_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter azure_subscription_id')

        try:
            delete_load_balancers(
                azure_tenant_id=azure_tenant_id,
                azure_subscription_id=azure_subscription_id,
                azure_client_id=azure_client_id,
                azure_client_secret=azure_client_secret,
                resource_group_name=resource_group_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_loadbalancer_invalid_parameter_azure_subscription_id_returns_error(self):
        azure_tenant_id = 'test'
        azure_subscription_id = None
        azure_client_id = 'test'
        azure_client_secret = 'test'
        resource_group_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter azure_subscription_id')

        try:
            delete_load_balancers(
                azure_tenant_id=azure_tenant_id,
                azure_subscription_id=azure_subscription_id,
                azure_client_id=azure_client_id,
                azure_client_secret=azure_client_secret,
                resource_group_name=resource_group_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_loadbalancer_missing_parameter_azure_client_id_returns_error(self):
        azure_tenant_id = 'test'
        azure_subscription_id = 'test'
        azure_client_id = ''
        azure_client_secret = 'test'
        resource_group_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter azure_client_id')

        try:
            delete_load_balancers(
                azure_tenant_id=azure_tenant_id,
                azure_subscription_id=azure_subscription_id,
                azure_client_id=azure_client_id,
                azure_client_secret=azure_client_secret,
                resource_group_name=resource_group_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_loadbalancer_invalid_parameter_azure_client_id_returns_error(self):
        azure_tenant_id = 'test'
        azure_subscription_id = 'test'
        azure_client_id = None
        azure_client_secret = 'test'
        resource_group_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter azure_client_id')

        try:
            delete_load_balancers(
                azure_tenant_id=azure_tenant_id,
                azure_subscription_id=azure_subscription_id,
                azure_client_id=azure_client_id,
                azure_client_secret=azure_client_secret,
                resource_group_name=resource_group_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_loadbalancer_missing_parameter_resource_group_name_returns_error(self):
        azure_tenant_id = 'test'
        azure_subscription_id = 'test'
        azure_client_id = 'test'
        azure_client_secret = ''
        resource_group_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter azure_client_secret')

        try:
            delete_load_balancers(
                azure_tenant_id=azure_tenant_id,
                azure_subscription_id=azure_subscription_id,
                azure_client_id=azure_client_id,
                azure_client_secret=azure_client_secret,
                resource_group_name=resource_group_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_loadbalancer_invalid_parameter_azure_client_secret_returns_error(self):
        azure_tenant_id = 'test'
        azure_subscription_id = 'test'
        azure_client_id = 'test'
        azure_client_secret = None
        resource_group_name = 'test'

        expected_exception = AttributeError(
            'Invalid input parameter azure_client_secret')

        try:
            delete_load_balancers(
                azure_tenant_id=azure_tenant_id,
                azure_subscription_id=azure_subscription_id,
                azure_client_id=azure_client_id,
                azure_client_secret=azure_client_secret,
                resource_group_name=resource_group_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_loadbalancer_missing_parameter_azure_client_secret_returns_error(self):
        azure_tenant_id = 'test'
        azure_subscription_id = 'test'
        azure_client_id = 'test'
        azure_client_secret = 'test'
        resource_group_name = ''

        expected_exception = AttributeError(
            'Invalid input parameter resource_group_name')

        try:
            delete_load_balancers(
                azure_tenant_id=azure_tenant_id,
                azure_subscription_id=azure_subscription_id,
                azure_client_id=azure_client_id,
                azure_client_secret=azure_client_secret,
                resource_group_name=resource_group_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    def test_delete_loadbalancer_invalid_parameter_resource_group_name_returns_error(self):
        azure_tenant_id = 'test'
        azure_subscription_id = 'test'
        azure_client_id = 'test'
        azure_client_secret = 'test'
        resource_group_name = None

        expected_exception = AttributeError(
            'Invalid input parameter resource_group_name')

        try:
            delete_load_balancers(
                azure_tenant_id=azure_tenant_id,
                azure_subscription_id=azure_subscription_id,
                azure_client_id=azure_client_id,
                azure_client_secret=azure_client_secret,
                resource_group_name=resource_group_name
            )
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))

    @patch('azure.common.credentials.ServicePrincipalCredentials')
    @patch('azure.mgmt.network.NetworkManagementClient')
    def test_delete_loadbalancer_success_returns_true(self, network_management_client_mock ,service_principal_credentials_mock):
        azure_tenant_id = 'test'
        azure_subscription_id = 'test'
        azure_client_id = 'test'
        azure_client_secret = 'test'
        resource_group_name = 'test'

        credentials_mock = MagicMock()

        load_balancer_stub = MagicMock()

        load_balancers_mock = MagicMock()
        load_balancers_mock.list = MagicMock(return_value = [load_balancer_stub, load_balancer_stub])

        network_client_mock = MagicMock()
        network_client_mock.load_balancers = load_balancers_mock

        service_principal_credentials_mock.return_value = credentials_mock
        network_management_client_mock.return_value = network_client_mock

        result = delete_load_balancers(
            azure_tenant_id=azure_tenant_id,
            azure_subscription_id=azure_subscription_id,
            azure_client_id=azure_client_id,
            azure_client_secret=azure_client_secret,
            resource_group_name=resource_group_name
        )

        self.assertTrue(result)
        self.assertEqual(load_balancers_mock.list.call_count, 1)
        self.assertEqual(service_principal_credentials_mock.call_count, 1)