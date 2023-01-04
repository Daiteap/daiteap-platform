from django.test import TestCase
from ..services import data_masker


class MaskData(TestCase):
    def test_mask_in_string_no_pattern_found(self):
        test_str = "Text with no senstive data."
        result_str = data_masker.mask_in_string(test_str)

        self.assertEqual(result_str, test_str)

    def test_mask_in_string_gcp_token(self):
        test_str = 'GCP error - "Help Token: TOKEN". Details...'
        result_str = data_masker.mask_in_string(test_str)
        expected_str = 'GCP error - "Help Token: *******". Details...'

        self.assertNotEqual(result_str, test_str)
        self.assertEqual(result_str, expected_str)

    def test_mask_in_string_aws_credentials_validation(self):
        test_str = "{'aws': True, 'aws_access_key_id': 'SECRET', 'aws_secret_access_key': 'SECRET', 'id': 1}"
        result_str = data_masker.mask_in_string(test_str)
        expected_str = "{'aws': True, 'aws_access_key_id': '*******', 'aws_secret_access_key': '*******', 'id': 1}"

        self.assertNotEqual(result_str, test_str)
        self.assertEqual(result_str, expected_str)

    def test_mask_in_string_azure_credentials_validation(self):
        test_str = "{'azure': True, 'azure_tenant_id': 'SECRET', 'azure_subscription_id': 'SECRET', 'azure_client_id': 'SECRET', 'azure_client_secret': 'SECRET', 'id': 1}"
        result_str = data_masker.mask_in_string(test_str)
        expected_str = "{'azure': True, 'azure_tenant_id': '*******', 'azure_subscription_id': '*******', 'azure_client_id': '*******', 'azure_client_secret': '*******', 'id': 1}"

        self.assertNotEqual(result_str, test_str)
        self.assertEqual(result_str, expected_str)

    def test_mask_in_string_google_credentials_validation(self):
        test_str = "{'google': True, 'google_key': 'SECRET', 'id': 1}"
        result_str = data_masker.mask_in_string(test_str)
        expected_str = "{'google': True, 'google_key': '*******', 'id': 1}"

        self.assertNotEqual(result_str, test_str)
        self.assertEqual(result_str, expected_str)

    def test_mask_in_string_openstack_credentials_validation(self):
        test_str = "{'openstack': True, 'region_name': 'SECRET', 'auth_url': 'SECRET', 'application_credential_id': 'SECRET', 'application_credential_secret': 'SECRET', 'external_network_id': 'SECRET', 'id': 1}"
        result_str = data_masker.mask_in_string(test_str)
        expected_str = "{'openstack': True, 'region_name': '*******', 'auth_url': '*******', 'application_credential_id': '*******', 'application_credential_secret': '*******', 'external_network_id': '*******', 'id': 1}"

        self.assertNotEqual(result_str, test_str)
        self.assertEqual(result_str, expected_str)

    def test_mask_in_string_onpremise_credentials_validation(self):
        test_str = "{'onpremise': True, 'gw_public_ip': 'SECRET', 'gw_private_ip': 'SECRET', 'admin_username': 'SECRET', 'admin_private_key': 'SECRET', 'admin_private_key_password': 'SECRET', 'id': 1}"
        result_str = data_masker.mask_in_string(test_str)
        expected_str = "{'onpremise': True, 'gw_public_ip': '*******', 'gw_private_ip': '*******', 'admin_username': '*******', 'admin_private_key': '*******', 'admin_private_key_password': '*******', 'id': 1}"

        self.assertNotEqual(result_str, test_str)
        self.assertEqual(result_str, expected_str)

    def test_mask_in_string_iotarm_credentials_validation(self):
        test_str = "{'iotarm': True, 'gw_public_ip': 'SECRET', 'gw_private_ip': 'SECRET', 'admin_username': 'SECRET', 'admin_private_key': 'SECRET', 'admin_private_key_password': 'SECRET', 'vpcCidr': 'SECRET', 'id': 1}"
        result_str = data_masker.mask_in_string(test_str)
        expected_str = "{'iotarm': True, 'gw_public_ip': '*******', 'gw_private_ip': '*******', 'admin_username': '*******', 'admin_private_key': '*******', 'admin_private_key_password': '*******', 'vpcCidr': '*******', 'id': 1}"

        self.assertNotEqual(result_str, test_str)
        self.assertEqual(result_str, expected_str)
