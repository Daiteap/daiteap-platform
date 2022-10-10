
from django.test import TestCase
import logging
from ..terraform.terraform_client import TerraformClient
from mock.mock import patch
from ..test.mock_funcs import func_no_return
import cloudcluster


class TerraformClientApply(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

    def test_apply_tfstate_not_dict_throws_error(self):
        terraform_client = TerraformClient()
        terraform_client.tfstate = 'test'
        expected_exception = AttributeError('tfstate is not a dictionary')

        try:
            terraform_client.apply(1, '', '')
        except AttributeError as e:
            returned_exception = e

        self.assertEqual(type(expected_exception), type(returned_exception))
        self.assertEqual(str(expected_exception), str(returned_exception))


    # def test_apply_missing_tfstate_returns_exception(self):
    #     expected_exception = Exception('tfstate file does not exist')
    #     terraform_client = TerraformClient()
    #     terraform_client.alicloud = True
    #     terraform_client.aws = True
    #     terraform_client.azure = True
    #     terraform_client.google = True
    #     expected_calls = ['terraform', 'init', './cloudcluster/terraform/']

    #     with patch.object(cloudcluster.services.run_shell, 'run_shell_with_subprocess_popen') as mock:
    #         mock.side_effect = func_no_return

    #         try:
    #             terraform_client.apply(1, '', '')
    #         except Exception as e:
    #             returned_exception = e

    #         mock.assert_called()
    #         self.assertEqual(mock.call_count, 1)
    #         self.assertEqual(str(mock.call_args_list[0][0][0][0]), expected_calls[0])
    #         self.assertEqual(str(mock.call_args_list[0][0][0][1]), expected_calls[1])
    #         self.assertTrue(expected_calls[2] in str(mock.call_args_list[0][0][0][2]))
    #         self.assertEqual(type(expected_exception), type(returned_exception))
    #         self.assertEqual(str(expected_exception), str(returned_exception))