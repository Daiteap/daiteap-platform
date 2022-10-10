import logging
import os
import pathlib
import subprocess
from mock import patch

from ..services import run_shell
from django.test import TestCase

from ..ansible import ansible_client

def func_with_exception(*arg):
    raise Exception('Mocked Exception')

def func_returns_false(*arg):
    return False

def func_no_return(cmd='', return_stdout=True, raise_on_error=True, log_data={}, *arg):
    return

FILE_BASE_DIR = str(pathlib.Path(__file__).parent.absolute().parent)

class AnsibleClientDNS(TestCase):
    def setUp(self):
        self.maxDiff = None
        logger = logging.getLogger()
        logger.disabled = True

        self.test_client = ansible_client.AnsibleClient()

    def test_run_dns_empty_node_lists_returns_exception(self):
        expected_exception = Exception('Nodes list is empty')

        nodes_ips = {}

        dns_servers_ips = {
            'google_server_ip': '1.1.1.1',
            'alicloud_server_ip': '',
            'aws_server_ip': '',
            'azure_server_ip': '',
            'openstack_server_ip': '',
            'onpremise_server_ip': '',
            'iotarm_server_ip': ''
        }

        try:
            returned_data = self.test_client.run_dns(1, '', '', nodes_ips, [], '3.3.3.3', dns_servers_ips, 'test.test', 'aws')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_dns_playbook_missing_returns_exception(self):
        expected_exception = Exception('Playbook does not exist')

        with patch('os.path.exists', new=func_returns_false):

            nodes_ips = {
                'alicloud_nodes': ['0.0.0.0'],
                'alicloud_server_private_ip': '0.0.0.0',
                'google_nodes': [],
                'google_server_private_ip': '',
                'aws_nodes': [],
                'aws_server_private_ip': '',
                'azure_nodes': [],
                'azure_server_private_ip': '',
                'openstack_nodes': [],
                'openstack_server_private_ip': '',
                'onpremise_nodes': [],
                'onpremise_server_private_ip': '',
                'iotarm_nodes': [],
                'iotarm_server_private_ip': ''
            }

            dns_servers_ips = {
                'google_server_ip': '1.1.1.1',
                'alicloud_server_ip': '',
                'aws_server_ip': '',
                'azure_server_ip': '',
                'openstack_server_ip': '',
                'onpremise_server_ip': '',
                'iotarm_server_ip': ''
            }

            try:
                returned_data = self.test_client.run_dns(1, '', '', nodes_ips, [], '2.2.2.2', dns_servers_ips, 'test.test', 'aws')
            except Exception as e:
                print(e)
                returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_dns_empty_google_server_private_ip_returns_exception(self):
        expected_exception = Exception('google_server_private_ip is empty')

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            nodes_ips = {
                'google_nodes': ['0.0.0.0'],
            }

            dns_servers_ips = {
                'google_server_ip': '1.1.1.1',
            }

            try:
                returned_data = self.test_client.run_dns(1, '', '', nodes_ips, [], '2.2.2.2', dns_servers_ips, 'test.test', 'google')
            except Exception as e:
                returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_dns_empty_aws_server_private_ip_returns_exception(self):
        expected_exception = Exception('aws_server_private_ip is empty')

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            nodes_ips = {
                'aws_nodes': ['0.0.0.0'],
            }

            dns_servers_ips = {
                'aws_server_ip': '',
            }

            try:
                returned_data = self.test_client.run_dns(1, '', '', nodes_ips, [], '2.2.2.2', dns_servers_ips, 'test.test', 'aws')
            except Exception as e:
                returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_dns_empty_azure_server_private_ip_returns_exception(self):
        expected_exception = Exception('azure_server_private_ip is empty')

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            nodes_ips = {
                'azure_nodes': ['0.0.0.0'],
            }

            dns_servers_ips = {
                'azure_server_ip': '',
            }

            try:
                returned_data = self.test_client.run_dns(1, '', '', nodes_ips, [], '2.2.2.2', dns_servers_ips, 'test.test', 'azure')
            except Exception as e:
                returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_dns_correct_google_only_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns/hosts.ini', '-e', '{"dns_servers": [], "provider_nodes": [], "dns_server_nodes_addresses": [], "provider_server_ip": "", "provider_server_private_ip": "", "internal_dns_zone": "test.test", "gateway_address": "2.2.2.2", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns/dns.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            nodes_ips = {
                'alicloud_nodes': ['0.0.0.1', '0.0.0.2'],
                'alicloud_server_private_ip': '192.0.0.0',
                'google_nodes': [],
                'google_server_private_ip': '',
                'aws_nodes': [],
                'aws_server_private_ip': '',
                'azure_nodes': [],
                'azure_server_private_ip': '',
                'openstack_nodes': [],
                'openstack_server_private_ip': '',
                'onpremise_nodes': [],
                'onpremise_server_private_ip': '',
                'iotarm_nodes': [],
                'iotarm_server_private_ip': ''
            }

            dns_servers_ips = {
                'google_server_ip': '',
                'alicloud_server_ip': '0.0.0.1',
                'aws_server_ip': '',
                'azure_server_ip': '',
                'openstack_server_ip': '',
                'onpremise_server_ip': '',
                'iotarm_server_ip': ''
            }

            try:
                returned_data = self.test_client.run_dns(1, '', '', nodes_ips, [], '2.2.2.2', dns_servers_ips, 'test.test', 'aws')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            self.assertEqual(mock.call_count, 1)
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)

    def test_run_dns_correct_aws_only_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns/hosts.ini', '-e', '{"dns_servers": [], "provider_nodes": ["0.0.0.1", "0.0.0.2"], "dns_server_nodes_addresses": [], "provider_server_ip": "0.0.0.1", "provider_server_private_ip": "192.0.0.0", "internal_dns_zone": "test.test", "gateway_address": "2.2.2.2", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns/dns.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return

            nodes_ips = {
                'alicloud_nodes': [],
                'alicloud_server_private_ip': '',
                'google_nodes': [],
                'google_server_private_ip': '',
                'aws_nodes': ['0.0.0.1', '0.0.0.2'],
                'aws_server_private_ip': '192.0.0.0',
                'azure_nodes': [],
                'azure_server_private_ip': '',
                'openstack_nodes': [],
                'openstack_server_private_ip': '',
                'onpremise_nodes': [],
                'onpremise_server_private_ip': '',
                'iotarm_nodes': [],
                'iotarm_server_private_ip': ''
            }

            dns_servers_ips = {
                'google_server_ip': '',
                'alicloud_server_ip': '',
                'aws_server_ip': '0.0.0.1',
                'azure_server_ip': '',
                'openstack_server_ip': '',
                'onpremise_server_ip': '',
                'iotarm_server_ip': ''
            }

            try:
                returned_data = self.test_client.run_dns(1, '', '', nodes_ips, [], '2.2.2.2', dns_servers_ips, 'test.test', 'aws')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            self.assertEqual(mock.call_count, 1)
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)

    def test_run_dns_correct_azure_only_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns/hosts.ini', '-e', '{"dns_servers": [], "provider_nodes": [], "dns_server_nodes_addresses": [], "provider_server_ip": "", "provider_server_private_ip": "", "internal_dns_zone": "test.test", "gateway_address": "2.2.2.2", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns/dns.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return

            nodes_ips = {
                'alicloud_nodes': [],
                'alicloud_server_private_ip': '',
                'google_nodes': [],
                'google_server_private_ip': '',
                'aws_nodes': [],
                'aws_server_private_ip': '',
                'azure_nodes': ['0.0.0.1', '0.0.0.2'],
                'azure_server_private_ip': '192.0.0.0',
                'openstack_nodes': [],
                'openstack_server_private_ip': '',
                'onpremise_nodes': [],
                'onpremise_server_private_ip': '',
                'iotarm_nodes': [],
                'iotarm_server_private_ip': ''
            }

            dns_servers_ips = {
                'google_server_ip': '',
                'alicloud_server_ip': '',
                'aws_server_ip': '',
                'azure_server_ip': '0.0.0.1',
                'openstack_server_ip': '',
                'onpremise_server_ip': '',
                'iotarm_server_ip': ''
            }

            try:
                returned_data = self.test_client.run_dns(1, '', '', nodes_ips, [], '2.2.2.2', dns_servers_ips, 'test.test', 'aws')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            self.assertEqual(mock.call_count, 1)
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)
 
    def test_run_dns_correct_quadruple_cloud_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns/hosts.ini', '-e', '{"google_nodes": ["0.0.0.1","0.0.0.2"], "aws_dns_server": "3.3.3.3", "alicloud_nodes": ["0.0.1.1","0.0.1.2"], "aws_nodes": ["0.0.2.1","0.0.2.2"], "azure_nodes": ["0.0.3.1","0.0.3.2"], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "google_server_ip": "0.0.0.1", "alicloud_server_ip": "0.0.1.1", "aws_server_ip": "0.0.2.1", "azure_server_ip": "0.0.3.1", "openstack_server_ip": "", "onpremise_server_ip": "", "iotarm_server_ip": "", "internal_dns_zone": "test.test", "google_server_private_ip": "192.0.0.0", "aws_server_private_ip": "192.0.0.2", "azure_server_private_ip": "192.0.0.3", "gateway_address": "2.2.2.2", "openstack_server_private_ip": "", "onpremise_server_private_ip": "", "onpremise_nodes_addresses": [], "iotarm_server_private_ip": "", "iotarm_nodes_addresses": [], "alicloud_server_private_ip": "192.0.0.1", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns/dns.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns/hosts.ini', '-e', '{"dns_servers": [], "provider_nodes": ["0.0.2.1", "0.0.2.2"], "dns_server_nodes_addresses": [], "provider_server_ip": "0.0.2.1", "provider_server_private_ip": "192.0.0.2", "internal_dns_zone": "test.test", "gateway_address": "2.2.2.2", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns/dns.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            nodes_ips = {
                'alicloud_nodes': ['0.0.1.1', '0.0.1.2'],
                'alicloud_server_private_ip': '192.0.0.1',
                'google_nodes': ['0.0.0.1', '0.0.0.2'],
                'google_server_private_ip': '192.0.0.0',
                'aws_nodes': ['0.0.2.1', '0.0.2.2'],
                'aws_server_private_ip': '192.0.0.2',
                'azure_nodes': ['0.0.3.1', '0.0.3.2'],
                'azure_server_private_ip': '192.0.0.3',
                'openstack_nodes': [],
                'openstack_server_private_ip': '',
                'onpremise_nodes': [],
                'onpremise_server_private_ip': '',
                'iotarm_nodes': [],
                'iotarm_server_private_ip': ''
            }

            dns_servers_ips = {
                'google_server_ip': '0.0.0.1',
                'alicloud_server_ip': '0.0.1.1',
                'aws_server_ip': '0.0.2.1',
                'azure_server_ip': '0.0.3.1',
                'openstack_server_ip': '',
                'onpremise_server_ip': '',
                'iotarm_server_ip': ''
            }

            try:
                returned_data = self.test_client.run_dns(1, '', '', nodes_ips, [], '2.2.2.2', dns_servers_ips, 'test.test', 'aws')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            self.assertEqual(mock.call_count, 1)
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)


class AnsibleClientDNSClient(TestCase):
    def setUp(self):
        self.maxDiff = None
        logger = logging.getLogger()
        logger.disabled = True

        self.test_client = ansible_client.AnsibleClient()

    def test_run_dns_client_empty_node_lists_returns_exception(self):
        expected_exception = Exception('Node list is empty')

        try:
            returned_data = self.test_client.run_dns_client(1, '', '', [], '', '', '2.2.2.2')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_dns_client_empty_server_private_ip_returns_exception(self):
        expected_exception = Exception('server_private_ip is empty')

        try:
            returned_data = self.test_client.run_dns_client(1, '', '', ['1.1.1.1'], '', '', '2.2.2.2')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_dns_client_invalid_provider_returns_exception(self):
        expected_exception = Exception('provider parameter is invalid')

        try:
            returned_data = self.test_client.run_dns_client(1, '', '', ['1.1.1.1'], '192.0.0.0', 'invalidProvider', '2.2.2.2')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_dns_client_playbook_missing_returns_exception(self):
        expected_exception = Exception('Playbook does not exist')

        with patch('os.path.exists', new=func_returns_false):
            try:
                returned_data = self.test_client.run_dns_client(1, '', '', ['1.1.1.1'], '192.0.0.0', 'google', '2.2.2.2')
            except Exception as e:
                returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_dns_client_correct_google_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns_client/hosts.ini', '-e', '{"google_nodes": ["1.1.1.1","1.1.1.2"], "alicloud_nodes": [], "aws_nodes": [], "azure_nodes": [], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "google_server_private_ip": "192.0.0.0", "aws_server_private_ip": "", "azure_server_private_ip": "", "openstack_server_private_ip": "", "onpremise_server_private_ip": "", "iotarm_server_private_ip": "", "alicloud_server_private_ip": "", "ansible_python_interpreter": "/usr/bin/python3", "gateway_address": "2.2.2.2", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns_client/dns_client.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            try:
                returned_data = self.test_client.run_dns_client(1, '', '', ['1.1.1.1', '1.1.1.2'], '192.0.0.0', 'google', '2.2.2.2')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            self.assertEqual(mock.call_count, 1)
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)

    def test_run_dns_client_correct_aws_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns_client/hosts.ini', '-e', '{"google_nodes": [], "alicloud_nodes": [], "aws_nodes": ["1.1.1.1","1.1.1.2"], "azure_nodes": [], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "google_server_private_ip": "", "aws_server_private_ip": "192.0.0.0", "azure_server_private_ip": "", "openstack_server_private_ip": "", "onpremise_server_private_ip": "", "iotarm_server_private_ip": "", "alicloud_server_private_ip": "", "ansible_python_interpreter": "/usr/bin/python3", "gateway_address": "2.2.2.2", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns_client/dns_client.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            try:
                returned_data = self.test_client.run_dns_client(1, '', '', ['1.1.1.1', '1.1.1.2'], '192.0.0.0', 'aws', '2.2.2.2')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            self.assertEqual(mock.call_count, 1)
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)

    def test_run_dns_client_correct_azure_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns_client/hosts.ini', '-e', '{"google_nodes": [], "alicloud_nodes": [], "aws_nodes": [], "azure_nodes": ["1.1.1.1","1.1.1.2"], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "google_server_private_ip": "", "aws_server_private_ip": "", "azure_server_private_ip": "192.0.0.0", "openstack_server_private_ip": "", "onpremise_server_private_ip": "", "iotarm_server_private_ip": "", "alicloud_server_private_ip": "", "ansible_python_interpreter": "/usr/bin/python3", "gateway_address": "2.2.2.2", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns_client/dns_client.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            try:
                returned_data = self.test_client.run_dns_client(1, '', '', ['1.1.1.1', '1.1.1.2'], '192.0.0.0', 'azure', '2.2.2.2')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            self.assertEqual(mock.call_count, 1)
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)

    def test_run_dns_client_correct_alicloud_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns_client/hosts.ini', '-e', '{"google_nodes": [], "alicloud_nodes": ["1.1.1.1","1.1.1.2"], "aws_nodes": [], "azure_nodes": [], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "google_server_private_ip": "", "aws_server_private_ip": "", "azure_server_private_ip": "", "openstack_server_private_ip": "", "onpremise_server_private_ip": "", "iotarm_server_private_ip": "", "alicloud_server_private_ip": "192.0.0.0", "ansible_python_interpreter": "/usr/bin/python3", "gateway_address": "2.2.2.2", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/dns_client/dns_client.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            try:
                returned_data = self.test_client.run_dns_client(1, '', '', ['1.1.1.1', '1.1.1.2'], '192.0.0.0', 'alicloud', '2.2.2.2')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            self.assertEqual(mock.call_count, 1)
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)


# class AnsibleClientFixHostnames(TestCase):
#     def setUp(self):
#         self.maxDiff = None
#         logger = logging.getLogger()
#         logger.disabled = True
#         self.maxDiff = None

#         self.test_client = ansible_client.AnsibleClient()

#     def test_run_fix_hostnames_empty_node_lists_returns_exception(self):
#         expected_exception = Exception('Nodes list is empty')

#         try:
#             returned_data = self.test_client.run_fix_hostnames(1, '', '', [[], [], [], [], [], []], 'clusterName', '2.2.2.2', 'test.test')
#         except Exception as e:
#             returned_data = e

#         self.assertEqual(type(returned_data), type(expected_exception))
#         self.assertEqual(str(returned_data), str(expected_exception))

#     def test_run_fix_hostnames_playbook_missing_returns_exception(self):
#         expected_exception = Exception('Playbook does not exist')

#         with patch('os.path.exists', new=func_returns_false):
#             try:
#                 returned_data = self.test_client.run_fix_hostnames(1, '', '', {'provider': 'google', 'nodes': ['0.0.0.0']}, 'clusterName', '2.2.2.2', 'test.test')
#             except Exception as e:
#                 returned_data = e

#         self.assertEqual(type(returned_data), type(expected_exception))
#         self.assertEqual(str(returned_data), str(expected_exception))

#     def test_run_fix_hostnames_correct_google_only_returns_nothing(self):
#         expected_call_args = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/hosts.ini', '-e', '{"google_nodes": ["0.0.0.1","0.0.0.2"], "alicloud_nodes": [], "internal_dns_zone": test.test, "aws_nodes": [], "azure_nodes": [], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "clustername": "clusterName", "counter": 1, "gateway_address": "2.2.2.2", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/fix_hostnames.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

#         with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
#             mock.side_effect = func_no_return
#             try:
#                 returned_data = self.test_client.run_fix_hostnames(1, '', '', [['0.0.0.1','0.0.0.2'], [], [], [], [], []], 'clusterName', '2.2.2.2', 'test.test')
#             except Exception as e:
#                 returned_data = e

#             mock.assert_called()
#             self.assertEqual(mock.call_count, 1)
#             self.assertEqual(str(mock.call_args_list[0]), expected_call_args)

#     def test_run_fix_hostnames_correct_google_only_with_counter_returns_nothing(self):
#         expected_call_args = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/hosts.ini', '-e', '{"google_nodes": ["0.0.0.1","0.0.0.2"], "alicloud_nodes": [], "internal_dns_zone": test.test, "aws_nodes": [], "azure_nodes": [], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "clustername": "clusterName", "counter": 4, "gateway_address": "2.2.2.2", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/fix_hostnames.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

#         with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
#             mock.side_effect = func_no_return
#             try:
#                 returned_data = self.test_client.run_fix_hostnames(1, '', '', [['0.0.0.1','0.0.0.2'], [], [], [], [], []], 'clusterName', '2.2.2.2', 'test.test', 4)
#             except Exception as e:
#                 returned_data = e

#             mock.assert_called()
#             self.assertEqual(mock.call_count, 1)
#             self.assertEqual(str(mock.call_args_list[0]), expected_call_args)

#     def test_run_fix_hostnames_correct_aws_only_returns_nothing(self):
#         expected_call_args = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/hosts.ini', '-e', '{"google_nodes": [], "alicloud_nodes": [], "internal_dns_zone": test.test, "aws_nodes": ["0.0.0.1","0.0.0.2"], "azure_nodes": [], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "clustername": "clusterName", "counter": 1, "gateway_address": "2.2.2.2", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/fix_hostnames.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

#         with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
#             mock.side_effect = func_no_return
#             try:
#                 returned_data = self.test_client.run_fix_hostnames(1, '', '', [[], [],  ['0.0.0.1','0.0.0.2'], [], [], []], 'clusterName', '2.2.2.2', 'test.test')
#             except Exception as e:
#                 returned_data = e

#             mock.assert_called()
#             self.assertEqual(mock.call_count, 1)
#             self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
    
#     def test_run_fix_hostnames_correct_aws_only_with_counter_returns_nothing(self):
#         expected_call_args = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/hosts.ini', '-e', '{"google_nodes": [], "alicloud_nodes": [], "internal_dns_zone": test.test, "aws_nodes": ["0.0.0.1","0.0.0.2"], "azure_nodes": [], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "clustername": "clusterName", "counter": 4, "gateway_address": "2.2.2.2", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/fix_hostnames.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

#         with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
#             mock.side_effect = func_no_return
#             try:
#                 returned_data = self.test_client.run_fix_hostnames(1, '', '', [[], [],  ['0.0.0.1','0.0.0.2'], [], [], []], 'clusterName', '2.2.2.2', 'test.test', 4)
#             except Exception as e:
#                 returned_data = e

#             mock.assert_called()
#             self.assertEqual(mock.call_count, 1)
#             self.assertEqual(str(mock.call_args_list[0]), expected_call_args)

#     def test_run_fix_hostnames_correct_azure_only_returns_nothing(self):
#         expected_call_args = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/hosts.ini', '-e', '{"google_nodes": [], "alicloud_nodes": [], "internal_dns_zone": test.test, "aws_nodes": [], "azure_nodes": ["0.0.0.1","0.0.0.2"], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "clustername": "clusterName", "counter": 1, "gateway_address": "2.2.2.2", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/fix_hostnames.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

#         with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
#             mock.side_effect = func_no_return
#             try:
#                 returned_data = self.test_client.run_fix_hostnames(1, '', '', [[], [], [],  ['0.0.0.1','0.0.0.2'], [], []], 'clusterName', '2.2.2.2', 'test.test')
#             except Exception as e:
#                 returned_data = e

#             mock.assert_called()
#             self.assertEqual(mock.call_count, 1)
#             self.assertEqual(str(mock.call_args_list[0]), expected_call_args)
    
#     def test_run_fix_hostnames_correct_azure_only_with_counter_returns_nothing(self):
#         expected_call_args = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/hosts.ini', '-e', '{"google_nodes": [], "alicloud_nodes": [], "internal_dns_zone": test.test, "aws_nodes": [], "azure_nodes": ["0.0.0.1","0.0.0.2"], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "clustername": "clusterName", "counter": 4, "gateway_address": "2.2.2.2", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/fix_hostnames.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

#         with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
#             mock.side_effect = func_no_return
#             try:
#                 returned_data = self.test_client.run_fix_hostnames(1, '', '', [[], [], [],  ['0.0.0.1','0.0.0.2'], [], []], 'clusterName', '2.2.2.2', 'test.test', 4)
#             except Exception as e:
#                 returned_data = e

#             mock.assert_called()
#             self.assertEqual(mock.call_count, 1)
#             self.assertEqual(str(mock.call_args_list[0]), expected_call_args)

#     def test_run_fix_hostnames_correct_alicloud_only_returns_nothing(self):
#         expected_call_args = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/hosts.ini', '-e', '{"google_nodes": [], "alicloud_nodes": ["0.0.0.1","0.0.0.2"], "internal_dns_zone": test.test, "aws_nodes": [], "azure_nodes": [], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "clustername": "clusterName", "counter": 1, "gateway_address": "2.2.2.2", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/fix_hostnames.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

#         with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
#             mock.side_effect = func_no_return
#             try:
#                 returned_data = self.test_client.run_fix_hostnames(1, '', '', [[], ['0.0.0.1','0.0.0.2'], [],  [], [], []], 'clusterName', '2.2.2.2', 'test.test')
#             except Exception as e:
#                 returned_data = e

#             mock.assert_called()
#             self.assertEqual(mock.call_count, 1)
#             self.assertEqual(str(mock.call_args_list[0]), expected_call_args)

#     def test_run_fix_hostnames_correct_alicloud_only_with_counter_returns_nothing(self):
#         expected_call_args = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/hosts.ini', '-e', '{"google_nodes": [], "alicloud_nodes": ["0.0.0.1","0.0.0.2"], "internal_dns_zone": test.test, "aws_nodes": [], "azure_nodes": [], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "clustername": "clusterName", "counter": 4, "gateway_address": "2.2.2.2", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/fix_hostnames.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

#         with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
#             mock.side_effect = func_no_return
#             try:
#                 returned_data = self.test_client.run_fix_hostnames(1, '', '', [[], ['0.0.0.1','0.0.0.2'], [],  [], [], []], 'clusterName', '2.2.2.2', 'test.test', 4)
#             except Exception as e:
#                 returned_data = e

#             mock.assert_called()
#             self.assertEqual(mock.call_count, 1)
#             self.assertEqual(str(mock.call_args_list[0]), expected_call_args)

#     def test_run_fix_hostnames_correct_quadruple_cloud_returns_nothing(self):
#         expected_call_args = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/hosts.ini', '-e', '{"google_nodes": ["0.0.1.1","0.0.1.2"], "alicloud_nodes": ["0.0.3.1","0.0.3.2"], "internal_dns_zone": test.test, "aws_nodes": ["0.0.2.1","0.0.2.2"], "azure_nodes": ["0.0.0.1","0.0.0.2"], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "clustername": "clusterName", "counter": 1, "gateway_address": "2.2.2.2", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/fix_hostnames/fix_hostnames.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

#         with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
#             mock.side_effect = func_no_return
#             try:
#                 returned_data = self.test_client.run_fix_hostnames(1, '', '', [['0.0.1.1','0.0.1.2'], ['0.0.3.1','0.0.3.2'], ['0.0.2.1','0.0.2.2'], ['0.0.0.1','0.0.0.2'], [], []], 'clusterName', '2.2.2.2', 'test.test')
#             except Exception as e:
#                 returned_data = e

#             mock.assert_called()
#             self.assertEqual(mock.call_count, 1)
#             self.assertEqual(str(mock.call_args_list[0]), expected_call_args)


class AnsibleClientSecureNodes(TestCase):
    def setUp(self):
        self.maxDiff = None
        logger = logging.getLogger()
        logger.disabled = True
        self.maxDiff = None

        self.test_client = ansible_client.AnsibleClient()

    def test_run_secure_nodes_empty_node_lists_returns_exception(self):
        expected_exception = Exception('Invalid parameter providers_nodes')

        try:
            returned_data = self.test_client.run_secure_nodes(1, '', '', 'admin', 'admin', 'admin', 'admin', [], 'clusterName', '2.2.2.2', 'test.test')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_secure_nodes_playbook_missing_returns_exception(self):
        expected_exception = Exception('Playbook does not exist')

        with patch('os.path.exists', new=func_returns_false):
            try:
                returned_data = self.test_client.run_secure_nodes(1, '', '', 'admin', 'admin', 'admin', 'admin', {'google': ['0.0.0.0']}, 'clusterName', '2.2.2.2', 'test.test')
            except Exception as e:
                print(e)
                returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_secure_nodes_correct_google_only_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.0.1","0.0.0.2"], "dc_ip": "0.0.0.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.google.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/CA_scm_server.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        expected_call_args_2 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.0.1","0.0.0.2"], "dc_ip": "0.0.0.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.google.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/domain-controller.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        expected_call_args_3 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.0.1","0.0.0.2"], "dc_ip": "0.0.0.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.google.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/cluster-host.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            try:
                returned_data = self.test_client.run_secure_nodes(1, '', '', 'admin', 'admin', 'admin', 'admin', {'google': ['0.0.0.0','0.0.0.1','0.0.0.2']}, 'clusterName', '2.2.2.2', 'test.test')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            self.assertEqual(mock.call_count, 3)
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)
            self.assertEqual(str(mock.call_args_list[1]), expected_call_args_2)
            self.assertEqual(str(mock.call_args_list[2]), expected_call_args_3)

    def test_run_secure_nodes_correct_aws_only_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.0.1","0.0.0.2"], "dc_ip": "0.0.0.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.aws.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/CA_scm_server.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        expected_call_args_2 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.0.1","0.0.0.2"], "dc_ip": "0.0.0.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.aws.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/domain-controller.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        expected_call_args_3 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.0.1","0.0.0.2"], "dc_ip": "0.0.0.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.aws.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/cluster-host.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            try:
                returned_data = self.test_client.run_secure_nodes(1, '', '', 'admin', 'admin', 'admin', 'admin', {'aws': ['0.0.0.0','0.0.0.1','0.0.0.2']}, 'clusterName', '2.2.2.2', 'test.test')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            self.assertEqual(mock.call_count, 3)


            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)
            self.assertEqual(str(mock.call_args_list[1]), expected_call_args_2)
            self.assertEqual(str(mock.call_args_list[2]), expected_call_args_3)

    def test_run_secure_nodes_correct_azure_only_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.0.1","0.0.0.2"], "dc_ip": "0.0.0.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.azure.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/CA_scm_server.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        expected_call_args_2 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.0.1","0.0.0.2"], "dc_ip": "0.0.0.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.azure.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/domain-controller.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        expected_call_args_3 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.0.1","0.0.0.2"], "dc_ip": "0.0.0.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.azure.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/cluster-host.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            try:
                returned_data = self.test_client.run_secure_nodes(1, '', '', 'admin', 'admin', 'admin', 'admin', {'azure': ['0.0.0.0','0.0.0.1','0.0.0.2']}, 'clusterName', '2.2.2.2', 'test.test')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            self.assertEqual(mock.call_count, 3)
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)
            self.assertEqual(str(mock.call_args_list[1]), expected_call_args_2)
            self.assertEqual(str(mock.call_args_list[2]), expected_call_args_3)

    def test_run_secure_nodes_correct_alicloud_only_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.0.1","0.0.0.2"], "dc_ip": "0.0.0.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.alicloud.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/CA_scm_server.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        expected_call_args_2 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.0.1","0.0.0.2"], "dc_ip": "0.0.0.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.alicloud.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/domain-controller.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        expected_call_args_3 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.0.1","0.0.0.2"], "dc_ip": "0.0.0.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.alicloud.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/cluster-host.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            try:
                returned_data = self.test_client.run_secure_nodes(1, '', '', 'admin', 'admin', 'admin', 'admin', {'alicloud': ['0.0.0.0','0.0.0.1','0.0.0.2']}, 'clusterName', '2.2.2.2', 'test.test')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            self.assertEqual(mock.call_count, 3)

            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)
            self.assertEqual(str(mock.call_args_list[1]), expected_call_args_2)
            self.assertEqual(str(mock.call_args_list[2]), expected_call_args_3)

    def test_run_secure_nodes_correct_triple_cloud_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.1.1","0.0.1.2","0.0.2.0","0.0.2.1","0.0.2.2","0.0.0.0","0.0.0.1","0.0.0.2"], "dc_ip": "0.0.1.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.google.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/CA_scm_server.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        expected_call_args_2 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.1.1","0.0.1.2","0.0.2.0","0.0.2.1","0.0.2.2","0.0.0.0","0.0.0.1","0.0.0.2"], "dc_ip": "0.0.1.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.google.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/domain-controller.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        expected_call_args_3 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.1.1","0.0.1.2","0.0.2.0","0.0.2.1","0.0.2.2","0.0.0.0","0.0.0.1","0.0.0.2"], "dc_ip": "0.0.1.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.google.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/cluster-host.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            try:
                returned_data = self.test_client.run_secure_nodes(1, '', '', 'admin', 'admin', 'admin', 'admin', {'google': ['0.0.1.0','0.0.1.1','0.0.1.2'], 'aws': ['0.0.2.0','0.0.2.1','0.0.2.2'], 'azure': ['0.0.0.0','0.0.0.1','0.0.0.2']}, 'clusterName', '2.2.2.2', 'test.test')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            self.assertEqual(mock.call_count, 3)
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)
            self.assertEqual(str(mock.call_args_list[1]), expected_call_args_2)
            self.assertEqual(str(mock.call_args_list[2]), expected_call_args_3)

    def test_run_secure_nodes_correct_quadruple_cloud_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.1.1","0.0.1.2","0.0.3.0","0.0.3.1","0.0.3.2","0.0.2.0","0.0.2.1","0.0.2.2","0.0.0.0","0.0.0.1","0.0.0.2"], "dc_ip": "0.0.1.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.google.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/CA_scm_server.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        expected_call_args_2 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.1.1","0.0.1.2","0.0.3.0","0.0.3.1","0.0.3.2","0.0.2.0","0.0.2.1","0.0.2.2","0.0.0.0","0.0.0.1","0.0.0.2"], "dc_ip": "0.0.1.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.google.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/domain-controller.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''
        expected_call_args_3 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/hosts.ini', '-e', '{"nodes": ["0.0.1.1","0.0.1.2","0.0.3.0","0.0.3.1","0.0.3.2","0.0.2.0","0.0.2.1","0.0.2.2","0.0.0.0","0.0.0.1","0.0.0.2"], "dc_ip": "0.0.1.0", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "ca_password": "admin", "krb_admin_password": "admin", "gateway_address": "2.2.2.2", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "clusterName-node-01.google.test.test", "cluster_domain": "test.test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes/cluster-host.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            try:
                returned_data = self.test_client.run_secure_nodes(1, '', '', 'admin', 'admin', 'admin', 'admin', {'google': ['0.0.1.0','0.0.1.1','0.0.1.2'], 'alicloud': ['0.0.3.0','0.0.3.1','0.0.3.2'], 'aws': ['0.0.2.0','0.0.2.1','0.0.2.2'], 'azure': ['0.0.0.0','0.0.0.1','0.0.0.2']}, 'clusterName', '2.2.2.2', 'test.test')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            self.assertEqual(mock.call_count, 3)
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)
            self.assertEqual(str(mock.call_args_list[1]), expected_call_args_2)
            self.assertEqual(str(mock.call_args_list[2]), expected_call_args_3)


class AnsibleClientSecureNodesClient(TestCase):
    def setUp(self):
        self.maxDiff = None
        logger = logging.getLogger()
        logger.disabled = True
        self.maxDiff = None

        self.test_client = ansible_client.AnsibleClient()

    def test_run_secure_nodes_client_empty_node_lists_returns_exception(self):
        expected_exception = Exception('Nodes list is empty')

        try:
            returned_data = self.test_client.run_secure_nodes_client(1, '', '', 'admin', 'admin', 'admin', [], '', '', '2.2.2.2', 'test.test')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_secure_nodes_client_empty_dc_ip_returns_exception(self):
        expected_exception = Exception('dc_ip parameter is empty')

        try:
            returned_data = self.test_client.run_secure_nodes_client(1, '', '', 'admin', 'admin', 'admin', ['1.1.1.1', '1., 1.1.1.2'], '', '', '2.2.2.2', 'test.test')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))
    
    def test_run_secure_nodes_client_empty_dc_hostname_returns_exception(self):
        expected_exception = Exception('dc_hostname parameter is empty')

        try:
            returned_data = self.test_client.run_secure_nodes_client(1, '', '', 'admin', 'admin', 'admin', ['1.1.1.1', '1.1.1.2'], '0.0.0.1', '', '2.2.2.2', 'test.test')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_secure_nodes_client_playbook_missing_returns_exception(self):
        expected_exception = Exception('Playbook does not exist')

        with patch('os.path.exists', new=func_returns_false):
            try:
                returned_data = self.test_client.run_secure_nodes_client(1, '', '', 'admin', 'admin', 'admin', ['1.1.1.1', '1.1.1.2'], '0.0.0.1', 'dc_hostname', '2.2.2.2', 'test.test')
            except Exception as e:
                returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_secure_nodes_client_correct_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes_client/hosts.ini', '-e', '{"nodes": ["1.1.1.1","1.1.1.2"], "dc_ip": "0.0.0.1", "cluster_domain": "test.test", "krb_realm": "TEST.TEST", "ldap_base_dn": "dc=test,dc=test", "krb_admin_password": "admin", "kdc_master_password": "admin", "internal_dns_zone": "test.test", "ldap_admin_password": "admin", "dc_hostname": "dc_hostname", "gateway_address": "2.2.2.2", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/secure_nodes_client/distribute_CA.yml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            try:
                returned_data = self.test_client.run_secure_nodes_client(1, '', '', 'admin', 'admin', 'admin', ['1.1.1.1', '1.1.1.2'], '0.0.0.1', 'dc_hostname', '2.2.2.2', 'test.test')
            except Exception as e:
                print(e)
                returned_data = e

            mock.assert_called()
            self.assertEqual(mock.call_count, 2)
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)


class AnsibleClientAddClusterUser(TestCase):
    def setUp(self):
        self.maxDiff = None
        logger = logging.getLogger()
        logger.disabled = True

        self.test_client = ansible_client.AnsibleClient()

    def test_run_add_cluster_user_invalid_dc_ip_returns_exception(self):
        expected_exception = Exception('Invalid dc_ip')

        try:
            returned_data = self.test_client.run_add_cluster_user(1, '', '', 'admin', '', {}, '2.2.2.2', 'test.test')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_add_cluster_user_missing_cluster_user_username_returns_exception(self):
        expected_exception = Exception('cluster_user needs to have parameter: username')

        cluster_user = {
            'kubernetesUser': False,
            'user_password': 'pass',
            'firstName': 'firstName',
            'lastName': 'lastName',
            'type': 'type',
            'publicSSHKey': 'publicSSHKey',
            'email': 'email',
        }

        try:
            returned_data = self.test_client.run_add_cluster_user(1, '', '', 'admin', '0.0.0.0', cluster_user, '2.2.2.2', 'test.test')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_add_cluster_user_empty_cluster_user_username_returns_exception(self):
        expected_exception = Exception('cluster_user parameter: username needs to be set')

        cluster_user = {
            'kubernetesUser': False,
            'user_password': 'pass',
            'username': '',
            'firstName': 'firstName',
            'lastName': 'lastName',
            'type': 'type',
            'publicSSHKey': 'publicSSHKey',
            'email': 'email',
        }

        try:
            returned_data = self.test_client.run_add_cluster_user(1, '', '', 'admin', '0.0.0.0', cluster_user, '2.2.2.2', 'test.test')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_add_cluster_user_missing_cluster_user_type_returns_exception(self):
        expected_exception = Exception('cluster_user needs to have parameter: type')

        cluster_user = {
            'kubernetesUser': False,
            'user_password': 'pass',
            'username': 'username',
            'firstName': 'firstName',
            'lastName': 'lastName',
            'publicSSHKey': 'publicSSHKey',
            'email': 'email',
        }

        try:
            returned_data = self.test_client.run_add_cluster_user(1, '', '', 'admin', '0.0.0.0', cluster_user, '2.2.2.2', 'test.test')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_add_cluster_user_empty_cluster_user_type_returns_exception(self):
        expected_exception = Exception('cluster_user parameter: type needs to be set')

        cluster_user = {
            'kubernetesUser': False,
            'user_password': 'pass',
            'username': 'username',
            'firstName': 'firstName',
            'lastName': 'lastName',
            'type': '',
            'publicSSHKey': 'publicSSHKey',
            'email': 'email',
        }

        try:
            returned_data = self.test_client.run_add_cluster_user(1, '', '', 'admin', '0.0.0.0', cluster_user, '2.2.2.2', 'test.test')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_add_cluster_user_missing_cluster_user_publicSSHKey_returns_exception(self):
        expected_exception = Exception('cluster_user needs to have parameter: publicSSHKey')

        cluster_user = {
            'kubernetesUser': False,
            'user_password': 'pass',
            'username': 'username',
            'firstName': 'firstName',
            'lastName': 'lastName',
            'type': 'type',
            'email': 'email',
        }

        try:
            returned_data = self.test_client.run_add_cluster_user(1, '', '', 'admin', '0.0.0.0', cluster_user, '2.2.2.2', 'test.test')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_add_cluster_user_empty_cluster_user_publicSSHKey_returns_exception(self):
        expected_exception = Exception('cluster_user parameter: publicSSHKey needs to be set')

        cluster_user = {
            'kubernetesUser': False,
            'user_password': 'pass',
            'username': 'username',
            'firstName': 'firstName',
            'lastName': 'lastName',
            'type': 'type',
            'publicSSHKey': '',
            'email': 'email',
        }

        try:
            returned_data = self.test_client.run_add_cluster_user(1, '', '', 'admin', '0.0.0.0', cluster_user, '2.2.2.2', 'test.test')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_add_cluster_user_playbook_missing_returns_exception(self):
        expected_exception = Exception('Playbook does not exist')

        cluster_user = {
            'kubernetesUser': False,
            'user_password': 'pass',
            'username': 'username',
            'firstName': 'firstName',
            'lastName': 'lastName',
            'type': 'type',
            'publicSSHKey': 'publicSSHKey',
            'email': 'email'
        }

        with patch('os.path.exists', new=func_returns_false):
            try:
                returned_data = self.test_client.run_add_cluster_user(1, '', '', 'admin', '0.0.0.0', cluster_user, '2.2.2.2', 'test.test')
            except Exception as e:
                returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_add_cluster_user_correct_returns_nothing(self):
        expected_call_args = 'call([\'ansible-playbook\', \'-i\', \'' + FILE_BASE_DIR + '/ansible/playbooks/add_cluster_user/hosts.ini\','
        expected_call_args += ' \'-e\', \'{"first_name": "firstName", "dc_node": "0.0.0.0", "last_name": "lastName", "type": "type", '
        expected_call_args += '"publick_ssh_key": "publicSSHKey", "ldap_admin_password": "admin", "email": "email", '
        expected_call_args += '"username": "username", "ansible_python_interpreter": '
        expected_call_args += '"/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}\', \'-u\', \'clouduser\', '
        expected_call_args += '\'--ssh-extra-args="-o StrictHostKeyChecking=no"\', \'--timeout\', \'120\', '
        expected_call_args += '\'' + FILE_BASE_DIR + '/ansible/playbooks/add_cluster_user/add_cluster_user.yaml\'], return_stdout=True, raise_on_error=True, log_data={\'user_id\': 1, \'environment_id\': \'\', \'environment_name\': \'\'})'

        cluster_user = {
            'kubernetesUser': False,
            'user_password': 'pass',
            'username': 'username',
            'firstName': 'firstName',
            'lastName': 'lastName',
            'type': 'type',
            'publicSSHKey': 'publicSSHKey',
            'email': 'email',
        }

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            try:
                returned_data = self.test_client.run_add_cluster_user(1, '', '', 'admin', '0.0.0.0', cluster_user, '2.2.2.2', 'test.test')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            # self.assertEqual(str(mock.call_args_list[0]), expected_call_args)

class AnsibleClientDeleteClusterUser(TestCase):
    def setUp(self):
        self.maxDiff = None
        logger = logging.getLogger()
        logger.disabled = True

        self.test_client = ansible_client.AnsibleClient()

    def test_run_delete_cluster_user_invalid_dc_ip_returns_exception(self):
        expected_exception = Exception('Invalid dc_ip')

        try:
            returned_data = self.test_client.run_delete_cluster_user(1, '', '', 'admin', '', [], {}, False, '2.2.2.2', 'test')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_delete_cluster_user_invalid_cluster_user_username_returns_exception(self):
        expected_exception = Exception('Invalid cluster_user_username')

        try:
            returned_data = self.test_client.run_delete_cluster_user(1, '', '', 'admin', '0.0.0.0', [], '', False, '2.2.2.2', 'test')
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_delete_cluster_user_playbook_missing_returns_exception(self):
        expected_exception = Exception('Playbook does not exist')

        cluster_user = {
            'kubernetesUser': False,
            'user_password': 'pass',
            'firstName': 'firstName',
            'lastName': 'lastName'
        }

        with patch('os.path.exists', new=func_returns_false):
            try:
                returned_data = self.test_client.run_delete_cluster_user(1, '', '', 'admin', '0.0.0.0', [], cluster_user, False, '2.2.2.2', 'test')
            except Exception as e:
                returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_delete_cluster_user_correct_without_client_hosts_returns_nothing(self):
        expected_call_args = 'call([\'ansible-playbook\', \'-i\', \'.' + FILE_BASE_DIR + '/ansible/playbooks/delete_cluster_user/hosts.ini\','
        expected_call_args += ' \'-e\', \'{"username": "username", "dc_node": "0.0.0.0", '
        expected_call_args += '"ldap_admin_password": "admin", '
        expected_call_args += '"client_nodes": [], "ansible_python_interpreter": '
        expected_call_args += '"/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}\', \'-u\', \'clouduser\', '
        expected_call_args += '\'--ssh-extra-args="-o StrictHostKeyChecking=no"\', \'--timeout\', \'120\', '
        expected_call_args += '\'.' + FILE_BASE_DIR + '/ansible/playbooks/delete_cluster_user/delete_cluster_user.yaml\'], return_stdout=True, raise_on_error=True, log_data={\'user_id\': 1, \'environment_id\': \'\', \'environment_name\': \'\'})'

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            try:
                returned_data = self.test_client.run_delete_cluster_user(1, '', '', 'admin', '0.0.0.0', [], 'username', False, '2.2.2.2', 'test')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            # self.assertEqual(str(mock.call_args_list[0]), expected_call_args)

    def test_run_delete_cluster_user_correct_with_client_hosts_returns_nothing(self):
        expected_call_args = 'call([\'ansible-playbook\', \'-i\', \'.' + FILE_BASE_DIR + '/ansible/playbooks/delete_cluster_user/hosts.ini\','
        expected_call_args += ' \'-e\', \'{"username": "username", "dc_node": "0.0.0.0", '
        expected_call_args += '"ldap_admin_password": "admin", '
        expected_call_args += '"client_nodes": ["0.0.0.1","0.0.0.2"], "ansible_python_interpreter": '
        expected_call_args += '"/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}\', \'-u\', \'clouduser\', '
        expected_call_args += '\'--ssh-extra-args="-o StrictHostKeyChecking=no"\', \'--timeout\', \'120\', '
        expected_call_args += '\'.' + FILE_BASE_DIR + '/ansible/playbooks/delete_cluster_user/delete_cluster_user.yaml\'], return_stdout=True, raise_on_error=True, log_data={\'user_id\': 1, \'environment_id\': \'\', \'environment_name\': \'\'})'

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            try:
                returned_data = self.test_client.run_delete_cluster_user(1, '', '', 'admin', '0.0.0.0', [{'private_ip':'0.0.0.1'}, {'private_ip':'0.0.0.2'}], 'username', False, '2.2.2.2', 'test')
            except Exception as e:
                returned_data = e

            mock.assert_called()
            # self.assertEqual(str(mock.call_args_list[0]), expected_call_args)


# class AnsibleClientNodesLabels(TestCase):
#     def setUp(self):
#         self.maxDiff = None
#         logger = logging.getLogger()
#         logger.disabled = True

#         self.test_client = ansible_client.AnsibleClient()

#     def test_run_nodes_labels_invalid_input_arg_master_node_address_returns_exception(self):
#         expected_exception = Exception('Invalid parameter master_node_address')

#         master_node_address = ''
#         google_nodes = []
#         alicloud_nodes = []
#         aws_nodes = []
#         azure_nodes = []

#         try:
#             returned_data = self.test_client.run_nodes_labels(1, '', '',
#                     master_node_address, [], [], [], [], google_nodes, alicloud_nodes, aws_nodes, azure_nodes, [], [], '2.2.2.2'
#                 )
#         except Exception as e:
#             returned_data = e

#         self.assertEqual(type(returned_data), type(expected_exception))
#         self.assertEqual(str(returned_data), str(expected_exception))

#     def test_run_nodes_labels_empty_node_lists_returns_exception(self):
#         expected_exception = Exception('Nodes list is empty')

#         master_node_address = '1.1.1.1'
#         google_nodes = []
#         alicloud_nodes = []
#         aws_nodes = []
#         azure_nodes = []

#         try:
#             returned_data = self.test_client.run_nodes_labels(1, '', '',
#                     master_node_address, [], [], [], [], google_nodes, alicloud_nodes, aws_nodes, azure_nodes, [], [], '2.2.2.2'
#                 )
#         except Exception as e:
#             returned_data = e

#         self.assertEqual(type(returned_data), type(expected_exception))
#         self.assertEqual(str(returned_data), str(expected_exception))

#     def test_run_nodes_labels_user_playbook_missing_returns_exception(self):
#         expected_exception = Exception('Playbook does not exist')

#         master_node_address = '1.1.1.1'
#         google_nodes = ['0.0.0.1']
#         alicloud_nodes = []
#         aws_nodes = []
#         azure_nodes = []

#         with patch('os.path.exists', new=func_returns_false):
#             try:
#                 returned_data = self.test_client.run_nodes_labels(1, '', '',
#                     master_node_address, [], [], [], [], google_nodes, alicloud_nodes, aws_nodes, azure_nodes, [], [], '2.2.2.2'
#                 )
#             except Exception as e:
#                 returned_data = e

#         self.assertEqual(type(returned_data), type(expected_exception))
#         self.assertEqual(str(returned_data), str(expected_exception))

#     def test_run_nodes_labels_correct_google_only_returns_nothing(self):
#         expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/node_labels/hosts.ini', '-e', '{"alicloud_lb_nodes": [], "aws_lb_nodes": [], "google_lb_nodes": [], "azure_lb_nodes": [], "google_nodes": ["0.0.0.1","0.0.0.2"], "aws_nodes": [], "azure_nodes": [], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "alicloud_nodes": [], "masternode": "1.1.1.1", "ansible_python_interpreter": "/usr/bin/python3", "gateway_address": "2.2.2.2", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/node_labels/node_labels.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

#         master_node_address = '1.1.1.1'
#         google_nodes = ['0.0.0.1', '0.0.0.2']
#         alicloud_nodes = []
#         aws_nodes = []
#         azure_nodes = []
        
        

#         with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
#             mock.side_effect = func_no_return
#             try:
#                 returned_data = self.test_client.run_nodes_labels(1, '', '',
#                     master_node_address, [], [], [], [], google_nodes, alicloud_nodes, aws_nodes, azure_nodes, [], [], '2.2.2.2'
#                 )
#             except Exception as e:
#                 returned_data = e

#             mock.assert_called()
#             self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)

#     def test_run_nodes_labels_correct_aws_only_returns_nothing(self):
#         expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/node_labels/hosts.ini', '-e', '{"alicloud_lb_nodes": [], "aws_lb_nodes": [], "google_lb_nodes": [], "azure_lb_nodes": [], "google_nodes": [], "aws_nodes": ["0.0.0.1","0.0.0.2"], "azure_nodes": [], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "alicloud_nodes": [], "masternode": "1.1.1.1", "ansible_python_interpreter": "/usr/bin/python3", "gateway_address": "2.2.2.2", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/node_labels/node_labels.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

#         master_node_address = '1.1.1.1'
#         google_nodes = []
#         alicloud_nodes = []
#         aws_nodes = ['0.0.0.1', '0.0.0.2']
#         azure_nodes = []

#         with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
#             mock.side_effect = func_no_return
#             try:
#                 returned_data = self.test_client.run_nodes_labels(1, '', '',
#                     master_node_address, [], [], [], [], google_nodes, alicloud_nodes, aws_nodes, azure_nodes, [], [], '2.2.2.2'
#                 )
#             except Exception as e:
#                 returned_data = e

#             mock.assert_called()
#             self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)

#     def test_run_nodes_labels_correct_azure_only_returns_nothing(self):
#         expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/node_labels/hosts.ini', '-e', '{"alicloud_lb_nodes": [], "aws_lb_nodes": [], "google_lb_nodes": [], "azure_lb_nodes": [], "google_nodes": [], "aws_nodes": [], "azure_nodes": ["0.0.0.1","0.0.0.2"], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "alicloud_nodes": [], "masternode": "1.1.1.1", "ansible_python_interpreter": "/usr/bin/python3", "gateway_address": "2.2.2.2", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/node_labels/node_labels.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

#         master_node_address = '1.1.1.1'
#         google_nodes = []
#         alicloud_nodes = []
#         aws_nodes = []
#         azure_nodes = ['0.0.0.1', '0.0.0.2']

#         with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
#             mock.side_effect = func_no_return
#             try:
#                 returned_data = self.test_client.run_nodes_labels(1, '', '',
#                     master_node_address, [], [], [], [], google_nodes, alicloud_nodes, aws_nodes, azure_nodes, [], [], '2.2.2.2'
#                 )
#             except Exception as e:
#                 returned_data = e

#             mock.assert_called()
#             self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)

#     def test_run_nodes_labels_correct_alicloud_only_returns_nothing(self):
#         expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/node_labels/hosts.ini', '-e', '{"alicloud_lb_nodes": [], "aws_lb_nodes": [], "google_lb_nodes": [], "azure_lb_nodes": [], "google_nodes": [], "aws_nodes": [], "azure_nodes": [], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "alicloud_nodes": ["0.0.0.1","0.0.0.2"], "masternode": "1.1.1.1", "ansible_python_interpreter": "/usr/bin/python3", "gateway_address": "2.2.2.2", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/node_labels/node_labels.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

#         master_node_address = '1.1.1.1'
#         google_nodes = []
#         alicloud_nodes = ['0.0.0.1', '0.0.0.2']
#         aws_nodes = []
#         azure_nodes = []

#         with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
#             mock.side_effect = func_no_return
#             try:
#                 returned_data = self.test_client.run_nodes_labels(1, '', '',
#                     master_node_address, [], [], [], [], google_nodes, alicloud_nodes, aws_nodes, azure_nodes, [], [], '2.2.2.2'
#                 )
#             except Exception as e:
#                 print(e)
#                 returned_data = e

#             mock.assert_called()
#             self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)

#     def test_run_nodes_labels_correct_quadruple_cloud_returns_nothing(self):
#         expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/node_labels/hosts.ini', '-e', '{"alicloud_lb_nodes": [], "aws_lb_nodes": [], "google_lb_nodes": [], "azure_lb_nodes": [], "google_nodes": ["0.0.0.1","0.0.0.2"], "aws_nodes": ["0.0.0.5","0.0.0.6"], "azure_nodes": ["0.0.0.7","0.0.0.8"], "openstack_nodes": [], "onpremise_nodes": [], "iotarm_nodes": [], "alicloud_nodes": ["0.0.0.3","0.0.0.4"], "masternode": "1.1.1.1", "ansible_python_interpreter": "/usr/bin/python3", "gateway_address": "2.2.2.2", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/node_labels/node_labels.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})'''

#         master_node_address = '1.1.1.1'
#         google_nodes = ['0.0.0.1', '0.0.0.2']
#         alicloud_nodes = ['0.0.0.3', '0.0.0.4']
#         aws_nodes = ['0.0.0.5', '0.0.0.6']
#         azure_nodes = ['0.0.0.7', '0.0.0.8']

#         with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
#             mock.side_effect = func_no_return
#             try:
#                 returned_data = self.test_client.run_nodes_labels(1, '', '',
#                     master_node_address, [], [], [], [], google_nodes, alicloud_nodes, aws_nodes, azure_nodes, [], [], '2.2.2.2'
#                 )
#             except Exception as e:
#                 returned_data = e

#             mock.assert_called()
#             self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)


class AnsibleClientAddElkSecrets(TestCase):
    def setUp(self):
        self.maxDiff = None
        logger = logging.getLogger()
        logger.disabled = True

        self.test_client = ansible_client.AnsibleClient()

    def test_run_add_elk_secrets_invalid_input_arg_user_id_returns_exception(self):
        expected_exception = Exception('Invalid parameter user_id')

        user_id = ''
        environment_id = 'environment_id'
        environment_name = 'environment_name'
        dc_node = '1.1.1.1'
        namespace = 'namespace'
        elastic_password = 'elastic_password'
        dns_name = 'dns_name'

        try:
            returned_data = self.test_client.run_add_elk_secrets(
                user_id, environment_id, environment_name, dc_node, namespace, elastic_password, dns_name
                )
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_add_elk_secrets_input_arg_environment_id_returns_exception(self):
        expected_exception = Exception('Invalid parameter environment_id')

        user_id = 'user_id'
        environment_id = ''
        environment_name = 'environment_name'
        dc_node = '1.1.1.1'
        namespace = 'namespace'
        elastic_password = 'elastic_password'
        dns_name = 'dns_name'

        try:
            returned_data = self.test_client.run_add_elk_secrets(
                user_id, environment_id, environment_name, dc_node, namespace, elastic_password, dns_name
                )
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))
    
    def test_run_add_elk_secrets_input_arg_environment_name_returns_exception(self):
        expected_exception = Exception('Invalid parameter environment_name')

        user_id = 'user_id'
        environment_id = 'environment_id'
        environment_name = ''
        dc_node = '1.1.1.1'
        namespace = 'namespace'
        elastic_password = 'elastic_password'
        dns_name = 'dns_name'

        try:
            returned_data = self.test_client.run_add_elk_secrets(
                user_id, environment_id, environment_name, dc_node, namespace, elastic_password, dns_name
                )
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_add_elk_secrets_input_arg_dc_node_returns_exception(self):
        expected_exception = Exception('Invalid parameter dc_node')

        user_id = 'user_id'
        environment_id = 'environment_id'
        environment_name = 'environment_name'
        dc_node = ''
        namespace = 'namespace'
        elastic_password = 'elastic_password'
        dns_name = 'dns_name'

        try:
            returned_data = self.test_client.run_add_elk_secrets(
                user_id, environment_id, environment_name, dc_node, namespace, elastic_password, dns_name
                )
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_add_elk_secrets_input_arg_namespace_returns_exception(self):
        expected_exception = Exception('Invalid parameter namespace')

        user_id = 'user_id'
        environment_id = 'environment_id'
        environment_name = 'environment_name'
        dc_node = 'dc_node'
        namespace = ''
        elastic_password = 'elastic_password'
        dns_name = 'dns_name'

        try:
            returned_data = self.test_client.run_add_elk_secrets(
                user_id, environment_id, environment_name, dc_node, namespace, elastic_password, dns_name
                )
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_add_elk_secrets_input_arg_elastic_password_returns_exception(self):
        expected_exception = Exception('Invalid parameter elastic_password')

        user_id = 'user_id'
        environment_id = 'environment_id'
        environment_name = 'environment_name'
        dc_node = 'dc_node'
        namespace = 'namespace'
        elastic_password = ''
        dns_name = 'dns_name'

        try:
            returned_data = self.test_client.run_add_elk_secrets(
                user_id, environment_id, environment_name, dc_node, namespace, elastic_password, dns_name
                )
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_add_elk_secrets_input_arg_dns_name_returns_exception(self):
        expected_exception = Exception('Invalid parameter dns_name')

        user_id = 'user_id'
        environment_id = 'environment_id'
        environment_name = 'environment_name'
        dc_node = 'dc_node'
        namespace = 'namespace'
        elastic_password = 'elastic_password'
        dns_name = ''

        try:
            returned_data = self.test_client.run_add_elk_secrets(
                user_id, environment_id, environment_name, dc_node, namespace, elastic_password, dns_name
                )
        except Exception as e:
            returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_add_elk_secrets_user_playbook_missing_returns_exception(self):
        expected_exception = Exception('Playbook does not exist')

        user_id = 'user_id'
        environment_id = 'environment_id'
        environment_name = 'environment_name'
        dc_node = '1.1.1.1'
        namespace = 'namespace'
        elastic_password = 'elastic_password'
        dns_name = 'dns_name'

        with patch('os.path.exists', new=func_returns_false):
            try:
                returned_data = self.test_client.run_add_elk_secrets(
                user_id, environment_id, environment_name, dc_node, namespace, elastic_password, dns_name
                )
            except Exception as e:
                returned_data = e

        self.assertEqual(type(returned_data), type(expected_exception))
        self.assertEqual(str(returned_data), str(expected_exception))

    def test_run_add_elk_secrets_correct_returns_nothing(self):
        expected_call_args_1 = '''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/add_elk_secrets/hosts.ini', '-e', '{"dc_node": "1.1.1.1", "namespace": "namespace", "elastic_password": "elastic_password", "dns_name": "dns_name", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/add_elk_secrets/add_elk_secrets.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 'user_id', 'environment_id': 'environment_id', 'environment_name': 'environment_name'})'''

        user_id = 'user_id'
        environment_id = 'environment_id'
        environment_name = 'environment_name'
        dc_node = '1.1.1.1'
        namespace = 'namespace'
        elastic_password = 'elastic_password'
        dns_name = 'dns_name'

        with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
            mock.side_effect = func_no_return
            try:
                returned_data = self.test_client.run_add_elk_secrets(
                    user_id, environment_id, environment_name, dc_node, namespace, elastic_password, dns_name
                )
            except Exception as e:
                returned_data = e
                print('\nn\n\n\\n\n\n\n\n\n\nn\n\n\n')
                print(str(e))

            mock.assert_called()
            self.assertEqual(str(mock.call_args_list[0]), expected_call_args_1)


# class AnsibleClientAwsLoadbalancer(TestCase):
#     def setUp(self):
#         self.maxDiff = None
#         logger = logging.getLogger()
#         logger.disabled = True

#         self.test_client = ansible_client.AnsibleClient()

#     def test_run_aws_loadbalancer_invalid_input_arg_key_id_returns_exception(self):
#         expected_exception = Exception('Invalid parameter key_id')

#         key_id = ''
#         key_secret = 'test'
#         region = 'test'
#         nodes = 'test'
#         master_node_address = 'test'


#         try:
#             returned_data = kubernetes_loadbalancer_integration(1, '', '', 
#                 key_id=key_id,
#                 key_secret=key_secret,
#                 nodes=nodes,
#                 master_node_address=master_node_address,
#                 gateway_address='2.2.2.2' 
#             )
#         except Exception as e:
#             print(e)
#             returned_data = e

#         self.assertEqual(type(returned_data), type(expected_exception))
#         self.assertEqual(str(returned_data), str(expected_exception))


#     def test_run_aws_loadbalancer_invalid_input_arg_key_secret_returns_exception(self):
#         expected_exception = Exception('Invalid parameter key_secret')

#         key_id = 'test'
#         key_secret = ''
#         region = 'test'
#         nodes = 'test'
#         master_node_address = 'test'

#         try:
#             returned_data = self.test_client.run_aws_loadbalancer(1, '', '', 
#                 key_id=key_id,
#                 key_secret=key_secret,
#                 nodes=nodes,
#                 master_node_address=master_node_address,
#                 gateway_address='2.2.2.2' 
#             )
#         except Exception as e:
#             returned_data = e

#         self.assertEqual(type(returned_data), type(expected_exception))
#         self.assertEqual(str(returned_data), str(expected_exception))

#     def test_run_aws_loadbalancer_invalid_input_arg_nodes_returns_exception(self):
#         expected_exception = Exception('Invalid parameter nodes')

#         key_id = 'test'
#         key_secret = 'test'
#         region = 'test'
#         nodes = ''
#         master_node_address = 'test'

#         try:
#             returned_data = self.test_client.run_aws_loadbalancer(1, '', '', 
#                 key_id=key_id,
#                 key_secret=key_secret,
#                 nodes=nodes,
#                 master_node_address=master_node_address,
#                 gateway_address='2.2.2.2' 
#             )
#         except Exception as e:
#             returned_data = e

#         self.assertEqual(type(returned_data), type(expected_exception))
#         self.assertEqual(str(returned_data), str(expected_exception))


#     def test_run_aws_loadbalancer_invalid_input_arg_master_node_address_returns_exception(self):
#         expected_exception = Exception('Invalid parameter master_node_address')

#         key_id = 'test'
#         key_secret = 'test'
#         region = 'test'
#         nodes = 'test'
#         master_node_address = ''

#         try:
#             returned_data = self.test_client.run_aws_loadbalancer(1, '', '', 
#                 key_id=key_id,
#                 key_secret=key_secret,
#                 nodes=nodes,
#                 master_node_address=master_node_address,
#                 gateway_address='2.2.2.2' 
#             )
#         except Exception as e:
#             returned_data = e

#         self.assertEqual(type(returned_data), type(expected_exception))
#         self.assertEqual(str(returned_data), str(expected_exception))


#     def test_run_aws_loadbalancer_user_playbook_missing_returns_exception(self):
#         expected_exception = Exception('Playbook does not exist')

#         key_id = 'test'
#         key_secret = 'test'
#         region = 'test'
#         nodes = 'test'
#         master_node_address = 'test'

#         with patch('os.path.exists', new=func_returns_false):
#             try:
#                 returned_data = kubernetes_loadbalancer_integration(
#                 resources='{}',
#                 user_id=1,
#                 clouds={'gooogle': {}},
#                 master_ip='3.3.3.3',
#                 gateway_address='2.2.2.2',
#                 cluster_id=1
#             )
#             except Exception as e:
#                 returned_data = e

#         self.assertEqual(type(returned_data), type(expected_exception))
#         self.assertEqual(str(returned_data), str(expected_exception))

#     def test_run_aws_loadbalancer_user_correct_without_client_hosts_returns_nothing(self):
#         self.maxDiff = None
#         expected_call_args = ('''call(['ansible-playbook', '-i', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/aws_integration/loadbalancer/hosts.ini', '-e', '{"keyid": "test", "keysecret": "test", "nodes": "test", "gateway_address": "2.2.2.2", "master_node_address": "test", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}', '-u', 'clouduser', '--timeout', '120', \'''' + FILE_BASE_DIR + '''/ansible/playbooks/aws_integration/loadbalancer/loadbalancer.yaml'], return_stdout=True, raise_on_error=True, log_data={'user_id': 1, 'environment_id': '', 'environment_name': ''})''')

#         key_id = 'test'
#         key_secret = 'test'
#         region = 'test'
#         nodes = 'test'
#         master_node_address = 'test'

#         with patch.object(run_shell, 'run_shell_with_subprocess_popen') as mock:
#             mock.side_effect = func_no_return
#             try:
#                 returned_data = self.test_client.run_aws_loadbalancer(1, '', '', 
#                 key_id=key_id,
#                 key_secret=key_secret,
#                 nodes=nodes,
#                 master_node_address=master_node_address,
#                 gateway_address='2.2.2.2' 
#             )
#             except Exception as e:
#                 returned_data = e

#             mock.assert_called()
#             self.assertEqual(str(mock.call_args_list[0]), expected_call_args)

