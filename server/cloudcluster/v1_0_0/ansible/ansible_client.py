import yaml
from cloudcluster.models import Clusters, CapiCluster, YaookCapiCluster
import os

from cloudcluster.settings import YAOOKCAPI_MANAGEMENT_CLUSTER_KUBECONFIG_PATH

from ..services import run_shell
import json
import pathlib

FILE_BASE_DIR = str(pathlib.Path(__file__).parent.absolute())

class AnsibleClient:
    def run_playbook(self, user_id, environment_id, environment_name, inventory_path, playbook_path, extra_vars='', user='clouduser', become=False, extra_cmd=[]):
        cmd = [
            'ansible-playbook',
            '-i', inventory_path,
            '-e', extra_vars,
            '-u', user,
            '--timeout', '300'
        ]

        cmd += extra_cmd

        if become:
            cmd.append('-b')
            cmd.append('--become-user=root')
            cmd.append('--become-method=sudo',)

        cmd.append(playbook_path)

        log_data = {'user_id': user_id, 'environment_id': environment_id, 'environment_name': environment_name}

        print('Running playbook: ' + playbook_path)

        run_shell.run_shell_with_subprocess_popen(cmd, return_stdout=True, raise_on_error=True, log_data=log_data)

    def run_prepare_kubespray(self, user_id, environment_id, environment_name, kubespray_inventory_dir_name, kubernetes_configuration):
        if 'version' not in kubernetes_configuration:
            raise Exception('missing parameter kubernetes_configuration')
        if 'serviceAddresses' not in kubernetes_configuration:
            raise Exception('missing parameter serviceAddresses')
        if 'podsSubnet' not in kubernetes_configuration:
            raise Exception('missing parameter podsSubnet')
        if 'networkPlugin' not in kubernetes_configuration:
            raise Exception('missing parameter networkPlugin')

        playbook_path = FILE_BASE_DIR + '/playbooks/prepare_kubespray/prepare_inventory.yaml'
        inventory_path = FILE_BASE_DIR + '/playbooks/prepare_kubespray/hosts.ini'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "inventory_directory_name": kubespray_inventory_dir_name,
            "kube_version": kubernetes_configuration['version'],
            "kube_service_addresses": kubernetes_configuration['serviceAddresses'],
            "kube_pods_subnet": kubernetes_configuration['podsSubnet'],
            "kube_network_plugin": kubernetes_configuration['networkPlugin'],
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_kubeflow(self, user_id, environment_id, environment_name, name, dc_node, delete):
        if not name:
            raise Exception('Invalid parameter name')
        if not dc_node:
            raise Exception('Invalid parameter dc_node')

        inventory_path = FILE_BASE_DIR + '/playbooks/kubeflow/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/kubeflow/kubeflow.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "dc_node": dc_node,
            "name": name,
            "delete": delete,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_prepare_nodes(self, user_id, environment_id, environment_name, node_ips, gateway_address, v2=False):
        if node_ips == []:
            raise Exception('node_ips is empty')
        if gateway_address == []:
            raise Exception('gateway_address is empty')

        if v2:
            playbook_path = FILE_BASE_DIR + '/playbooks/dlcm_v2_prepare_nodes/prepare_nodes.yaml'
            inventory_path = FILE_BASE_DIR + '/playbooks/dlcm_v2_prepare_nodes/hosts.ini'
        else:
            playbook_path = FILE_BASE_DIR + '/playbooks/prepare_nodes/prepare_nodes.yaml'
            inventory_path = FILE_BASE_DIR + '/playbooks/prepare_nodes/hosts.ini'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        whitelist_ips = ''
        nodes_private_ips = ''

        for node_ip in node_ips:
            whitelist_ips += node_ip + ','
            nodes_private_ips += '"' + 'clouduser' + '@' + node_ip + '"' + ','

        whitelist_ips = whitelist_ips[:-1]
        nodes_private_ips = nodes_private_ips[:-1]


        extra_vars = '{"whitelist_ips": "' + whitelist_ips + '", "nodes_public_ips": [' + nodes_private_ips + '], "gateway_address": "' + gateway_address + '", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}'

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars, become=True)

    def run_upgrade_kubespray(self, user_id, environment_id, environment_name, gateway_address, kubespray_inventory_dir_name):
        if kubespray_inventory_dir_name == '':
            raise Exception('kubespray_inventory_dir_name is empty')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        playbook_path = FILE_BASE_DIR + '/playbooks/kubespray/cluster.yml'
        inventory_path = FILE_BASE_DIR + '/playbooks/kubespray/inventory/' + kubespray_inventory_dir_name + '/inventory.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "gateway_address": gateway_address,
            "upgrade_cluster_setup": "true",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, user='clouduser', become=True, extra_vars=extra_vars)

    def run_fix_scale_inventory(self, user_id, environment_id, environment_name, kubespray_inventory_dir_name, node_name):
        if kubespray_inventory_dir_name == '':
            raise Exception('kubespray_inventory_dir_name is empty')
        if node_name == '':
            raise Exception('Invalid parameter node_name')

        playbook_path = FILE_BASE_DIR + '/playbooks/fix_scale_inventory/fix_scale_inventory.yaml'
        inventory_path = FILE_BASE_DIR + '/playbooks/fix_scale_inventory/hosts.ini'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "inventory_directory_name": kubespray_inventory_dir_name,
            "node_name": node_name,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_refresh_kubespray_facts_cache(self, user_id, environment_id, environment_name, gateway_address, kubespray_inventory_dir_name):
        if kubespray_inventory_dir_name == '':
            raise Exception('kubespray_inventory_dir_name is empty')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        playbook_path = FILE_BASE_DIR + '/playbooks/kubespray/facts.yml'
        inventory_path = FILE_BASE_DIR + '/playbooks/kubespray/inventory/' + kubespray_inventory_dir_name + '/inventory.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "gateway_address": gateway_address,
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, user='clouduser', become=True, extra_vars=extra_vars)

    def run_add_kubespray_nodes(self, user_id, environment_id, environment_name, gateway_address, kubespray_inventory_dir_name, node_name):
        if kubespray_inventory_dir_name == '':
            raise Exception('kubespray_inventory_dir_name is empty')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')
        if not node_name:
            raise Exception('Invalid parameter node_name')

        playbook_path = FILE_BASE_DIR + '/playbooks/kubespray/scale.yml'
        inventory_path = FILE_BASE_DIR + '/playbooks/kubespray/inventory/' + kubespray_inventory_dir_name + '/inventory.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "gateway_address": gateway_address,
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa",
            "ignore_assert_errors": "true"
        })

        extra_cmd = ['--limit=' + node_name]

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, user='clouduser', become=True, extra_vars=extra_vars, extra_cmd=extra_cmd)

    def run_kubespray(self, user_id, environment_id, environment_name, gateway_address, kubespray_inventory_dir_name):
        if kubespray_inventory_dir_name == '':
            raise Exception('kubespray_inventory_dir_name is empty')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        playbook_path = FILE_BASE_DIR + '/playbooks/kubespray/cluster.yml'
        inventory_path = FILE_BASE_DIR + '/playbooks/kubespray/inventory/' + kubespray_inventory_dir_name + '/inventory.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "gateway_address": gateway_address,
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, user='clouduser', become=True, extra_vars=extra_vars)

    def run_dns(self, user_id, environment_id, environment_name, nodes_ips, dns_servers, gateway_address, dns_servers_ips, internal_dns_zone, provider_name, dns_server_nodes_addresses=[], v2=False):
        if provider_name + '_nodes' not in nodes_ips:
            raise Exception('Nodes list is empty')
        if provider_name + '_nodes' in nodes_ips and provider_name + '_server_private_ip' not in nodes_ips:
            raise Exception(provider_name + '_server_private_ip is empty')

        if gateway_address == []:
            raise Exception('gateway_address is empty')

        if v2:
            playbook_path = FILE_BASE_DIR + '/playbooks/dlcm_v2_dns/dns.yaml'
            inventory_path = FILE_BASE_DIR + '/playbooks/dlcm_v2_dns/hosts.ini'
        else:
            playbook_path = FILE_BASE_DIR + '/playbooks/dns/dns.yaml'
            inventory_path = FILE_BASE_DIR + '/playbooks/dns/hosts.ini'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({"dns_servers": dns_servers,
                                 "provider_nodes": nodes_ips[provider_name + '_nodes'],
                                 "dns_server_nodes_addresses": dns_server_nodes_addresses,
                                 "provider_server_ip": dns_servers_ips[provider_name + '_server_ip'],
                                 "provider_server_private_ip": nodes_ips[provider_name + '_server_private_ip'],
                                 "internal_dns_zone": internal_dns_zone,
                                 "gateway_address": gateway_address,
                                 "ansible_python_interpreter": "/usr/bin/python3",
                                 "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
                                 })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_add_dns_address(self, user_id, environment_id, environment_name, new_nodes, dns_server_address, gateway_address):
        if not new_nodes:
            raise Exception('Invalid parameter new_nodes')
        if not dns_server_address:
            raise Exception('Invalid parameter dns_server_address')

        inventory_path = FILE_BASE_DIR + '/playbooks/add_dns_address/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/add_dns_address/playbook.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')
        extra_vars = json.dumps({
            "new_nodes": new_nodes,
            "dns_server_address": dns_server_address,
            "gateway_address": gateway_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_dns_client(self, user_id, environment_id, environment_name, nodes, server_private_ip, provider, gateway_address):
        if nodes == []:
            raise Exception('Node list is empty')

        if server_private_ip == '':
            raise Exception('server_private_ip is empty')

        if provider not in ['google', 'aws', 'azure', 'alicloud', 'openstack', 'onpremise', 'iotarm']:
            raise Exception('provider parameter is invalid')

        if gateway_address == []:
            raise Exception('gateway_address is empty')

        playbook_path = FILE_BASE_DIR + '/playbooks/dns_client/dns_client.yaml'
        inventory_path = FILE_BASE_DIR + '/playbooks/dns_client/hosts.ini'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        nodes_var = ''

        for node in nodes:
            nodes_var += '"' + node + '"' + ','
        nodes_var = nodes_var[:-1]

        google_nodes_var = ''
        alicloud_nodes_var = ''
        aws_nodes_var = ''
        azure_nodes_var = ''
        openstack_nodes_var = ''
        onpremise_nodes_var = ''
        iotarm_nodes_var = ''

        google_server_private_ip = ''
        aws_server_private_ip = ''
        azure_server_private_ip = ''
        openstack_server_private_ip = ''
        onpremise_server_private_ip = ''
        iotarm_server_private_ip = ''
        alicloud_server_private_ip = ''

        if provider == 'google':
            google_server_private_ip = server_private_ip
            google_nodes_var = nodes_var
        elif provider == 'aws':
            aws_server_private_ip = server_private_ip
            aws_nodes_var = nodes_var
        elif provider == 'azure':
            azure_server_private_ip = server_private_ip
            azure_nodes_var = nodes_var
        elif provider == 'openstack':
            openstack_server_private_ip = server_private_ip
            openstack_nodes_var = nodes_var
        elif provider == 'onpremise':
            onpremise_server_private_ip = server_private_ip
            onpremise_nodes_var = nodes_var
        elif provider == 'iotarm':
            iotarm_server_private_ip = server_private_ip
            iotarm_nodes_var = nodes_var
        elif provider == 'alicloud':
            alicloud_server_private_ip = server_private_ip
            alicloud_nodes_var = nodes_var

        extra_vars = '{"google_nodes": [' + google_nodes_var + '], "alicloud_nodes": [' + alicloud_nodes_var + '], "aws_nodes": [' + aws_nodes_var + '], "azure_nodes": [' + azure_nodes_var + '], "openstack_nodes": [' + openstack_nodes_var + '], "onpremise_nodes": [' + onpremise_nodes_var + '], "iotarm_nodes": [' + iotarm_nodes_var + '], '
        extra_vars += '"google_server_private_ip": "' + google_server_private_ip + '", "aws_server_private_ip": "' + aws_server_private_ip
        extra_vars += '", "azure_server_private_ip": "' + azure_server_private_ip + '", "openstack_server_private_ip": "' + openstack_server_private_ip + '", "onpremise_server_private_ip": "' + onpremise_server_private_ip + '", "iotarm_server_private_ip": "' + iotarm_server_private_ip + '", "alicloud_server_private_ip": "' + alicloud_server_private_ip + '", '
        extra_vars += '"ansible_python_interpreter": "/usr/bin/python3", "gateway_address": "' + gateway_address + '", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}'

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_fix_hostnames(self, user_id, environment_id, environment_name, provider, clustername, gateway_address, internal_dns_zone, nodes_counter=1, v2=False):
        if 'nodes' not in provider or 'provider' not in provider:
            raise Exception('Invalid parameter provider')
        if gateway_address == []:
            raise Exception('gateway_address is empty')

        if v2:
            inventory_path = FILE_BASE_DIR + '/playbooks/dlcm_v2_fix_hostnames/hosts.ini'
            playbook_path = FILE_BASE_DIR + '/playbooks/dlcm_v2_fix_hostnames/fix_hostnames.yaml'
        else:
            inventory_path = FILE_BASE_DIR + '/playbooks/fix_hostnames/hosts.ini'
            playbook_path = FILE_BASE_DIR + '/playbooks/fix_hostnames/fix_hostnames.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        provider_nodes_var = ''

        if provider['nodes'] != []:
            for i in range(len(provider['nodes'])):
                provider_nodes_var += '"' + provider['nodes'][i] + '"' + ','
            provider_nodes_var = provider_nodes_var[:-1]

        extra_vars = '{"provider_nodes": [' + provider_nodes_var + '], "provider": ' + provider['provider']  + ','
        extra_vars += '"internal_dns_zone": ' + internal_dns_zone + ','
        extra_vars += ' "clustername": "' + clustername + '", "counter": ' + str(nodes_counter) + ', "gateway_address": "' + gateway_address + '", '
        extra_vars += '"ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}'

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_secure_nodes(self, user_id, environment_id, environment_name, krb_admin_password, kdc_master_password, ldap_admin_password, ca_password, providers_nodes, clustername, gateway_address, internal_dns_zone):

        if not providers_nodes:
            raise Exception('Invalid parameter providers_nodes')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')
        if not krb_admin_password:
            raise Exception('Invalid parameter krb_admin_password')
        if not kdc_master_password:
            raise Exception('Invalid parameter kdc_master_password')
        if not ldap_admin_password:
            raise Exception('Invalid parameter ldap_admin_password')
        if not ca_password:
            raise Exception('Invalid parameter ca_password')

        inventory_path = FILE_BASE_DIR + '/playbooks/secure_nodes/hosts.ini'
        ca_playbook_path = FILE_BASE_DIR + '/playbooks/secure_nodes/CA_scm_server.yml'
        dc_playbook_path = FILE_BASE_DIR + '/playbooks/secure_nodes/domain-controller.yml'
        hosts_playbook_path = FILE_BASE_DIR + '/playbooks/secure_nodes/cluster-host.yml'

        if not os.path.exists(ca_playbook_path) or not os.path.exists(dc_playbook_path) or not os.path.exists(hosts_playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        dc_ip = ''
        dc_hostname = ''
        nodes = ''

        for provider in providers_nodes:
            if providers_nodes[provider] != []:
                for i in range(len(providers_nodes[provider])):
                    if not dc_ip:
                        dc_ip = providers_nodes[provider][0]
                        continue
                    nodes += '"' + providers_nodes[provider][i] + '"' + ','

            if not dc_hostname and len(providers_nodes[provider]) >= 1 and dc_ip == providers_nodes[provider][0]:
                dc_hostname = clustername + '-node-01.' + provider + '.' + internal_dns_zone

        nodes = nodes[:-1]

        cluster_domain = internal_dns_zone
        krb_realm = internal_dns_zone.upper()
        ldap_base_dn = ''

        split_internal_dns_zone = internal_dns_zone.split('.')

        for zone in split_internal_dns_zone:
            ldap_base_dn += ',dc=' + zone

        ldap_base_dn  = ldap_base_dn[1:]

        extra_vars = '{"nodes": [' + nodes + '], "dc_ip": "' + dc_ip
        extra_vars += '", "cluster_domain": "' + cluster_domain + '", "krb_realm": "' + krb_realm + '", "ldap_base_dn": "' + ldap_base_dn + '", "ca_password": "' + ca_password + '", "krb_admin_password": "' + krb_admin_password + '", "gateway_address": "' + gateway_address + '", "kdc_master_password": "' + kdc_master_password
        extra_vars += '", "internal_dns_zone": "' + internal_dns_zone + '", "ldap_admin_password": "' + ldap_admin_password + '", "dc_hostname": "' + dc_hostname
        extra_vars += '", "cluster_domain": "' + internal_dns_zone + '", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}'

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=ca_playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)
        self.run_playbook(user_id, environment_id, environment_name, playbook_path=dc_playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)
        self.run_playbook(user_id, environment_id, environment_name, playbook_path=hosts_playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_secure_nodes_client(self, user_id, environment_id, environment_name, krb_admin_password, kdc_master_password, ldap_admin_password, nodes, dc_ip, dc_hostname, gateway_address, internal_dns_zone):
        if nodes == []:
            raise Exception('Nodes list is empty')

        if krb_admin_password == '':
            raise Exception('krb_admin_password parameter is empty')

        if kdc_master_password == '':
            raise Exception('kdc_master_password parameter is empty')

        if ldap_admin_password == '':
            raise Exception('ldap_admin_password parameter is empty')

        if dc_ip == '':
            raise Exception('dc_ip parameter is empty')

        if dc_hostname == '':
            raise Exception('dc_hostname parameter is empty')

        if gateway_address == []:
            raise Exception('gateway_address is empty')

        inventory_path = FILE_BASE_DIR + '/playbooks/secure_nodes_client/hosts.ini'
        ca_playbook_path = FILE_BASE_DIR + '/playbooks/secure_nodes_client/distribute_CA.yml'
        hosts_playbook_path = FILE_BASE_DIR + '/playbooks/secure_nodes_client/cluster-host.yml'

        if not os.path.exists(ca_playbook_path) or not os.path.exists(hosts_playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        nodes_var = ''

        for i in range(len(nodes)):
            nodes_var += '"' + nodes[i] + '"' + ','

        nodes_var = nodes_var[:-1]

        cluster_domain = internal_dns_zone
        krb_realm = internal_dns_zone.upper()
        ldap_base_dn = ''

        split_internal_dns_zone = internal_dns_zone.split('.')

        for zone in split_internal_dns_zone:
            ldap_base_dn += ',dc=' + zone

        ldap_base_dn  = ldap_base_dn[1:]

        extra_vars = '{"nodes": [' + nodes_var + '], "dc_ip": "' + dc_ip
        extra_vars += '", "cluster_domain": "' + cluster_domain + '", "krb_realm": "' + krb_realm + '", "ldap_base_dn": "' + ldap_base_dn + '", "krb_admin_password": "' + krb_admin_password + '", "kdc_master_password": "' + kdc_master_password
        extra_vars += '", "internal_dns_zone": "' + internal_dns_zone + '", "ldap_admin_password": "' + ldap_admin_password + '", "dc_hostname": "' + dc_hostname
        extra_vars += '", "gateway_address": "' + gateway_address + '", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}'

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=ca_playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)
        self.run_playbook(user_id, environment_id, environment_name, playbook_path=hosts_playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_add_cluster_user(self, user_id, environment_id, environment_name, ldap_admin_password, dc_ip, cluster_user, gateway_address, internal_dns_zone):
        if dc_ip == '':
            raise Exception('Invalid dc_ip')

        if gateway_address == []:
            raise Exception('gateway_address is empty')

        if ldap_admin_password == '':
            raise Exception('ldap_admin_password is empty')

        required_user_params = [
            'kubernetesUser',
            'username',
            'user_password',
            'type',
            'publicSSHKey',
        ]

        for parameter in required_user_params:
            if parameter not in cluster_user:
                raise Exception('cluster_user needs to have parameter: ' + parameter)
            if type(cluster_user[parameter]) is not bool and not cluster_user[parameter]:
                raise Exception('cluster_user parameter: ' + parameter + ' needs to be set')

        inventory_path = FILE_BASE_DIR + '/playbooks/add_cluster_user/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/add_cluster_user/add_cluster_user.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        krb_realm = internal_dns_zone.upper()
        ldap_base_dn = ''

        split_internal_dns_zone = internal_dns_zone.split('.')

        for zone in split_internal_dns_zone:
            ldap_base_dn += ',dc=' + zone

        ldap_base_dn  = ldap_base_dn[1:]

        extra_vars = '{"first_name": "' + cluster_user['firstName'] + '", "dc_node": "' + dc_ip + '", "last_name": "' + cluster_user['lastName']
        extra_vars += '", "type": "' + cluster_user['type'] + '", "publick_ssh_key": "' + cluster_user['publicSSHKey']
        extra_vars += '", "krb_realm": "' + krb_realm + '", "ldap_base_dn": "' + ldap_base_dn + '", "ldap_admin_password": "' + ldap_admin_password + '", "gateway_address": "' + gateway_address + '", "email": "' + cluster_user['email']
        extra_vars += '", "username": "' + cluster_user['username'] + '", "user_password": "' + cluster_user['user_password']
        extra_vars += '", "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"}'

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def add_user_to_ldap_group(self, user_id, environment_id, environment_name, ldap_admin_password, dc_ip, cluster_user, group_name, gateway_address, internal_dns_zone):
        if dc_ip == '':
            raise Exception('Invalid dc_ip')

        if ldap_admin_password == '':
            raise Exception('Invalid ldap_admin_password')

        if gateway_address == []:
            raise Exception('gateway_address is empty')

        required_user_params = [
            'username',
            'firstName',
            'lastName',
            'email',
        ]

        for parameter in required_user_params:
            if parameter not in cluster_user:
                raise Exception('cluster_user needs to have parameter: ' + parameter)

        inventory_path = FILE_BASE_DIR + '/playbooks/add_user_to_ldap_group/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/add_user_to_ldap_group/site.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        ldap_base_dn = ''

        split_internal_dns_zone = internal_dns_zone.split('.')

        for zone in split_internal_dns_zone:
            ldap_base_dn += ',dc=' + zone
            
        ldap_base_dn  = ldap_base_dn[1:]

        extra_vars = json.dumps({
            "username": cluster_user['username'],
            "groupName": group_name,
            "dc_node": dc_ip,
            "baseDN": ldap_base_dn,
            "adminDN": "cn=admin," + ldap_base_dn,
            "gateway_address": gateway_address,
            "adminPassword": ldap_admin_password,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)


    def run_delete_cluster_user(self, user_id, environment_id, environment_name, ldap_admin_password, dc_ip, client_hosts, cluster_user_username, kubernetes_user, gateway_address, internal_dns_zone):
        if dc_ip == '':
            raise Exception('Invalid dc_ip')
        if cluster_user_username == '':
            raise Exception('Invalid cluster_user_username')
        if kubernetes_user == '':
            raise Exception('Invalid kubernetes_user')
        if gateway_address == []:
            raise Exception('gateway_address is empty')

        inventory_path = FILE_BASE_DIR + '/playbooks/delete_cluster_user/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/delete_cluster_user/delete_cluster_user.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        client_hosts_var = []

        for host in client_hosts:
            client_hosts_var.append(host['private_ip'])

        if client_hosts_var != '':
            client_hosts_var = client_hosts_var[:-1]

        ldap_base_dn = ''

        split_internal_dns_zone = internal_dns_zone.split('.')

        for zone in split_internal_dns_zone:
            ldap_base_dn += ',dc=' + zone

        ldap_base_dn  = ldap_base_dn[1:]

        extra_vars = json.dumps({
            "username": cluster_user_username,
            "dc_node": dc_ip,
            "ldap_base_dn": ldap_base_dn,
            "ldap_admin_password": ldap_admin_password,
            "kubernetes_user": str(kubernetes_user),
            "client_nodes": client_hosts_var,
            "gateway_address": gateway_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_nodes_labels(self, user_id, environment_id, environment_name, master_node_address, provider_nodes, provider_lb_nodes, provider_id, gateway_address, provider):
        if not master_node_address:
            raise Exception('Invalid parameter master_node_address')
        if provider_nodes == []:
            raise Exception('Nodes list is empty')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        inventory_path = FILE_BASE_DIR + '/playbooks/node_labels/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/node_labels/node_labels.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "provider_lb_nodes": json.dumps(provider_lb_nodes),
            "provider_nodes": provider_nodes,
            "provider_id": provider_id,
            "provider": provider,
            "masternode": master_node_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "gateway_address": gateway_address,
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_k3s_ansible(self, user_id, environment_id, environment_name, master_nodes, worker_nodes, gateway_address, dns_servers_ips, kubernetes_configuration):
        if not master_nodes:
            raise Exception('Invalid parameter master_nodes')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')
        if 'version' not in kubernetes_configuration:
            raise Exception('missing parameter kubernetes_configuration')
        if 'serviceAddresses' not in kubernetes_configuration:
            raise Exception('missing parameter serviceAddresses')
        if 'podsSubnet' not in kubernetes_configuration:
            raise Exception('missing parameter podsSubnet')
        if 'networkPlugin' not in kubernetes_configuration:
            raise Exception('missing parameter networkPlugin')

        inventory_path = FILE_BASE_DIR + '/playbooks/k3s-ansible/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/k3s-ansible/site.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        local_dns_servers = ''

        for dns_servers_ip in dns_servers_ips:
            local_dns_servers += dns_servers_ips[dns_servers_ip] + ' '

        local_dns_servers.strip()

        extra_vars = json.dumps({
            'external_cloud_provider': kubernetes_configuration['external_cloud_provider'],
            'kube_version': kubernetes_configuration['version'],
            'kube_service_addresses': kubernetes_configuration['serviceAddresses'],
            'kube_pods_subnet': kubernetes_configuration['podsSubnet'],
            'kube_network_plugin': kubernetes_configuration['networkPlugin'],
            'master_nodes': master_nodes,
            'worker_nodes': worker_nodes,
            'gateway_address': gateway_address,
            'local_dns_servers': local_dns_servers,
            'ansible_python_interpreter': '/usr/bin/python3',
            'ansible_ssh_private_key_file': '/var/.ssh/id_rsa'
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path,
                            inventory_path=inventory_path, extra_vars=extra_vars)

    def run_add_k3s_node(self, user_id, environment_id, environment_name, master_nodes, worker_nodes, gateway_address, kubernetes_configuration):
        if not master_nodes:
            raise Exception('Invalid parameter master_nodes')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        inventory_path = FILE_BASE_DIR + '/playbooks/k3s-ansible/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/k3s-ansible/node.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "kube_version": kubernetes_configuration['version'],
            "kube_service_addresses": kubernetes_configuration['serviceAddresses'],
            "kube_pods_subnet": kubernetes_configuration['podsSubnet'],
            "kube_network_plugin": kubernetes_configuration['networkPlugin'],
            "master_nodes": master_nodes,
            "worker_nodes": worker_nodes,
            "gateway_address": gateway_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path,
                            inventory_path=inventory_path, extra_vars=extra_vars)

    def run_add_elk_secrets(self, user_id, environment_id, environment_name, dc_node, namespace, elastic_password, dns_name):
        if not user_id:
            raise Exception('Invalid parameter user_id')
        if not environment_id:
            raise Exception('Invalid parameter environment_id')
        if not environment_name:
            raise Exception('Invalid parameter environment_name')
        if not dc_node:
            raise Exception('Invalid parameter dc_node')
        if not namespace:
            raise Exception('Invalid parameter namespace')
        if not elastic_password:
            raise Exception('Invalid parameter elastic_password')
        if not dns_name:
            raise Exception('Invalid parameter dns_name')

        inventory_path = FILE_BASE_DIR + '/playbooks/add_elk_secrets/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/add_elk_secrets/add_elk_secrets.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "dc_node": dc_node,
            "namespace": namespace,
            "elastic_password": elastic_password,
            "dns_name": dns_name,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path,
                            inventory_path=inventory_path, extra_vars=extra_vars)

    def run_monitoring(self, user_id, environment_id, environment_name, master_node, grafana_admin_password, grafana_port, kubectl_command, kubeconfig_path, gateway_address):
        if not master_node:
            raise Exception('Invalid parameter master_node')
        if not grafana_admin_password:
            raise Exception('Invalid parameter grafana_admin_password')
        if not grafana_port:
            raise Exception('Invalid parameter grafana_port')
        if not kubectl_command:
            raise Exception('Invalid parameter kubectl_command')
        if not kubeconfig_path:
            raise Exception('Invalid parameter kubeconfig_path')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        inventory_path = FILE_BASE_DIR + '/playbooks/monitoring/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/monitoring/site.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "master_node_address": master_node,
            "grafana_admin_password": grafana_admin_password,
            "grafana_port": grafana_port,
            "kubectl_command": kubectl_command,
            "kubeconfig_path": kubeconfig_path,
            "gateway_address": gateway_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)


    def run_webhook_service(self, user_id, environment_id, environment_name, master_public_ip, ldap_admin_password, kubernetes_users_group_name, gateway_address, internal_dns_zone):
        if not master_public_ip:
            raise Exception('Invalid parameter master_public_ip')
        if not ldap_admin_password:
            raise Exception('Invalid parameter ldap_admin_password')
        if not kubernetes_users_group_name:
            raise Exception('Invalid parameter kubernetes_users_group_name')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')


        inventory_path = FILE_BASE_DIR + '/playbooks/webhook-service/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/webhook-service/webhook.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        ldap_base_dn = ''

        split_internal_dns_zone = internal_dns_zone.split('.')

        for zone in split_internal_dns_zone:
            ldap_base_dn += ',dc=' + zone
            
        ldap_base_dn  = ldap_base_dn[1:]

        extra_vars = json.dumps({
            "master_public_ip": master_public_ip,
            "adminPassword": ldap_admin_password,
            "baseDN": ldap_base_dn,
            "gateway_address": gateway_address,
            "kubernetes_users_group_name": kubernetes_users_group_name,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_add_kubernetes_role_to_user(self, user_id, environment_id, environment_name, dc_node, username, gateway_address):
        if not username:
            raise Exception('Invalid parameter username')
        if not dc_node:
            raise Exception('Invalid parameter dc_node')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        inventory_path = FILE_BASE_DIR + '/playbooks/add_kubernetes_role_to_user/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/add_kubernetes_role_to_user/add_role.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "username": username,
            "dc_node": dc_node,
            "gateway_address": gateway_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_host_interface_mtu(self, user_id, environment_id, environment_name, all_nodes_private_ips, gateway_address, v2=False):
        if not all_nodes_private_ips:
            raise Exception('Invalid parameter all_nodes')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        if v2:
            inventory_path = FILE_BASE_DIR + '/playbooks/dlcm_v2_host_interface_mtu/hosts.ini'
            playbook_path = FILE_BASE_DIR + '/playbooks/dlcm_v2_host_interface_mtu/mtu.yml'
        else:
            inventory_path = FILE_BASE_DIR + '/playbooks/host_interface_mtu/hosts.ini'
            playbook_path = FILE_BASE_DIR + '/playbooks/host_interface_mtu/mtu.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "all_nodes": all_nodes_private_ips,
            "gateway_address": gateway_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)


    def run_vpn_server(self, user_id, environment_id, environment_name, node_address, client_public_ip, client_subnet, providers):
        if not node_address:
            raise Exception('Invalid parameter node_address')
        if not client_public_ip:
            raise Exception('Invalid parameter client_public_ip')
        if not client_subnet:
            raise Exception('Invalid parameter client_subnet')
        if not providers:
            raise Exception('Invalid parameter providers')

        inventory_path = FILE_BASE_DIR + '/playbooks/vpn_server/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/vpn_server/playbook.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "node_address": node_address,
            "client_public_ip": client_public_ip,
            "client_subnet": client_subnet,
            "providers": providers,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)


    def run_vpn_routing(self, user_id, environment_id, environment_name, gateway_address, vpn_server_private_ip, providers, nodes_addresses):
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')
        if not vpn_server_private_ip:
            raise Exception('Invalid parameter vpn_server_private_ip')
        if not providers:
            raise Exception('Invalid parameter providers')
        if not nodes_addresses:
            raise Exception('Invalid parameter nodes_addresses')

        inventory_path = FILE_BASE_DIR + '/playbooks/vpn_routing/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/vpn_routing/playbook.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "gateway_address": gateway_address,
            "vpn_server_private_ip": vpn_server_private_ip,
            "providers": providers,
            "nodes_addresses": nodes_addresses,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)


    def run_add_ssh_key(self, user_id, environment_id, environment_name, app_public_key, app_ssh_user, ssh_user, ssh_user_private_key, ssh_user_private_key_password, nodes, gateway_address):
        if not ssh_user:
            raise Exception('Invalid parameter ssh_user')
        if not ssh_user_private_key:
            raise Exception('Invalid parameter ssh_user_private_key')
        if not nodes:
            raise Exception('Invalid parameter nodes')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')
        if not app_public_key:
            raise Exception('Invalid parameter app_public_key')

        inventory_path = FILE_BASE_DIR + '/playbooks/add_ssh_key/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/add_ssh_key/playbook.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')
        extra_vars = json.dumps({
            "ssh_user": app_ssh_user,
            "app_public_key": app_public_key,
            "nodes": nodes,
            "gateway_address": gateway_address,
            "ssh_user_private_key_password": ssh_user_private_key_password,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": ssh_user_private_key
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars, user=ssh_user)

    def run_create_user(self, user_id, environment_id, environment_name, new_user_public_key, new_user_username, nodes, gateway_address):
        if not nodes:
            raise Exception('Invalid parameter nodes')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')
        if not new_user_public_key:
            raise Exception('Invalid parameter app_public_key')

        inventory_path = FILE_BASE_DIR + '/playbooks/create_user/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/create_user/playbook.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')
        extra_vars = json.dumps({
            "ssh_user": new_user_username,
            "app_public_key": new_user_public_key,
            "nodes_addresses": nodes,
            "gateway_address": gateway_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_delete_user(self, user_id, environment_id, environment_name, username, nodes, gateway_address):
        if not nodes:
            raise Exception('Invalid parameter nodes')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        inventory_path = FILE_BASE_DIR + '/playbooks/delete_user/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/delete_user/playbook.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')
        extra_vars = json.dumps({
            "ssh_user": username,
            "nodes_addresses": nodes,
            "gateway_address": gateway_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_create_kubernetes_user(self, user_id, environment_id, environment_name,  username,  kubeconfig_value):
        if not username:
            raise Exception('Invalid parameter username')
        if not kubeconfig_value:
            raise Exception('Invalid parameter kubeconfig_value')

        inventory_path = FILE_BASE_DIR + '/playbooks/create_kubernetes_user/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/create_kubernetes_user/playbook.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        master_ip = yaml.safe_load(kubeconfig_value)["clusters"][0]["cluster"]["server"]

        extra_vars = json.dumps({
            "user": username,
            "master_ip": master_ip,
            "cluster_id": environment_id,
            "kubeconfig_value": kubeconfig_value,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_delete_kubernetes_user(self, user_id, environment_id, environment_name,  username,  kubeconfig_value):
        if not username:
            raise Exception('Invalid parameter username')
        if not kubeconfig_value:
            raise Exception('Invalid parameter kubeconfig_value')

        inventory_path = FILE_BASE_DIR + '/playbooks/delete_kubernetes_user/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/delete_kubernetes_user/playbook.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "user": username,
            "cluster_id": environment_id,
            "kubeconfig_value": kubeconfig_value,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)


    def run_fix_coredns(self, user_id, environment_id, environment_name, master_node_address, gateway_address, dns_servers_ips):
        if not master_node_address:
            raise Exception('Invalid parameter master_node_address')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        inventory_path = FILE_BASE_DIR + '/playbooks/fix_coredns/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/fix_coredns/playbook.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        local_dns_servers = ''

        for dns_servers_ip in dns_servers_ips:
            local_dns_servers += dns_servers_ips[dns_servers_ip] + ' '

        local_dns_servers.strip()

        extra_vars = json.dumps({
            "master_node_address": master_node_address,
            "gateway_address": gateway_address,
            "local_dns_servers": local_dns_servers,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_delete_kubespray_directory(self, user_id, environment_id, environment_name, inventory_directory_name):
        if not inventory_directory_name:
            raise Exception('Invalid parameter inventory_directory_name')

        inventory_path = FILE_BASE_DIR + '/playbooks/delete_kubespray_directory/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/delete_kubespray_directory/playbook.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "inventory_directory_name": inventory_directory_name,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_capi_cluster(self, user_id, environment_id, control_plane, worker_nodes, management_cluster_namespace, auth_url,
                        application_credential_id, application_credential_secret, region,
                        cluster_name, kubernetes_version, ssh_key_name, operation, external_network_id):
        cluster = CapiCluster.objects.filter(id=environment_id)[0]

        environment_name = cluster.title

        inventory_path = FILE_BASE_DIR + '/playbooks/capi_cluster/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/capi_cluster/playbook.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "AUTH_URL": auth_url,
            "APPLICATION_CREDENTIAL_ID": application_credential_id,
            "APPLICATION_CREDENTIAL_SECRET": application_credential_secret,
            "REGION": region,
            "NAMESPACE": management_cluster_namespace,
            "CLUSTER_NAME": cluster_name,
            "KUBERNETES_VERSION": kubernetes_version,
            "OPENSTACK_SSH_KEY_NAME": ssh_key_name,
            "OPENSTACK_EXTERNAL_NETWORK_ID": external_network_id,
            "KUBERNTES_COMMAND": operation,
            'control_plane': control_plane,
            'worker_nodes': worker_nodes,
            "ansible_python_interpreter": "/usr/bin/python3"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_yaookcapi_cluster(self, user_id, environment_id, control_plane, worker_nodes, management_cluster_namespace, auth_url,
                        application_credential_id, application_credential_secret, wg_peers,
                        cluster_name, kubernetes_version, operation, delete_old_machine_deployments = False):
        cluster = YaookCapiCluster.objects.filter(id=environment_id)[0]

        environment_name = cluster.title

        inventory_path = FILE_BASE_DIR + '/playbooks/yaookcapi_cluster/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/yaookcapi_cluster/playbook.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
        "CLUSTER_NAME": cluster_name,
        "CONTROL_PLANE_MACHINE_COUNT": control_plane['replicas'],
        "KUBERNETES_VERSION": kubernetes_version,
        "OPENSTACK_CONTROL_PLANE_IMAGE_NAME": control_plane['operatingSystem'],
        "OPENSTACK_CONTROL_PLANE_MACHINE_FLAVOR": control_plane['instanceType'],
        "OS_APPLICATION_CREDENTIAL_ID": application_credential_id,
        "OS_APPLICATION_CREDENTIAL_SECRET": application_credential_secret,
        "OS_AUTH_TYPE": "v3applicationcredential",
        "OS_AUTH_URL": auth_url,
        "wg_peers": wg_peers,
        "NAMESPACE": management_cluster_namespace,
        "DELETE_OLD_MACHINE_DEPLOYMENTS": delete_old_machine_deployments,
        "worker_nodes": worker_nodes,
        "control_plane": control_plane,
        "KUBERNTES_COMMAND": operation,
        "PATH_TO_MANAGEMENT_CLUSTER_KUBECTL": YAOOKCAPI_MANAGEMENT_CLUSTER_KUBECONFIG_PATH,
            "ansible_python_interpreter": "/usr/bin/python3"
        })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def kubernetes_nfs_storage_integration(self, resources, user_id, master_ip, gateway_address, cluster_id):
        cluster = Clusters.objects.filter(id=cluster_id)[0]

        environment_id = str(cluster.id)
        environment_name = cluster.title
        master_node_address = master_ip

        if not master_node_address:
            raise Exception('Invalid parameter master_node_address')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        inventory_path = FILE_BASE_DIR + '/playbooks/kubernetes_nfs_storage/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/kubernetes_nfs_storage/storage.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "gateway_address": gateway_address,
            "master_node_address": master_node_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
            })

        ansible_client = AnsibleClient()
        ansible_client.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    def run_kubernetes_decomission_nodes(self, user_id, environment_id, environment_name, nodes_to_delete, master_node_ip, primary_master_node_name, gateway_address):
        inventory_path = FILE_BASE_DIR + '/playbooks/kubernetes_decomission_nodes/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/kubernetes_decomission_nodes/playbook.yml'

        if not nodes_to_delete:
            raise Exception('Invalid parameter nodes_to_delete')

        if not master_node_ip:
            raise Exception('Invalid parameter master_node_ip')

        if not primary_master_node_name:
            raise Exception('Invalid parameter primary_master_node_name')

        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "nodes_to_delete": nodes_to_delete,
            "masternode": master_node_ip,
            "primary_master_node_name": primary_master_node_name,
            "gateway_address": gateway_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
            })

        self.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)