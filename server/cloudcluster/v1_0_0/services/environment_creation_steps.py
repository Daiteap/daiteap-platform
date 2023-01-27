from __future__ import absolute_import, unicode_literals

import base64
import json
import logging
import os
import pathlib
import tempfile
import time
import yaml
import socket
from string import Template
from cloudcluster.v1_0_0 import tasks

import environment_providers.environment_providers as environment_providers
import environment_providers.google.services.api_client as google_client
import paramiko
from cloudcluster import settings
from cloudcluster.models import (CapiCluster, CloudAccount, Clusters,
                                 DaiteapUser, Service,
                                 Machine, Profile, YaookCapiCluster)
from cloudcluster.settings import (
    CAPI_MANAGEMENT_CLUSTER_NAMESPACE, DEBUG, LDAP_KUBERNETES_USERS_GROUP_NAME,
    SUPPORTED_K3S_VERSIONS, YAOOKCAPI_MANAGEMENT_CLUSTER_KUBECONFIG_PATH,
    YAOOKCAPI_MANAGEMENT_CLUSTER_NAMESPACE)
from cloudcluster.v1_0_0.manifests.templates import (CALICO_MANIFEST,
                                                     FLANNEL_MANIFEST)
from cloudcluster.v1_0_0.services.constants import OPENSTACK_CLOUDS_CONF

from ..ansible.ansible_client import AnsibleClient
from ..helm.helm_client import HelmClient
from ..helm.values_templates.templates import (elasticsearch_template,
                                               fluentd_template,
                                               basic_template_with_replicas,
                                               kibana_template)
from ..mailgun.mailgun_client import MailgunClient
from ..services import random_string, run_shell, ssh_client, vault_service, vpn_client
from ..services.kubespray_inventory import build_inventory

LONGHORN_PASSWORD_LENGTH = 16
GRAFANA_PASSWORD_LENGTH = 16
GRAFANA_PORT = 31000
KIBANA_PORT = 31001
ES_PASSWORD_LENGTH = 16

logger = logging.getLogger(__name__)


FILE_BASE_DIR = str(pathlib.Path(__file__).parent.absolute().parent)

def get_nodes_addresses(resources, user_id, cluster):
    machines = Machine.objects.filter(cluster=cluster)

    nodes_addresses = []

    for node in machines:
        node_data = {}

        node_data['id'] = node.kube_name
        node_data['address'] = node.privateIP
        node_data['kube_master'] = node.kube_master
        node_data['kube_etcd'] = node.kube_etcd

        nodes_addresses.append(node_data)

    if nodes_addresses == '':
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_dlcm_environment'
        }
        logger.error('', extra=log_data)
        return None

    return nodes_addresses

def get_used_terraform_environment_resources(resources, user_id, cluster_id):
    environment_providers.get_used_terraform_environment_resources(resources, user_id, cluster_id)

def prepare_kubespray(resources, ansible_client: AnsibleClient, user_id, cluster_id, kubespray_inventory_dir_name, kubernetes_configuration):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    nodes_addresses = get_nodes_addresses(resources, user_id, cluster)

    ansible_client.run_prepare_kubespray(user_id, str(cluster.id), cluster.title, kubespray_inventory_dir_name, kubernetes_configuration)

    build_inventory(nodes_addresses, FILE_BASE_DIR + '/ansible/playbooks/kubespray/inventory/' + kubespray_inventory_dir_name + '/inventory.yaml')

def kubernetes_decomission_nodes(cluster_id, user_id, nodes_to_delete):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    master_node = Machine.objects.filter(cluster=cluster_id, kube_master=True, publicIP__isnull=False)[0]
    gateway_address = settings.SSH_USERNAME + '@' + master_node.publicIP
    master_node_ip = master_node.privateIP
    primary_master_node_name = master_node.kube_name

    ansible_client = AnsibleClient()

    if len(nodes_to_delete) > 0:
        ansible_client.run_kubernetes_decomission_nodes(user_id, str(cluster_id), cluster.title, nodes_to_delete, master_node_ip, primary_master_node_name, gateway_address)

def delete_kubespray_inventory_dir(ansible_client: AnsibleClient, user_id, cluster_id, kubespray_inventory_dir_name):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    ansible_client.run_delete_kubespray_directory(user_id, str(cluster.id), cluster.title, kubespray_inventory_dir_name)

def fix_coredns(ansible_client: AnsibleClient, user_id, cluster_id, gateway_address, master_node_address, dns_servers_ips):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    ansible_client.run_fix_coredns(user_id, str(cluster.id), cluster.title, master_node_address, gateway_address, dns_servers_ips)

def prepare_nodes(ansible_client: AnsibleClient, user_id, nodes_privateips, gateway_address, cluster_id, v2=False):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    ansible_client.run_prepare_nodes(user_id, str(cluster.id), cluster.title, nodes_privateips, gateway_address, v2=v2)

def dns(resources, user_id, gateway_address, nodes_ips, cluster_id, dns_servers_ips, v2=False):
    environment_providers.run_dns(resources, nodes_ips, dns_servers_ips, cluster_id, user_id, gateway_address, v2=v2)

def host_interface_mtu(ansible_client: AnsibleClient, user_id, gateway_address, all_nodes_private_ips, cluster_id, v2=False):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    ansible_client.run_host_interface_mtu(user_id, str(cluster.id), cluster.title, all_nodes_private_ips, gateway_address, v2=v2)

def fix_hostnames(user_id, nodes_ips, gateway_address, cluster_id, v2=False):
    environment_providers.fix_hostnames(user_id, nodes_ips, gateway_address, cluster_id, v2)

def secure_nodes(ansible_client: AnsibleClient, user_id, nodes_ips, gateway_address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    krb_admin_password = random_string.get_random_alphanumeric_string(20)
    kdc_master_password = random_string.get_random_alphanumeric_string(20)
    ldap_admin_password = random_string.get_random_alphanumeric_string(20)
    ca_password = random_string.get_random_alphanumeric_string(20)

    cluster.krb_admin_password = krb_admin_password
    cluster.kdc_master_password = kdc_master_password
    cluster.ldap_admin_password = ldap_admin_password
    cluster.ca_password = ca_password

    cluster.save()

    providers_nodes = {}

    for provider_nodes in nodes_ips:
        if provider_nodes.endswith('_nodes'):
            providers_nodes[provider_nodes.split('_nodes')[0]] = nodes_ips[provider_nodes]

    ansible_client.run_secure_nodes(user_id, str(cluster.id), cluster.title, krb_admin_password, kdc_master_password, ldap_admin_password, ca_password, providers_nodes, cluster.name, gateway_address, json.loads(cluster.config)['internal_dns_zone'])

def webhook_service(ansible_client: AnsibleClient, user_id, master_ip, gateway_address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    ansible_client.run_webhook_service(user_id, str(cluster.id), cluster.title, master_ip, cluster.ldap_admin_password, LDAP_KUBERNETES_USERS_GROUP_NAME, gateway_address, json.loads(cluster.config)['internal_dns_zone'])

def kubespray(ansible_client: AnsibleClient, user_id, gateway_address, cluster_id, kubespray_inventory_dir_name):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    ansible_client.run_kubespray(user_id, str(cluster.id), cluster.title, gateway_address, kubespray_inventory_dir_name)

def upgrade_kubespray_cluster(ansible_client: AnsibleClient, user_id, gateway_address, cluster_id, kubespray_inventory_dir_name):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    ansible_client.run_upgrade_kubespray(user_id, str(cluster.id), cluster.title, gateway_address, kubespray_inventory_dir_name)

def create_daiteap_dns_record(cluster_id, ip_list):
    google_client.create_daiteap_dns_record_set(cluster_id, ip_list)

    return

def delete_daiteap_dns_record(cluster_id):
    google_client.delete_daiteap_dns_record_set(cluster_id)

    return

def install_ingress_controller(clusterId):
    serviceName = 'nginx-ingress'
    configuration = {
        'name': 'daiteap',
        'namespace': 'daiteap-ingress',
        'service_type': 'LoadBalancer',
        'replicas': 1,
        'cloud_providers': []
    }
    is_yaookcapi = False
    cluster = Clusters.objects.filter(id=clusterId)
    if len(cluster) == 0:
        cluster = CapiCluster.objects.filter(id=clusterId)
        if len(cluster) == 0:
            cluster = YaookCapiCluster.objects.filter(id=clusterId)[0]
            is_yaookcapi = True
    else:
        cluster = cluster[0]

    for machine in Machine.objects.filter(cluster_id=clusterId):
        if machine.provider not in configuration['cloud_providers']:
            configuration['cloud_providers'].append(machine.provider)

    chart = HelmClient()
    chart.Helm_DIR = FILE_BASE_DIR + '/helm/charts/'
    chart.name = configuration['name']
    chart.chart_name = serviceName
    chart.namespace = configuration['namespace']

    service = Service.objects.filter(name=serviceName)[0]
    service_options = json.loads(service.options)

    if is_yaookcapi:
        vpn_client.connect(cluster.wireguard_config, cluster.id)

    values_file = ""

    selectedProviders, providers_string = environment_providers.get_service_selected_providers(service_options, configuration)

    template = Template(basic_template_with_replicas)
    values_file = template.substitute(
        providers=providers_string,
        service_type=configuration['service_type'],
        replicas=configuration['replicas']
    )

    with tempfile.TemporaryDirectory() as credentials_path:
        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
            print(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        with open(credentials_path + 'values.yaml', 'a') as text_file:
            text_file.write(values_file)

        chart.kubeconfig_path = credentials_path + 'kubectl_config'
        uninstalled = False

        try:
            chart.uninstall()            
            uninstalled = True
        except Exception as e:
            print(e)
        
        if uninstalled:
            cmd = ['kubectl',
                '--kubeconfig',
                credentials_path + 'kubectl_config',
                'get',
                'service',
                '--namespace',
                'daiteap-ingress',
                'daiteap-ingress-nginx-controller',
                '--ignore-not-found'
            ]
            max_retries = 30
            wait_seconds = 20
            for i in range(0, max_retries):
                time.sleep(wait_seconds)

                output = run_shell.run_shell_with_subprocess_popen(cmd, workdir='./', return_stdout=True)
                if output['stdout'] == []:
                    break

                if i == max_retries - 1:
                    raise Exception('Timeout while waiting daiteap ingress controller to uninstall')

        chart.install(credentials_path + 'values.yaml')

        yaml.safe_load(cluster.kubeconfig)

        cmd = ['kubectl',
            '--kubeconfig',
            credentials_path + 'kubectl_config',
            'get',
            'service',
            '--namespace',
            'daiteap-ingress',
            'daiteap-ingress-nginx-controller',
            '-o',
            'jsonpath="{.status.loadBalancer.ingress[0].*}"'
        ]

        max_retries = 30
        wait_seconds = 20
        for i in range(0, max_retries):
            time.sleep(wait_seconds)

            output = run_shell.run_shell_with_subprocess_popen(cmd, workdir='./', return_stdout=True)
            if output['stdout'] != ['""']:
                break

            if i == max_retries - 1:
                raise Exception('Timeout while waiting daiteap ingress controller to create')

        ip_list = get_loadbalancer_service_addresses(output['stdout'][0].strip('"'))

    if is_yaookcapi:
        vpn_client.disconnect(cluster.wireguard_config, cluster.id)

    return ip_list

def get_loadbalancer_service_addresses(service):
    ip_list = []
    max_retries = 30
    wait_seconds = 20
    for i in range(0, max_retries):
        try:
            time.sleep(wait_seconds)
            ais = socket.getaddrinfo(str(service),443)
            break
        except:
            if i == max_retries - 1:
                raise Exception('Timeout while waiting loadbalancer service address')

    for result in ais:
      if result[-1][0] not in ip_list:
        ip_list.append(result[-1][0])

    ip_list = list(set(ip_list))
    return ip_list

def install_cert_manager(clusterId):
    serviceName = 'cert-manager'
    configuration = {
        'name': 'daiteap-cert-manager',
        'namespace': 'daiteap-ingress',
        'service_type': '',
        'replicas': 1,
        'cloud_providers': []
    }
    is_yaookcapi = False
    cluster = Clusters.objects.filter(id=clusterId)
    if len(cluster) == 0:
        cluster = CapiCluster.objects.filter(id=clusterId)
        if len(cluster) == 0:
            cluster = YaookCapiCluster.objects.filter(id=clusterId)[0]
            is_yaookcapi = True
    else:
        cluster = cluster[0]

    for machine in Machine.objects.filter(cluster_id=clusterId):
        if machine.provider not in configuration['cloud_providers']:
            configuration['cloud_providers'].append(machine.provider)

    chart = HelmClient()
    chart.Helm_DIR = FILE_BASE_DIR + '/helm/charts/'
    chart.name = configuration['name']
    chart.chart_name = serviceName
    chart.namespace = configuration['namespace']

    service_options = {'name': {'choice': 'custom', 'type': 'string'}, 'namespace': {'choice': 'custom', 'type': 'string', 'default': 'default'}, 'service_type': {'choice': 'single', 'values': [''], 'default': ''}, 'cloud_providers': {'choice': 'multiple', 'values': ['google', 'aws', 'azure', 'alicloud', 'openstack']}, 'replicas': {'choice': 'custom', 'type': 'int', 'default': 1}, 'yamlConfig': True}

    if is_yaookcapi:
        vpn_client.connect(cluster.wireguard_config, cluster.id)

    values_file = ""

    selectedProviders, providers_string = environment_providers.get_service_selected_providers(service_options, configuration)

    template = Template(basic_template_with_replicas)
    values_file = template.substitute(
        providers=providers_string,
        service_type=configuration['service_type'],
        replicas=configuration['replicas']
    )

    with tempfile.TemporaryDirectory() as credentials_path:

        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
            print(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        with open(credentials_path + 'values.yaml', 'a') as text_file:
            text_file.write(values_file)

        chart.kubeconfig_path = credentials_path + 'kubectl_config'
        try:
            command = ['kubectl', '--kubeconfig=' + chart.kubeconfig_path, 'delete', '-f']
            command.append('https://github.com/cert-manager/cert-manager/releases/download/v1.8.2/cert-manager.crds.yaml')

            run_shell.run_shell_with_subprocess_call(command, workdir='./')

            chart.uninstall(credentials_path + 'values.yaml')
            time.sleep(20)
        except:
            print('no cert manager')

        command = ['kubectl', '--kubeconfig=' + chart.kubeconfig_path, 'apply', '-f']
        command.append('https://github.com/cert-manager/cert-manager/releases/download/v1.8.2/cert-manager.crds.yaml')

        run_shell.run_shell_with_subprocess_call(command, workdir='./')

        chart.install(credentials_path + 'values.yaml')

        yaml.safe_load(cluster.kubeconfig)

        issuer = open(os.path.join(settings.BASE_DIR + '/cloudcluster/v1_0_0/manifests/cert-issuer.yaml'))

        with open(credentials_path + 'cert-issuer.yaml', 'a') as text_file:
            text_file.write(issuer.read())

        command = ['kubectl', '--kubeconfig=' + credentials_path + 'kubectl_config', 'apply', '-f']
        command.append(credentials_path + 'cert-issuer.yaml')

        run_shell.run_shell_with_subprocess_call(command, workdir='./')

    if is_yaookcapi:
        vpn_client.disconnect(cluster.wireguard_config, cluster.id)

    return

def install_capi_cluster(ansible_client: AnsibleClient, user_id, cluster_id):
    cluster = CapiCluster.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.capi_config)
    account = CloudAccount.objects.filter(id=config['openstack']['account'], provider='openstack')[0]
    regions_params = json.loads(account.regions)
    credentials = vault_service.read_secret(account.credentials)

    operation = 'create'
    cluster_name = str(cluster.id)
    region = config['openstack']['region']
    kubernetes_version = config['kubernetesConfiguration']['version']
    worker_nodes = config['openstack']['workerNodes']
    control_plane = config['openstack']['controlPlane']

    payload = {
        'provider': 'openstack',
        'accountId': config['openstack']['account']
    }
    operating_systems = environment_providers.get_valid_operating_systems(payload, 5, user_id)

    for worker_node in worker_nodes:
        for os in operating_systems:
            if os['value'] == worker_node['operatingSystem']:
                worker_node['operatingSystem'] = os['os']

    for os in operating_systems:
        if os['value'] == control_plane['operatingSystem']:
            control_plane['operatingSystem'] = os['os']

    cluster.capi_config = json.dumps(config)
    cluster.save()

    for region_param in regions_params:
        if region_param['name'] == config['openstack']['region']:
            for worker_node in worker_nodes:
                for zone_param in region_param['zones']:
                    for instance_param in zone_param['instances']:
                        if instance_param['name'] == worker_node['instanceType']:
                            worker_node['instanceType'] = instance_param['type']
                            break

            for zone_param in region_param['zones']:
                for instance_param in zone_param['instances']:
                    if instance_param['name'] == control_plane['instanceType']:
                        control_plane['instanceType'] = instance_param['type']
                        break

    auth_url = credentials['auth_url']
    application_credential_id = credentials['application_credential_id']
    application_credential_secret = credentials['application_credential_secret']
    ssh_key_name = credentials['ssh_key_name']

    external_network_id = vault_service.read_secret(account.credentials)['external_network_id']

    ansible_client.run_capi_cluster(user_id, cluster_id, control_plane,
                                    worker_nodes, CAPI_MANAGEMENT_CLUSTER_NAMESPACE, auth_url,
                                    application_credential_id, application_credential_secret, region,
                                    cluster_name, kubernetes_version, ssh_key_name, operation, external_network_id)

def resize_capi_cluster(ansible_client: AnsibleClient, user_id, cluster_id, workerNodes):
    cluster = CapiCluster.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.capi_config)
    account = CloudAccount.objects.filter(id=config['openstack']['account'], provider='openstack')[0]
    regions_params = json.loads(account.regions)
    credentials = vault_service.read_secret(account.credentials)

    operation = 'apply'
    cluster_name = str(cluster.id)
    region = config['openstack']['region']
    kubernetes_version = config['kubernetesConfiguration']['version']
    worker_nodes = workerNodes
    control_plane = config['openstack']['controlPlane']

    payload = {
        'provider': 'openstack',
        'accountId': config['openstack']['account']
    }
    operating_systems = environment_providers.get_valid_operating_systems(payload, 5, user_id)

    for worker_node in worker_nodes:
        for os in operating_systems:
            if os['value'] == worker_node['operatingSystem']:
                worker_node['operatingSystem'] = os['os']

    for os in operating_systems:
        if os['value'] == control_plane['operatingSystem']:
            control_plane['operatingSystem'] = os['os']

    cluster.capi_config = json.dumps(config)
    cluster.save()

    for region_param in regions_params:
        if region_param['name'] == config['openstack']['region']:
            for worker_node in worker_nodes:
                for zone_param in region_param['zones']:
                    if zone_param['name'] == worker_node['zone']:
                        for instance_param in zone_param['instances']:
                            if instance_param['name'] == worker_node['instanceType']:
                                worker_node['instanceType'] = instance_param['type']

            for zone_param in region_param['zones']:
                if zone_param['name'] == control_plane['zone']:
                    for instance_param in zone_param['instances']:
                        if instance_param['name'] == control_plane['instanceType']:
                            control_plane['instanceType'] = instance_param['type']

    auth_url = credentials['auth_url']
    application_credential_id = credentials['application_credential_id']
    application_credential_secret = credentials['application_credential_secret']
    ssh_key_name = credentials['ssh_key_name']
    

    external_network_id = vault_service.read_secret(account.credentials)['external_network_id']

    ansible_client.run_capi_cluster(user_id, cluster_id, control_plane,
                                    worker_nodes, CAPI_MANAGEMENT_CLUSTER_NAMESPACE, auth_url,
                                    application_credential_id, application_credential_secret, region,
                                    cluster_name, kubernetes_version, ssh_key_name, operation, external_network_id)

def delete_capi_cluster(cluster_id, user_id):
    cluster = CapiCluster.objects.filter(id=cluster_id)[0]

    filtered_environment_providers = []
    resources = json.loads(cluster.capi_config)

    for environment_provider in environment_providers.supported_providers:
        if environment_provider in resources:
            filtered_environment_providers.append(environment_provider)

    # Clean disk resources
    for environment_provider in filtered_environment_providers:
        environment_providers.supported_providers[environment_provider]['provider'].destroy_disk_resources(cluster_id, user_id)

    # delete cluster if present
    command = ['kubectl', '--kubeconfig=/root/.kube/config', '-n', 'default', 'get', 'cluster',
                cluster_id, '-o', 'jsonpath={.metadata.name}']

    output = run_shell.run_shell_with_subprocess_popen(command, workdir='./', return_stdout=True)

    if len(output['stdout'][0]) > 0:
        command = ['kubectl', '--kubeconfig=/root/.kube/config', '-n', 'default', 'delete', 'cluster']
        command.append(str(cluster.id))

        run_shell.run_shell_with_subprocess_call(command, workdir='./')

    # delete secret if present
    command = ['kubectl', '--kubeconfig=/root/.kube/config', '-n', 'default', 'get', 'secret',
                str(cluster.id) + '-cloud-config', '-o', 'jsonpath={.metadata.name}']

    output = run_shell.run_shell_with_subprocess_popen(command, workdir='./', return_stdout=True)

    if len(output['stdout'][0]) > 0:
        command = ['kubectl', '--kubeconfig=/root/.kube/config', '-n', 'default', 'delete', 'secret']
        command.append(str(cluster.id) + '-cloud-config')

        run_shell.run_shell_with_subprocess_call(command, workdir='./')

    return

def install_yaookcapi_cluster(user_id, cluster_id):
    cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.yaookcapi_config)
    account = CloudAccount.objects.filter(id=config['openstack']['account'], provider='openstack')[0]
    regions_params = json.loads(account.regions)
    credentials = vault_service.read_secret(account.credentials)

    operation = 'create'
    cluster_name = str(cluster.id)
    kubernetes_version = config['kubernetesConfiguration']['version']
    worker_nodes = config['openstack']['workerNodes']
    control_plane = config['openstack']['controlPlane']

    payload = {
        'provider': 'openstack',
        'accountId': config['openstack']['account']
    }
    operating_systems = environment_providers.get_valid_operating_systems(payload, 8, user_id)

    for worker_node in worker_nodes:
        for os in operating_systems:
            if os['value'] == worker_node['operatingSystem']:
                worker_node['operatingSystem'] = os['os']

    for os in operating_systems:
        if os['value'] == control_plane['operatingSystem']:
            control_plane['operatingSystem'] = os['os']

    for region_param in regions_params:
        if region_param['name'] == config['openstack']['region']:
            for worker_node in worker_nodes:
                for zone_param in region_param['zones']:
                    for instance_param in zone_param['instances']:
                        if instance_param['name'] == worker_node['instanceType']:
                            worker_node['instanceType'] = instance_param['type']
                            break

            for zone_param in region_param['zones']:
                for instance_param in zone_param['instances']:
                    if instance_param['name'] == control_plane['instanceType']:
                        control_plane['instanceType'] = instance_param['type']
                        break

    auth_url = credentials['auth_url']
    application_credential_id = credentials['application_credential_id']
    application_credential_secret = credentials['application_credential_secret']

    # Add cluster to wireguard
    wg_peers = []
    wg_peers.append({
        'indent': cluster.wireguard_indent,
        'publicKey': cluster.wireguard_public_key
        }
    )

    # Add users to wireguard
    project_users = DaiteapUser.objects.filter(projects__id=cluster.project.id)

    for project_user in project_users:
        if project_user.user.profile.wireguard_public_key:
            wg_peers.append({
                'indent': str(cluster.id) + '-' + str(project_user.user.id),
                'publicKey': project_user.user.profile.wireguard_public_key
            })

    #TODO: Fix
    zone = 'AZ2'
    for worker_node in worker_nodes:
        # set random zone
        worker_node['zone'] = zone

    control_plane['zone'] = zone

    ansible_client = AnsibleClient()
    ansible_client.run_yaookcapi_cluster(user_id, cluster_id, control_plane,
                                    worker_nodes, YAOOKCAPI_MANAGEMENT_CLUSTER_NAMESPACE, auth_url,
                                    application_credential_id, application_credential_secret, wg_peers,
                                    cluster_name, kubernetes_version, operation)

def resize_yaookcapi_cluster(ansible_client: AnsibleClient, user_id, cluster_id, workerNodes, delete_old_machine_deployments = False):
    cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.yaookcapi_config)
    account = CloudAccount.objects.filter(id=config['openstack']['account'], provider='openstack')[0]
    regions_params = json.loads(account.regions)
    credentials = vault_service.read_secret(account.credentials)

    operation = 'apply'
    cluster_name = str(cluster.id)
    kubernetes_version = config['kubernetesConfiguration']['version']
    if workerNodes:
        worker_nodes = workerNodes
    else:
        worker_nodes = config['openstack']['workerNodes']
    control_plane = config['openstack']['controlPlane']

    payload = {
        'provider': 'openstack',
        'accountId': config['openstack']['account']
    }
    operating_systems = environment_providers.get_valid_operating_systems(payload, 8, user_id)

    for worker_node in worker_nodes:
        for os in operating_systems:
            if os['value'] == worker_node['operatingSystem']:
                worker_node['operatingSystem'] = os['os']

    for os in operating_systems:
        if os['value'] == control_plane['operatingSystem']:
            control_plane['operatingSystem'] = os['os']

    cluster.yaookcapi_config = json.dumps(config)
    cluster.save()

    for region_param in regions_params:
        if region_param['name'] == config['openstack']['region']:
            for worker_node in worker_nodes:
                for zone_param in region_param['zones']:
                    for instance_param in zone_param['instances']:
                        if instance_param['name'] == worker_node['instanceType']:
                            worker_node['instanceType'] = instance_param['type']
                            break

            for zone_param in region_param['zones']:
                for instance_param in zone_param['instances']:
                    if instance_param['name'] == control_plane['instanceType']:
                        control_plane['instanceType'] = instance_param['type']
                        break

    auth_url = credentials['auth_url']
    application_credential_id = credentials['application_credential_id']
    application_credential_secret = credentials['application_credential_secret']

    # Add cluster to wireguard
    wg_peers = []
    wg_peers.append({
        'indent': cluster.wireguard_indent,
        'publicKey': cluster.wireguard_public_key
        }
    )

    # Add users to wireguard
    project_users = DaiteapUser.objects.filter(projects__id=cluster.project.id)

    for project_user in project_users:
        if project_user.user.profile.wireguard_public_key:
            wg_peers.append({
                'indent': str(cluster.id) + '-' + str(project_user.user.id),
                'publicKey': project_user.user.profile.wireguard_public_key
            })

    #TODO: Fix
    zone = 'AZ2'
    for worker_node in worker_nodes:
        # set random zone
        worker_node['zone'] = zone

    control_plane['zone'] = zone

    ansible_client.run_yaookcapi_cluster(user_id, cluster_id, control_plane,
                                    worker_nodes, YAOOKCAPI_MANAGEMENT_CLUSTER_NAMESPACE, auth_url,
                                    application_credential_id, application_credential_secret, wg_peers,
                                    cluster_name, kubernetes_version, operation, delete_old_machine_deployments)

def delete_yaookcapi_cluster(cluster_id, user_id):
    cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]

    filtered_environment_providers = []
    resources = json.loads(cluster.yaookcapi_config)

    for environment_provider in environment_providers.supported_providers:
        if environment_provider in resources:
            filtered_environment_providers.append(environment_provider)

    # Clean disk resources
    for environment_provider in filtered_environment_providers:
        environment_providers.supported_providers[environment_provider]['provider'].destroy_disk_resources(cluster_id, user_id)

    # delete cluster if present
    command = ['kubectl', '--kubeconfig=' + YAOOKCAPI_MANAGEMENT_CLUSTER_KUBECONFIG_PATH, '-n', 'default', 'delete', 'yaook', '-l',
                'cluster-name=' + cluster_id, '--ignore-not-found']
    

    output = run_shell.run_shell_with_subprocess_popen(command, workdir='./', return_stdout=True, raise_on_error=False)

    logger.debug(output)

    not_found_msg = 'Error from server (NotFound): clusters.cluster.x-k8s.io \"' + str(cluster.id) + '\" not found'
    if output['return_code'] != 0 and "stderr" in output and output['stderr']:
        if not_found_msg in output["stderr"]:
            logger.debug('Cluster not found in management cluster, deleting from the database')
        else:
            raise Exception(output["stderr"])

    # delete secret if present
    command = ['kubectl', '--kubeconfig=' + YAOOKCAPI_MANAGEMENT_CLUSTER_KUBECONFIG_PATH, '-n', 'default', 'get', 'secret',
                str(cluster.id) + '-openrc', '-o', 'jsonpath={.metadata.name}']

    output = run_shell.run_shell_with_subprocess_popen(command, workdir='./', return_stdout=True, raise_on_error=False)


    if len(output['stdout']) > 0 and len(output['stdout'][0]) > 0:
        command = ['kubectl', '--kubeconfig=' + YAOOKCAPI_MANAGEMENT_CLUSTER_KUBECONFIG_PATH, '-n', 'default', 'delete', 'secret']
        command.append(str(cluster.id) + '-openrc')

        run_shell.run_shell_with_subprocess_call(command, workdir='./')

    return

def nodes_labels(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    environment_providers.nodes_labels(resources, user_id, clouds, master_ip, gateway_address, cluster_id)

def monitoring(ansible_client: AnsibleClient, user_id, master_node_address, gateway_address, cluster_id, kubectl_command, kubeconfig_path):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    grafana_admin_password = random_string.get_random_alphanumeric_string(GRAFANA_PASSWORD_LENGTH)
    ansible_client.run_monitoring(user_id, str(cluster.id), cluster.title, master_node_address, grafana_admin_password, GRAFANA_PORT, kubectl_command, kubeconfig_path, gateway_address)
    cluster.grafana_admin_password = grafana_admin_password
    cluster.save()

    with tempfile.TemporaryDirectory() as credentials_path:

        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        service_kubeconfig_path = credentials_path + 'kubectl_config'

        cluster.grafana_address = tasks.create_service_addresses(credentials_path, "prometheus-grafana", "monitoring", cluster.id, service_kubeconfig_path)[0]
        cluster.save()

def prepare_kubeadm_nodes(cluster_id, kubernetes_configuration, skip_machines=[]):
    fix_apt_commands = [
        'sudo dpkg --configure -a',
        'sudo apt --fix-broken install -y',
    ]

    commands = [
        'sudo apt-get install --allow-downgrades --allow-change-held-packages -y kubelet={}-00 kubeadm={}-00'.format(kubernetes_configuration['version'].replace('v', ''), kubernetes_configuration['version'].replace('v', '')),
        "sudo kubeadm reset -f",
    ]

    skip_errors_commands = []

    if kubernetes_configuration['networkPlugin'] == 'flannel':
        skip_errors_commands = [
            'sudo ip link delete cni0',
            'sudo ip link delete flannel.1'
        ]

    machines = Machine.objects.filter(cluster_id=cluster_id).order_by('-publicIP')
    public_ip_gateway = ''

    for machine in machines:
        if machine.publicIP:
            if public_ip_gateway == '':
                public_ip_gateway = machine.publicIP

    machines = machines.exclude(id__in=skip_machines)

    for machine in machines:
        if machine.publicIP:
            if public_ip_gateway == '':
                public_ip_gateway = machine.publicIP
            ssh_client.exec_commands_on_node(node_address=machine.publicIP, commands=fix_apt_commands, skip_errors=True)
            ssh_client.exec_commands_on_node(machine.publicIP, commands, command_retry_attempts=120)
            ssh_client.exec_commands_on_node(node_address=machine.publicIP, commands=skip_errors_commands, skip_errors=True)
        else:
            ssh_client.exec_commands_on_node(node_address=machine.privateIP, commands=fix_apt_commands, gateway_address=public_ip_gateway, skip_errors=True)
            ssh_client.exec_commands_on_node(machine.privateIP, commands, gateway_address=public_ip_gateway, command_retry_attempts=120)
            ssh_client.exec_commands_on_node(node_address=machine.privateIP, commands=skip_errors_commands, gateway_address=public_ip_gateway, skip_errors=True)

def remove_masters_taint(master_machine_public_ip):
    commands = [
        'sudo kubectl --kubeconfig /root/.kube/config taint nodes --all node-role.kubernetes.io/master-',
        'sudo kubectl --kubeconfig /root/.kube/config taint nodes --all node-role.kubernetes.io/control-plane-'
    ]

    ssh_client.exec_commands_on_node(master_machine_public_ip, commands, skip_errors=True)

def init_kubeadm_primary_master(master_machine, kubernetes_configuration):
    commands = [
        'sudo kubeadm init ' +
        ' --control-plane-endpoint $(hostname -I | awk \'{print $1}\') ' +
        ' --apiserver-cert-extra-sans=' + master_machine.publicIP + ' ' +
        ' --upload-certs ' +
        ' --pod-network-cidr ' + kubernetes_configuration['podsSubnet'] +
        ' --service-cidr ' + kubernetes_configuration['serviceAddresses'] +
        ' --node-name ' + master_machine.kube_name +
        ' --kubernetes-version=' + kubernetes_configuration['version'],
        'sudo mkdir -p /root/.kube',
        'sudo cp /etc/kubernetes/admin.conf /root/.kube/config',
        'sudo chown root:root /root/.kube/config',
    ]

    if kubernetes_configuration['networkPlugin'] == 'calico':
        with tempfile.NamedTemporaryFile() as calico_tmp_local_file:
            calico_tmp_local_file.write(CALICO_MANIFEST.encode('utf-8'))

            calico_tmp_remote_file_path = '/tmp/calico.yaml'

            ssh_client.transfer_file(master_machine.publicIP, calico_tmp_local_file.name, calico_tmp_remote_file_path)

            commands.append('sudo kubectl --kubeconfig /root/.kube/config apply -f ' + calico_tmp_remote_file_path)
    elif kubernetes_configuration['networkPlugin'] == 'flannel':
        with tempfile.NamedTemporaryFile() as flannel_tmp_local_file:
            flannel_manifest_data = FLANNEL_MANIFEST.substitute(network = kubernetes_configuration['podsSubnet'])
            flannel_tmp_local_file.write(flannel_manifest_data.encode('utf-8'))

            flannel_tmp_remote_file_path = '/tmp/flannel.yaml'

            ssh_client.transfer_file(master_machine.publicIP, flannel_tmp_local_file.name, flannel_tmp_remote_file_path)

            commands.append('sudo kubectl --kubeconfig /root/.kube/config apply -f ' + flannel_tmp_remote_file_path)
    else:
        raise Exception('Unknown network plugin: ' + kubernetes_configuration['networkPlugin'])

    ssh_client.exec_commands_on_node(master_machine.publicIP, commands)

def get_kubeadm_join_command(master_machine_public_ip):
    commands = [
        'sudo kubeadm --kubeconfig /root/.kube/config token create --print-join-command',
    ]

    join_command = ssh_client.exec_commands_on_node(master_machine_public_ip, commands, return_output=True)[0].rstrip()

    return join_command

def get_kubeadm_certificate_key(master_machine_public_ip):
    commands = [
        'sudo kubeadm init phase upload-certs --upload-certs | tail -n1',
    ]

    certificate_key = ssh_client.exec_commands_on_node(master_machine_public_ip, commands, return_output=True)[0].rstrip()

    return certificate_key

def join_kubeadm_node(node, join_command, is_control_plane, certificate_key='', gateway_address=''):
    commands = []

    if is_control_plane:
        commands.append('sudo ' + join_command + ' --control-plane' + ' --certificate-key ' + certificate_key + ' --node-name ' + node.kube_name)
    else:
        commands.append('sudo ' + join_command + ' --node-name ' + node.kube_name)

    if node.publicIP:
        ssh_client.exec_commands_on_node(node.publicIP, commands, return_output=True)
    else:
        ssh_client.exec_commands_on_node(node.privateIP, commands, return_output=True, gateway_address=gateway_address)

def download_k3s_config(address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    user = 'clouduser'
    command = 'sudo cat /etc/rancher/k3s/k3s.yaml | sed -r \'s/(\\b[0-9]{1,3}\\.){3}[0-9]{1,3}\\b\'/"' + address + '\"/ | sed \'/certificate-authority-data:/d\' | sed \'/server:/i \\ \\ \\ \\ insecure-skip-tls-verify: true\''

    ssh = paramiko.SSHClient()
    key = paramiko.RSAKey.from_private_key_file('/var/.ssh/id_rsa')
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(address, username=user, pkey=key)
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)

    kubeconfig = ssh_stdout

    ssh_stderr_data = ssh_stderr.read()

    if ssh_stderr_data != b'':
        raise Exception('Error downloading kubeconfig: ' + str(ssh_stderr_data))

    cluster.kubeconfig = kubeconfig.read().decode('ascii')
    cluster.save()

def download_kubernetes_config(address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    user = 'clouduser'
    command = 'sudo cat /root/.kube/config | sed -r \'s/(\\b[0-9]{1,3}\\.){3}[0-9]{1,3}\\b\'/"' + address + '\"/'

    ssh = paramiko.SSHClient()
    key = paramiko.RSAKey.from_private_key_file('/var/.ssh/id_rsa')
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(address, username=user, pkey=key)
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)

    kubeconfig = ssh_stdout

    ssh_stderr_data = ssh_stderr.read()

    if ssh_stderr_data != b'':
        raise Exception('Error downloading kubeconfig: ' + str(ssh_stderr_data))

    cluster.kubeconfig = kubeconfig.read().decode('ascii')
    cluster.save()

def download_capi_kubernetes_config(cluster_id):
    cluster = CapiCluster.objects.filter(id=cluster_id)[0]

    command = ['kubectl', '--kubeconfig=/root/.kube/config',
            '-n', 'default', 'get', 'secret']
    command.append(cluster_id + '-kubeconfig')
    command.append('-o')
    command.append('jsonpath=\'{.data.value}\'')

    output = run_shell.run_shell_with_subprocess_popen(command, workdir='./', return_stdout=True)

    kubeconfig = base64.b64decode(output['stdout'][0]).decode('utf-8')

    cluster.kubeconfig = kubeconfig
    cluster.save()

    return

def install_capi_cni_plugin(cluster_id):
    cluster = CapiCluster.objects.filter(id=cluster_id)[0]

    with tempfile.TemporaryDirectory() as credentials_path:
        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        kubeconfig_path = credentials_path + 'kubectl_config'

        command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'apply', '-f']
        command.append('https://docs.projectcalico.org/v3.20/manifests/calico.yaml')

        run_shell.run_shell_with_subprocess_call(command, workdir='./')

    return

def download_yaookcapi_kubernetes_config(cluster_id):
    cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]

    command = 'kubectl --kubeconfig=' + YAOOKCAPI_MANAGEMENT_CLUSTER_KUBECONFIG_PATH + ' -n default get secret ' + cluster_id + '-inventory -o jsonpath="{.data.inventory\\.tar\\.gz}" | base64 -d | tar -xzO inventory/.etc/admin.conf'

    output = run_shell.run_shell_with_subprocess_popen(command, workdir='./', return_stdout=True, shell=True)

    kubeconfig = ''.join(output['stdout'])

    cluster.kubeconfig = kubeconfig
    cluster.save()

    return

def get_yaookcapi_status(cluster_id):
    command = 'kubectl --kubeconfig=' + YAOOKCAPI_MANAGEMENT_CLUSTER_KUBECONFIG_PATH + ' -n default get yaookcluster.yaook.mk8s.io ' + cluster_id + ' -o jsonpath="{.status.phase}"'

    output = run_shell.run_shell_with_subprocess_popen(command, workdir='./', return_stdout=True, shell=True)

    status = ''.join(output['stdout'])

    return status

def wait_for_yaookcapi_cluster(retries, wait_seconds, cluster_id):
    for _ in range(retries):
        status = get_yaookcapi_status(cluster_id).lower()
        if status == 'running':
            return
        # elif status == 'failed':
        #     raise Exception('Cluster failed to start')
        time.sleep(wait_seconds)

    raise Exception('YaookCapi cluster failed to start')

def download_yaookcapi_wireguard_config(cluster_id):
    cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]

    command = 'kubectl --kubeconfig=' + YAOOKCAPI_MANAGEMENT_CLUSTER_KUBECONFIG_PATH + ' -n default get secret ' + cluster_id + '-inventory -o jsonpath="{.data.inventory\.tar\.gz}" | base64 -d | tar -xzO inventory/.etc/wireguard/wg_' + cluster.wireguard_indent + '.conf'

    output = run_shell.run_shell_with_subprocess_popen(command, workdir='./', return_stdout=True, shell=True)
    wireguard_config = ''
    for line in output['stdout']:
        if 'REPLACEME' in line:
            line = line.replace('REPLACEME', cluster.wireguard_private_key)
        wireguard_config += line

    cluster.wireguard_config = wireguard_config
    cluster.save()

    wireguard_user_configs = []

    project_users = Profile.objects.filter(daiteap_user__projects__id=cluster.project.id)

    for project_user in project_users:
        if project_user.wireguard_public_key:
            try:
                command = 'kubectl --kubeconfig=' + YAOOKCAPI_MANAGEMENT_CLUSTER_KUBECONFIG_PATH + ' -n default get secret ' + cluster_id + '-inventory -o jsonpath="{.data.inventory\.tar\.gz}" | base64 -d | tar -xzO inventory/.etc/wireguard/wg_' + str(cluster.id) + '-' + str(project_user.daiteap_user.user.id) + '.conf'
                output = run_shell.run_shell_with_subprocess_popen(command, workdir='./', return_stdout=True, shell=True)
                wireguard_config = ''.join(output['stdout'])
                wireguard_user_configs.append({ str(project_user.daiteap_user.user.id): wireguard_config })
            except Exception as e:
                logger.debug(e)

    cluster.wireguard_user_configs = json.dumps(wireguard_user_configs)
    cluster.save()

    return

def install_yaookcapi_cni_plugin(cluster_id):
    cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]

    with tempfile.TemporaryDirectory() as credentials_path:
        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        kubeconfig_path = credentials_path + 'kubectl_config'

        command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'apply', '-f']
        command.append('https://docs.projectcalico.org/v3.20/manifests/calico.yaml')

        run_shell.run_shell_with_subprocess_call(command, workdir='./')

    return

def install_openstack_csi(cluster_id):
    config = {}
    cluster = Clusters.objects.filter(id=cluster_id)
    if len(cluster) == 0:
        cluster = CapiCluster.objects.filter(id=cluster_id)[0]
        if len(cluster) == 0:
            config = json.loads(cluster.yaookcapi_config)
        else:
            config = json.loads(cluster.capi_config)
    else:
        cluster = cluster[0]
        config = json.loads(cluster.config)

    with tempfile.TemporaryDirectory() as credentials_path:
        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        kubeconfig_path = credentials_path + 'kubectl_config'

        account = CloudAccount.objects.filter(id=config['openstack']['account'], provider='openstack')[0]
        credentials = vault_service.read_secret(account.credentials)
        auth_url = credentials['auth_url']
        application_credential_id = credentials['application_credential_id']
        application_credential_secret = credentials['application_credential_secret']

        with open(credentials_path + 'cloud.conf', 'a') as text_file:
            text_file.write(OPENSTACK_CLOUDS_CONF.format(auth_url, application_credential_id, application_credential_secret))

        command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'create', 'secret', '-n', 'kube-system', 'generic', 'cloud-config', '--from-file=' + credentials_path + 'cloud.conf']

        try:
            run_shell.run_shell_with_subprocess_popen(command, workdir='./')
        except Exception as e:
            print(str(e))
            if 'already exists' not in str(e):
                raise Exception(e)

        files_to_apply = [
            FILE_BASE_DIR + '/../../environment_providers/openstack/cinder-csi-plugin/cinder-csi-controllerplugin-rbac.yaml',
            FILE_BASE_DIR + '/../../environment_providers/openstack/cinder-csi-plugin/cinder-csi-controllerplugin.yaml',
            FILE_BASE_DIR + '/../../environment_providers/openstack/cinder-csi-plugin/cinder-csi-nodeplugin-rbac.yaml',
            FILE_BASE_DIR + '/../../environment_providers/openstack/cinder-csi-plugin/cinder-csi-nodeplugin.yaml',
            FILE_BASE_DIR + '/../../environment_providers/openstack/cinder-csi-plugin/csi-cinder-driver.yaml',
            FILE_BASE_DIR + '/../../environment_providers/openstack/cinder-csi-plugin/storageclass.yaml'
            ]

        for file_to_apply in files_to_apply:
            command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'apply', '-f', file_to_apply]
            run_shell.run_shell_with_subprocess_call(command, workdir='./')

    return

def install_longhorn_storage(cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)
    if len(cluster) == 0:
        cluster = CapiCluster.objects.filter(id=cluster_id)[0]
        if len(cluster) == 0:
            cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
    else:
        cluster = cluster[0]

    with tempfile.TemporaryDirectory() as credentials_path:
        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        kubeconfig_path = credentials_path + 'kubectl_config'

        files_to_apply = [
            os.path.join(settings.BASE_DIR + '/cloudcluster/v1_0_0/manifests/longhorn-iscsi-installation.yaml'),
            os.path.join(settings.BASE_DIR + '/cloudcluster/v1_0_0/manifests/longhorn-storageclass.yaml'),
            ]

        for file_to_apply in files_to_apply:
            command = ['kubectl', '-n', 'kube-system', '--kubeconfig=' + kubeconfig_path, 'apply', '-f', file_to_apply]
            run_shell.run_shell_with_subprocess_call(command, workdir='./')

        command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'apply', '-f', os.path.join(settings.BASE_DIR + '/cloudcluster/v1_0_0/manifests/longhorn.yaml')]

        run_shell.run_shell_with_subprocess_call(command, workdir='./')

        # make longhorn default storage class
        command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'patch', 'storageclass', 'longhorn', '-p', '{"metadata": {"annotations": {"storageclass.kubernetes.io/is-default-class": "true"}}}']
        run_shell.run_shell_with_subprocess_call(command, workdir='./')

        if settings.USE_DNS_FOR_SERVICES:
            cluster.longhorn_username = 'admin'
            cluster.longhorn_password = random_string.get_random_alphanumeric_string(LONGHORN_PASSWORD_LENGTH)
        else:
            cluster.longhorn_username = ''
            cluster.longhorn_password = ''

        cluster.longhorn_address = tasks.create_service_addresses(credentials_path, "longhorn-frontend", "longhorn-system", cluster.id, kubeconfig_path, cluster.longhorn_username, cluster.longhorn_password)[0]
        cluster.save()

    return

def check_if_kubernetes_cluster_is_reachable(cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)
    if len(cluster) == 0:
        cluster = CapiCluster.objects.filter(id=cluster_id)[0]
        if len(cluster) == 0:
            cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
    else:
        cluster = cluster[0]

    with tempfile.TemporaryDirectory() as credentials_path:
        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        kubeconfig_path = credentials_path + 'kubectl_config'

        command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'get', 'nodes']
        run_shell.run_shell_with_subprocess_call(command, workdir='./')

    return

def remove_master_capi_nodes_taint(cluster_id):
    cluster = CapiCluster.objects.filter(id=cluster_id)[0]

    with tempfile.TemporaryDirectory() as credentials_path:
        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        kubeconfig_path = credentials_path + 'kubectl_config'

        command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'taint', 'nodes', '--all', 'node-role.kubernetes.io/master-']

        try:
            run_shell.run_shell_with_subprocess_popen(command, workdir='./')
        except Exception as e:
            print(str(e))
            if 'taint "node-role.kubernetes.io/master" not found' not in str(e):
                raise Exception(e)

    return

def remove_master_yaookcapi_nodes_taint(cluster_id):
    cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]

    with tempfile.TemporaryDirectory() as credentials_path:
        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        kubeconfig_path = credentials_path + 'kubectl_config'

        command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'taint', 'nodes', '--all', 'node-role.kubernetes.io/master-']

        try:
            run_shell.run_shell_with_subprocess_popen(command, workdir='./')
        except Exception as e:
            print(str(e))
            if 'taint "node-role.kubernetes.io/master" not found' not in str(e):
                raise Exception(e)

    return

def install_openstack_ccm(cluster_id):
    cluster = CapiCluster.objects.filter(id=cluster_id)[0]
    if len(cluster) == 0:
        cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]

    config = json.loads(cluster.capi_config)

    with tempfile.TemporaryDirectory() as credentials_path:
        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        kubeconfig_path = credentials_path + 'kubectl_config'

        account = CloudAccount.objects.filter(id=config['openstack']['account'], provider='openstack')[0]
        credentials = vault_service.read_secret(account.credentials)
        auth_url = credentials['auth_url']
        application_credential_id = credentials['application_credential_id']
        application_credential_secret = credentials['application_credential_secret']

        with open(credentials_path + 'cloud.conf', 'a') as text_file:
            text_file.write(OPENSTACK_CLOUDS_CONF.format(auth_url, application_credential_id, application_credential_secret))

        command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'create', 'secret', '-n', 'kube-system', 'generic', 'cloud-config', '--from-file=' + credentials_path + 'cloud.conf']

        try:
            run_shell.run_shell_with_subprocess_popen(command, workdir='./')
        except Exception as e:
            print(str(e))
            if 'already exists' not in str(e):
                raise Exception(e)

        command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'apply', '-f', FILE_BASE_DIR + '/../../environment_providers/openstack/ccm/cloud-controller-manager-roles.yaml']
        run_shell.run_shell_with_subprocess_call(command, workdir='./')

        command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'apply', '-f', FILE_BASE_DIR + '/../../environment_providers/openstack/ccm/cloud-controller-manager-role-bindings.yaml']
        run_shell.run_shell_with_subprocess_call(command, workdir='./')

        command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'apply', '-f', FILE_BASE_DIR + '/../../environment_providers/openstack/ccm/openstack-cloud-controller-manager-ds.yaml']
        run_shell.run_shell_with_subprocess_call(command, workdir='./')

    return

def add_capi_nodes_labels(cluster_id):
    cluster = CapiCluster.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.capi_config)

    with tempfile.TemporaryDirectory() as credentials_path:
        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        kubeconfig_path = credentials_path + 'kubectl_config'

        # get cluster nodes
        command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'get', 'nodes',
                    '-o', 'jsonpath={.items[*].metadata.name}']

        output = run_shell.run_shell_with_subprocess_popen(command, workdir='./', return_stdout=True)

        nodes = output['stdout'][0].split(' ')

        # check if all the nodes are initialized
        if len(nodes) < len(config['openstack']['workerNodes']) + int(config['openstack']['controlPlane']['replicas']):
            raise Exception('Nodes are still initializing')

        # remove the taint from the nodes
        for node in nodes:
            command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'label', 'node', '--overwrite',
                        node, 'provider=openstack']
            
            run_shell.run_shell_with_subprocess_call(command, workdir='./')

    return

def add_yaookcapi_nodes_labels(cluster_id):
    cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.yaookcapi_config)

    with tempfile.TemporaryDirectory() as credentials_path:
        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        kubeconfig_path = credentials_path + 'kubectl_config'

        # get cluster nodes
        command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'get', 'nodes',
                    '-o', 'jsonpath={.items[*].metadata.name}']

        output = run_shell.run_shell_with_subprocess_popen(command, workdir='./', return_stdout=True)

        nodes = output['stdout'][0].split(' ')

        # check if all the nodes are initialized
        if len(nodes) < len(config['openstack']['workerNodes']) + int(config['openstack']['controlPlane']['replicas']):
            raise Exception('Nodes are still initializing')

        # remove the taint from the nodes
        for node in nodes:
            command = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'label', 'node', '--overwrite',
                        node, 'provider=openstack']

            run_shell.run_shell_with_subprocess_call(command, workdir='./')

    return

def add_elk_secrets(resources, ansible_client, gateway_address, user_id, nodes_ips, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    helm = HelmClient()
    helm.namespace = 'logs'
    helm.Helm_DIR = FILE_BASE_DIR + '/helm/'

    es_admin_password = random_string.get_random_alphanumeric_string(ES_PASSWORD_LENGTH)

    cluster.es_admin_password = es_admin_password
    cluster.kibana_address = gateway_address.split("@", 1)[1] + ":" + str(KIBANA_PORT)
    cluster.save()

    dc_node = environment_providers.get_dc_node_from_nodes_ips(nodes_ips, resources)

    ansible_client.run_add_elk_secrets(user_id, str(cluster.id), cluster.title, dc_node, 'logs', cluster.es_admin_password, 'elastic')

    return


def helm_elasticsearch(resources, nodes_count, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    helm = HelmClient()
    helm.namespace = 'logs'
    helm.Helm_DIR = FILE_BASE_DIR + '/helm/'

    storage_class = environment_providers.get_storageclass_name(resources)

    with tempfile.TemporaryDirectory() as credentials_path:
        minimum_master_nodes = 2
        requests_cpu = '\"100m\"'
        requests_memory = '\"1Gi\"'
        if nodes_count < 3:
            replicas = 2
        else:
            replicas = 3

        credentials_path = credentials_path + "/"
        template = Template(elasticsearch_template)
        values_file = template.substitute(
            replicas=replicas,
            minimum_master_nodes=minimum_master_nodes,
            requests_cpu=requests_cpu,
            requests_memory=requests_memory,
            storage_class=storage_class
        )

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)

        os.chmod(credentials_path + 'kubectl_config', 0o700)

        with open(credentials_path + 'values.yaml', 'a') as text_file:
            text_file.write(values_file)

        helm.name = 'elasticsearch'
        helm.chart_name = 'elasticsearch'
        helm.kubeconfig_path = credentials_path + 'kubectl_config'

        helm.install(credentials_path + 'values.yaml')

def helm_kibana(nodes_count, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    helm = HelmClient()
    helm.namespace = 'logs'
    helm.Helm_DIR = FILE_BASE_DIR + '/helm/'

    with tempfile.TemporaryDirectory() as credentials_path:
        if nodes_count < 3:
            requests_cpu = '\"100m\"'
            requests_memory = '\"1Gi\"'
        else:
            requests_cpu = '\"1000m\"'
            requests_memory = '\"2Gi\"'

        kibana_encryption_key = random_string.get_random_alphanumeric_string(50)
        credentials_path = credentials_path + "/"
        template = Template(kibana_template)
        values_file = template.substitute(
            requests_cpu=requests_cpu,
            requests_memory=requests_memory,
            kibana_encryption_key=kibana_encryption_key,
            node_port=KIBANA_PORT
        )

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        with open(credentials_path + 'values.yaml', 'a') as text_file:
            text_file.write(values_file)

        helm.name = 'kibana'
        helm.chart_name = 'kibana'
        helm.kubeconfig_path = credentials_path + 'kubectl_config'

        helm.install(credentials_path + 'values.yaml')

def helm_fluentd(cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    helm = HelmClient()
    helm.namespace = 'logs'
    helm.Helm_DIR = FILE_BASE_DIR + '/helm/'

    with tempfile.TemporaryDirectory() as credentials_path:
        credentials_path = credentials_path + "/"
        template = Template(fluentd_template)

        values_file = template.substitute(
            elastic_password=cluster.es_admin_password
        )

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        with open(credentials_path + 'values.yaml', 'a') as text_file:
            text_file.write(values_file)

        helm.name = 'fluentd'
        helm.chart_name = 'fluentd-elasticsearch'
        helm.kubeconfig_path = credentials_path + 'kubectl_config'

        helm.install(credentials_path + 'values.yaml')

def email_notification(user_id, cluster_id):
    if not DEBUG:
        # Send email notification
        email_client = MailgunClient()
        email_client.email_environment_created(user_id, cluster_id)

def k3s_ansible(ansible_client: AnsibleClient, user_id, gateway_address, cluster_id, dns_servers_ips, resources):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    nodes_addresses = get_nodes_addresses(resources, user_id, cluster)

    master_nodes = []
    worker_nodes = []

    for node in nodes_addresses:
        if node['kube_master']:
            master_nodes.append({'address': node['address'], 'id': node['id']})
        else:
            worker_nodes.append({'address': node['address'], 'id': node['id']})

    if 'kubernetesConfiguration' not in resources:
        resources['kubernetesConfiguration'] = {
            'networkPlugin': 'flannel',
            'podsSubnet': '10.233.64.0/18',
            'serviceAddresses': '10.233.0.0/18',
            'version': SUPPORTED_K3S_VERSIONS[0]
        }

    external_cloud_provider = "false"

    if 'load_balancer_integration' in resources:
        external_cloud_provider = "true"

    resources['kubernetesConfiguration']['external_cloud_provider'] = external_cloud_provider

    ansible_client.run_k3s_ansible(user_id, str(cluster.id), cluster.title, master_nodes, worker_nodes, gateway_address, dns_servers_ips, resources['kubernetesConfiguration'])
