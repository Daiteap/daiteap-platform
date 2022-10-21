import json
import logging
import os
import tempfile
import traceback

from cloudcluster.models import CloudAccount, Clusters, Machine, Tenant
from cloudcluster.v1_0_0.services import random_string, constants
from cloudcluster.v1_0_0.ansible.ansible_client import AnsibleClient
from cloudcluster.v1_0_0 import tasks
from environment_providers import environment_providers

ONPREMISE_SHARED_VPN_PASSWORD_LENGTH = 16

logger = logging.getLogger(__name__)

def create_new_machines(resources, user_id, cluster_id, machines, new_indices_counter, old_machines):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    onpremise_account = CloudAccount.objects.filter(id=resources['onpremise']['account'],tenant__daiteapuser__user_id=user_id, provider='onpremise')[0]

    new_onpremise_nodes = []
    onpremise_nodes = []
    onpremise_nodes.append({'private_ip': onpremise_account.gw_private_ip, 'public_ip': onpremise_account.gw_public_ip, 'user': 'clouduser'})
    for node_private_ip in resources['onpremise']['machines']:
        onpremise_nodes.append({'private_ip': node_private_ip })
    for node_private_ip in machines['onPremiseMachines']:
        onpremise_nodes.append({'private_ip': node_private_ip })
        new_onpremise_nodes.append(node_private_ip)

    try:
        with tempfile.TemporaryDirectory() as credentials_path:
            with open(os.open(credentials_path + 'id_rsa', os.O_CREAT | os.O_WRONLY, 0o600), 'a') as onpremise_account_admin_private_key_file:
                onpremise_account_admin_private_key_file.write(onpremise_account.admin_private_key)
            with open('/var/.ssh/id_rsa.pub') as f:
                app_public_key = f.readlines()[0].rstrip()
        ansible_client = AnsibleClient()
        ansible_client.run_add_ssh_key(user_id, str(cluster.id), cluster.title, app_public_key, 'clouduser', onpremise_account.admin_username, credentials_path + 'id_rsa', onpremise_account.admin_private_key_password, new_onpremise_nodes, onpremise_account.admin_username + "@" + onpremise_account.gw_public_ip)
    except Exception as e:
        cluster.resizestep = -2
        cluster.save()
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_add_machines_to_vms',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
        return

    return {}

def create_resources(resources, user_id, cluster_id, internal_dns_zone, nodes_counter):
    # Add ssh key on instances
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    if 'onpremise' in resources:
        onpremise_nodes = []
        onpremise_account = CloudAccount.objects.filter(id=resources['account'],tenant__daiteapuser__user_id=user_id, provider='onpremise')[0]
        onpremise_nodes.append(onpremise_account.gw_private_ip)
        for node_private_ip in resources['machines']:
            onpremise_nodes.append(node_private_ip)

        with tempfile.TemporaryDirectory() as credentials_path:
            with open(os.open(credentials_path + 'id_rsa', os.O_CREAT | os.O_WRONLY, 0o600), 'a') as onpremise_account_admin_private_key_file:
                onpremise_account_admin_private_key_file.write(onpremise_account.admin_private_key)
            with open('/var/.ssh/id_rsa.pub') as f:
                app_public_key = f.readlines()[0].rstrip()

            ansible_client = AnsibleClient()
            ansible_client.run_add_ssh_key(\
                user_id,
                str(cluster.id),
                cluster.title,
                app_public_key,
                'clouduser',
                onpremise_account.admin_username,
                credentials_path + 'id_rsa',
                onpremise_account.admin_private_key_password,
                onpremise_nodes,
                onpremise_account.admin_username + "@" + onpremise_account.gw_public_ip
            )

    tf_variables = {}

    for supported_provider in environment_providers.supported_providers:
        if supported_provider != 'onpremise':
            shared_secret = {'onpremise' + '_' + supported_provider + '_shared_secret': random_string .get_random_alphanumeric_string(ONPREMISE_SHARED_VPN_PASSWORD_LENGTH)}

            cluster.vpn_secrets = json.dumps(shared_secret)

            cluster.save()

            tf_variables[supported_provider + '_' + 'onpremise' + '_shared_secret'] = shared_secret
            tf_variables[supported_provider + '_' + 'onpremise' + '_network_cidr'] = resources['onpremise']['vpcCidr']
            tf_variables[supported_provider + '_' + 'onpremise' + '_vpn_gateway_internet_ip'] = onpremise_account.gw_public_ip


    return 0, tf_variables

def create_vpn(self):
    pass

def validate_regions_zones_instance_types(provider_data, user, environment_type):
    pass

def get_provider_config_params(payload, user):

    config = {}
    config['onpremise'] = {
        'nodes': len(payload['onpremise']['machines']),
        'operatingSystem': payload['onpremise']['operatingSystem'],
        'machines': payload['onpremise']['machines'],
        'vpcCidr': payload['onpremise']['vpcCidr'],
        'account': payload['onpremise']['account']
    }

    return config

def restart_machine(config, user_id, machine):
    pass

def start_machine(config, user_id, machine):
    pass

def stop_machine(config, user_id, machine):
    pass

def get_nodes(cluster_id, user_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    nodes = {'onpremise': []}

    config = json.loads(cluster.config)
    if 'onpremise' in config:
        onpremise_account = CloudAccount.objects.filter(id=config['onpremise']['account'],tenant__daiteapuser__user_id=user_id, provider='onpremise')[0]
        node = {
            'public_ip': onpremise_account.gw_public_ip,
            'private_ip': onpremise_account.gw_private_ip,
        }

        nodes['onpremise'].append(node)

        for machine in config['onpremise']['machines']:
            node = {
                'private_ip': machine,
            }
            nodes['onpremise'].append(node)

    return nodes

def get_machine_records(resources, environment_provider, cloud, cluster_id, nodes_counter):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    onpremise_nodes_addresses = []

    machines = []

    if 'onpremise' in resources:
        for node in cloud:
            nodes_counter += 1
            if nodes_counter < 10:
                machine_name = (cluster.name + '-node-0' + str(nodes_counter) + '.onpremise')
                onpremise_nodes_addresses.append({'hostname': machine_name, 'private_ip': node['private_ip']})
            else:
                machine_name = (cluster.name + '-node-' + str(nodes_counter) + '.onpremise')
                onpremise_nodes_addresses.append({'hostname': machine_name, 'private_ip': node['private_ip']})
            
            if 'internal_dns_zone' in resources:
                machine_name += '.' + resources['internal_dns_zone']

            cpu = 0
            ram = 0
            hdd = 0

            machine = Machine(
                cluster=cluster,
                name=machine_name,
                provider=environment_provider,
                status=0,
                cpu=cpu,
                ram=ram,
                hdd=hdd
            )

            if 'internal_dns_zone' in resources:
                machine.kube_name = machine_name.replace('.onpremise.' + resources['internal_dns_zone'], '')
            else:
                machine.kube_name = machine_name.replace('.onpremise', '')

            if 'kube_master' in node:
                machine.kube_master = node['kube_master']
            if 'kube_etcd' in node:
                machine.kube_etcd = node['kube_etcd']

            if 'public_ip' in node and node['public_ip']:
                machine.publicIP = node['public_ip']
            if 'operatingSystem' in resources[environment_provider] and resources[environment_provider]['operatingSystem']:
                machine.operating_system = resources[environment_provider]['operatingSystem']
            if 'private_ip' in node and node['private_ip']:
                machine.privateIP = node['private_ip']
            if 'instanceType' in resources[environment_provider] and resources[environment_provider]['instanceType']:
                machine.type = resources[environment_provider]['instanceType']
            if 'region' in node and node['region']:
                machine.region = node['region']
            if 'zone' in node and node['zone']:
                machine.zone = node['zone']
            if 'instance_id' in node and node['instance_id']:
                machine.instance_id = node['instance_id']

            machines.append(machine)
    
    return machines, nodes_counter

def get_tf_code(environment_type):
    return ''

def get_valid_operating_systems(payload, environment_type, user_id):
    if environment_type == constants.ClusterType.CAPI.value:
        # CAPI
        return []
    elif environment_type == constants.ClusterType.DLCM_V2.value:
        # DLCM v2
        return []
    else:
        return [
            {
                'os': "Canonical, Ubuntu, 18.04 LTS, amd64",
                'value': "ubuntu-1804-bionic",
            },
            {
                'os': "Debian, Debian GNU/Linux, 9 (stretch), amd64",
                'value': "debian-9-stretch"
            }
        ]

def update_cloud_credentials(payload, request):
    onpremise = payload['account_params']

    if 'label' in onpremise and 'old_label' in onpremise:
        if onpremise['old_label'] == '' or len(onpremise['old_label']) < 3 or len(onpremise['old_label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter old_label.', extra=log_data)
            raise Exception('Invalid parameter old_label.')

        if onpremise['label'] != '' and len(onpremise['label']) < 3 or len(onpremise['label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter label.', extra=log_data)
            raise Exception('Invalid parameter label.')

        if onpremise['label'] != '':
            try:
                account = CloudAccount.objects.filter(id=onpremise['old_label'],tenant_id=request.daiteap_user.tenant_id, provider='onpremise')[0]
                new_account = False
                account.label = onpremise['label']
            except:
                new_account = True
                account = CloudAccount(
                    label=onpremise['label']
                )

            if ((new_account and len(CloudAccount.objects.filter(id=onpremise['label'],tenant_id=request.daiteap_user.tenant_id, provider='onpremise')) > 0) or
                (not new_account and onpremise['label'] != onpremise['old_label'] and 
                len(CloudAccount.objects.filter(id=onpremise['label'],tenant_id=request.daiteap_user.tenant_id, provider='onpremise')) > 0)
            ):
                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                }
                logger.error('Invalid parameter label.', extra=log_data)
                raise Exception('Invalid parameter label.')

            if new_account:
                account.save()

            if 'gw_public_ip' in onpremise:
                if onpremise['gw_public_ip'] != '**********' and onpremise['gw_public_ip'] != '' and len(onpremise['gw_public_ip']) < 7 or len(onpremise['gw_public_ip']) > 15:
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                    }
                    logger.error('Invalid parameter gw_public_ip.', extra=log_data)
                    raise Exception('Invalid parameter gw_public_ip.')
                if onpremise["gw_public_ip"] != "**********":
                    account.gw_public_ip = onpremise["gw_public_ip"]

            if 'gw_private_ip' in onpremise:
                if onpremise['gw_private_ip'] != '**********' and onpremise['gw_private_ip'] != '' and len(onpremise['gw_private_ip']) < 7 or len(onpremise['gw_private_ip']) > 15:
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                    }
                    logger.error('Invalid parameter gw_private_ip.', extra=log_data)
                    raise Exception('Invalid parameter gw_private_ip.')
                if onpremise["gw_private_ip"] != "**********":
                    account.gw_private_ip = onpremise["gw_private_ip"]

            if 'admin_username' in onpremise:
                if onpremise['admin_username'] != '**********' and onpremise['admin_username'] != '' and (len(onpremise['admin_username']) > 36 or len(onpremise['admin_username']) < 3):
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                    }
                    logger.error('Invalid parameter admin_username.', extra=log_data)
                    raise Exception('Invalid parameter admin_username.')
                if onpremise["admin_username"] != "**********":
                    account.admin_username = onpremise["admin_username"]

            if 'admin_private_key' in onpremise:
                if onpremise['admin_private_key'] != '**********' and onpremise['admin_private_key'] != '' and len(onpremise['admin_private_key']) < 3:
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                    }
                    logger.error('Invalid parameter admin_private_key.', extra=log_data)
                    raise Exception('Invalid parameter admin_private_key.')
                if onpremise["admin_private_key"] != "**********":
                    account.admin_private_key = onpremise["admin_private_key"]

    else:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error('Invalid account_params parameter.', extra=log_data)
        raise Exception('Invalid account_params parameter.')

    account.regions_update_status = 1  # updating
    account.save()
    if not new_account and onpremise['label'] != onpremise['old_label']:
        clusters = Clusters.objects.filter(user=request.user.username)
        for cluster in clusters:
            config = json.loads(cluster.config)
            if 'onpremise' not in config:
                continue
            if config['onpremise']['account'] == onpremise['old_label']:
                config['onpremise']['account'] = onpremise['label']
                cluster.config = json.dumps(config)
                cluster.save()
    tasks.worker_update_provider_regions.delay('onpremise', request.user.id, account.id)

def create_cloud_credentials(payload, request, all_account_labels):
    onpremise = payload['account_params']

    if ('label' in onpremise and 
        'gw_public_ip' in onpremise and
        'gw_private_ip' in onpremise and
        'admin_username' in onpremise and
        'admin_private_key' in onpremise):

        if onpremise['label'] != '' and len(onpremise['label']) < 3 or len(onpremise['label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter label.', extra=log_data)
            raise Exception('Invalid parameter label.')

        if onpremise['gw_public_ip'] != '' and len(onpremise['gw_public_ip']) < 7 or len(onpremise['gw_public_ip']) > 15:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter gw_public_ip.', extra=log_data)
            raise Exception('Invalid parameter gw_public_ip.')

        if len(onpremise['gw_private_ip']) < 7 or len(onpremise['gw_private_ip']) > 15:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter gw_private_ip.', extra=log_data)
            raise Exception('Invalid parameter gw_private_ip.')

        if len(onpremise['admin_username']) > 36 or len(onpremise['admin_username']) < 3:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter admin_username.', extra=log_data)
            raise Exception('Invalid parameter admin_username.')

        if len(onpremise['admin_private_key']) < 3:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter admin_private_key.', extra=log_data)
            raise Exception('Invalid parameter admin_private_key.')

        if 'admin_private_key_password' in onpremise:
            if len(onpremise['admin_private_key_password']) < 3:
                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                }
                logger.error('Invalid parameter admin_private_key_password.', extra=log_data)
                raise Exception('Invalid parameter admin_private_key_password.')

        if onpremise['label'] != '':
            if onpremise['label'] in all_account_labels:
                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                }
                logger.error('Account label already exists.', extra=log_data)
                raise Exception('Account label already exists.')

            account = CloudAccount(
                label=onpremise['label'],
                tenant=Tenant.objects.filter(id=request.daiteap_user.tenant_id)[0],
                provider='onpremise',
                contact=request.user.email,
                description=onpremise['description']
            )
            
            account.user = request.user
            account.save()
            account.gw_public_ip = onpremise["gw_public_ip"]
            account.gw_private_ip = onpremise["gw_private_ip"]
            account.admin_username = onpremise["admin_username"]
            account.admin_private_key = onpremise["admin_private_key"]

            if 'admin_private_key_password' in onpremise:
                account.admin_private_key_password = onpremise["admin_private_key_password"]

    else:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error('Invalid account_params parameter.', extra=log_data)
        raise Exception('Invalid account_params parameter.')

    account.regions_update_status = 0
    account.save()

    tasks.worker_update_provider_regions.delay('onpremise', request.user.id, account.id)

def get_gateway_address_dc_private_ip_and_client_hosts(clouds, master_private_ip, gateway_address, client_hosts, config, user_id):
    if 'onpremise' in config and gateway_address == '':
        onpremise_account = CloudAccount.objects.filter(id=config['onpremise']['account'],tenant__daiteapuser__user_id=user_id, provider='onpremise')[0]
        master_private_ip = onpremise_account.admin_username + '@' + onpremise_account.gw_private_ip
        gateway_address = onpremise_account.admin_username + '@' + onpremise_account.gw_public_ip
        client_hosts.append({'private_ip': onpremise_account.gw_private_ip})

        for onpremise_node in config['onpremise']['machines']:
            client_hosts.append({'private_ip': onpremise_node})

    return master_private_ip, gateway_address, client_hosts

def validate_account_permissions(credentials, user_id, storage_enabled):
    return None

def stop_all_machines(cluster_id):
    pass

def start_all_machines(cluster_id):
    pass

def restart_all_machines(cluster_id):
    pass

def run_nodes_labels(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    provider_nodes = []
    provider_lb_nodes = []
    provider_id = ''
    provider = 'onpremise'

    for node in clouds['onpremise']:
        provider_nodes.append(node['name'])

    ansible_client = AnsibleClient()
    ansible_client.run_nodes_labels(user_id, str(cluster.id), cluster.title, master_ip, provider_nodes, provider_lb_nodes, provider_id, gateway_address, provider)

def run_vpn_server(filtered_environment_providers, vpn_configs, resources, cluster_id, user_id):
    if 'onpremise' in filtered_environment_providers and len(filtered_environment_providers) > 1:
        cluster = Clusters.objects.filter(id=cluster_id)[0]

        vpn_providers = environment_providers.set_vpn_configs(filtered_environment_providers, vpn_configs, resources, cluster_id, user_id, 'onpremise')

        onpremise_account = CloudAccount.objects.filter(id=resources['onpremise']['account'],tenant__daiteapuser__user_id=user_id, provider='onpremise')[0]

        ansible_client = AnsibleClient()
        ansible_client.run_vpn_server(user_id, str(cluster.id), cluster.title, 'clouduser' + "@" + onpremise_account.gw_public_ip, onpremise_account.gw_public_ip, resources['onpremise']['vpcCidr'], vpn_providers)

def run_vpn_routing(resources, user_id, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    vpn_provider_networks = environment_providers.get_vpn_provider_networks(resources, ['onpremise'])

    onpremise_nodes_addresses = []

    onpremise_account = CloudAccount.objects.filter(id=resources['onpremise']['account'],tenant__daiteapuser__user_id=user_id, provider='onpremise')[0]

    onpremise_nodes_addresses.append('clouduser' + '@' + onpremise_account.gw_private_ip)

    for node in resources['onpremise']['machines']:
        onpremise_nodes_addresses.append('clouduser' + '@' + node)

    if onpremise_nodes_addresses:
        ansible_client = AnsibleClient()
        ansible_client.run_vpn_routing(user_id, str(cluster.id), cluster.title, 'clouduser' + "@" + onpremise_account.gw_public_ip, onpremise_account.gw_private_ip, vpn_provider_networks, onpremise_nodes_addresses)

def run_added_machines_vpn_routing(resources, user_id, cluster_id, new_machines):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    vpn_provider_networks = environment_providers.get_vpn_provider_networks(resources, ['onpremise'])

    onpremise_account = CloudAccount.objects.filter(id=resources['onpremise']['account'],tenant__daiteapuser__user_id=user_id, provider='onpremise')[0]

    ansible_client = AnsibleClient()
    ansible_client.run_vpn_routing(user_id, str(cluster.id), cluster.title, 'clouduser' + "@" + onpremise_account.gw_public_ip, onpremise_account.gw_private_ip, vpn_provider_networks, new_machines['onPremiseMachines'])

def set_vpn_configs(vpn_configs, resources, vpn_secrets, vpn_provider_name, user_id):
    onpremise_account = CloudAccount.objects.filter(id=resources['onpremise']['account'],tenant__daiteapuser__user_id=user_id, provider='onpremise')[0]
    vpn_provider = [{"remote_public_ip": onpremise_account.gw_public_ip, "remote_right_id": onpremise_account.gw_private_ip, "remote_subnet": resources['onpremise']['vpcCidr'], "provider_name": "onpremise", "key_exchange_version": "ikev2", "pre_shared_key": vpn_secrets[vpn_provider_name + '_onpremise_shared_secret']}]
    return vpn_provider

def get_dns_config(resources, nodes_ips, dns_servers_ips, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    machines = Machine.objects.filter(cluster=cluster)

    dns_server_nodes_addresses = []
    for machine in machines:
        if machine.provider == 'onpremise':
            dns_server_nodes_addresses.append({'hostname': machine.name, 'private_ip': machine.privateIP})

    internal_dns_zone = resources['internal_dns_zone']
    server_private_ip = nodes_ips['google_server_private_ip']
    server_ip = dns_servers_ips['google_server_ip']

    dns_config = {
        'onpremise': {
        'name': 'onpremise',
        'publicDnsServer': f'server=/onpremise.{ internal_dns_zone }/{ server_private_ip }\n',
        'privateDnsServer': f'server=/onpremise.{ internal_dns_zone }/{ server_private_ip }\n',
        "lastDnsServer": "server=/#/8.8.8.8",
        'groups': 'onpremise-server-node',
        'serverName': f'{ server_ip }',
        'dns_server_nodes_addresses': dns_server_nodes_addresses
    }}

    return dns_config

def update_provider_regions(account_id, user_id):
    return

def add_new_machines_to_resources(machines, resources):
    for _ in range(machines['nodes']):
        resources[machines['provider']]['machines'] += machines['onpremiseMachines']

    return resources

def run_add_dns_address(machines, new_nodes_privateips, clouds, user_id, cluster, server_private_ip, gateway_address):
    ansible_client = AnsibleClient()

    machines = Machine.objects.filter(cluster=cluster, provider='onpremise')

    onpremise_new_nodes = []

    for machine in machines:
        if machine.privateIP in new_nodes_privateips:
            onpremise_new_nodes.append({'private_ip': machine.privateIP, 'hostname': machine.name})

    try:
        ansible_client.run_add_dns_address(user_id, str(cluster.id), cluster.title, onpremise_new_nodes, server_private_ip, gateway_address)
    except Exception as e:
        cluster = Clusters.objects.filter(id=cluster.id)[0]
        cluster.resizestep = -5
        cluster.save()
        log_data = {
            'client_request': json.dumps(machines),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_add_machines_to_vms',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
        return

def run_dns(resources, nodes_ips, dns_servers_ips, cluster_id, user_id, gateway_address, providers_dns_configs, supported_provider, v2):
    dns_servers = environment_providers.get_ansible_dns_servers(supported_provider, resources, providers_dns_configs)

    ansible_client = AnsibleClient()
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    ansible_client.run_dns(user_id, str(cluster.id), cluster.title, nodes_ips, dns_servers, gateway_address, dns_servers_ips, json.loads(cluster.config)['internal_dns_zone'], supported_provider, v2=v2)

def get_user_friendly_params(provider_config, is_capi = False, is_yaookcapi = False):
    return provider_config

def get_storage_buckets(payload, request):
    return {}

def create_storage_bucket(payload, request):
    return {}

def delete_storage_bucket(payload, request):
    return {}

def get_bucket_files(payload, request):
    return {}

def add_bucket_file(payload, request):
    return {}

def delete_bucket_file(payload, request):
    return {}

def download_bucket_file(payload, request):
    return {}

def get_storage_accounts(payload, request):
    return {}

def delete_bucket_folder(payload, request):
    return {}

def get_bucket_details(payload, request):
    return {}

def get_cloud_account_info(cloud_account):
    return {}