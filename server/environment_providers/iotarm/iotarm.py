from environment_providers import environment_providers
import json
import logging
import os
import tempfile
import traceback

from cloudcluster.models import CloudAccount, Clusters, Machine, Tenant
from cloudcluster.v1_0_0.services import random_string
from cloudcluster.v1_0_0.ansible.ansible_client import AnsibleClient
from cloudcluster.v1_0_0 import tasks
from cloudcluster.v1_0_0.services import vault_service, constants
import cloudcluster.v1_0_0.views as views

IOTARM_SHARED_VPN_PASSWORD_LENGTH = 16

logger = logging.getLogger(__name__)

def create_new_machines(resources, user_id, cluster_id, machines, new_indices_counter, old_machines):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    iotarm_account = CloudAccount.objects.filter(id=resources['iotarm']['account'],tenant__daiteapuser__user_id=user_id)[0]
    iotarm_account_credentials = vault_service.read_secret(iotarm_account.credentials)
    new_iotarm_nodes = []
    iotarm_nodes = []
    iotarm_nodes.append({'private_ip': iotarm_account_credentials['gw_private_ip'], 'public_ip': iotarm_account_credentials['gw_public_ip'], 'user': 'clouduser'})
    for node_private_ip in resources['iotarm']['machines']:
        iotarm_nodes.append({'private_ip': node_private_ip })
    for node_private_ip in machines['iotarmMachines']:
        iotarm_nodes.append({'private_ip': node_private_ip })
        new_iotarm_nodes.append(node_private_ip)

    try:
        with tempfile.TemporaryDirectory() as credentials_path:
            with open(os.open(credentials_path + 'id_rsa', os.O_CREAT | os.O_WRONLY, 0o600), 'a') as iotarm_account_admin_private_key_file:
                iotarm_account_admin_private_key_file.write(iotarm_account_credentials['admin_private_key'])
            with open('/var/.ssh/id_rsa.pub') as f:
                app_public_key = f.readlines()[0].rstrip()
            ansible_client = AnsibleClient()

            admin_private_key_password = ''
            if 'admin_private_key_password' in iotarm_account_credentials:
                admin_private_key_password = iotarm_account_credentials['admin_private_key_password']

            ansible_client.run_add_ssh_key(user_id,
                                           str(cluster.id),
                                           cluster.title,
                                           app_public_key,
                                           'clouduser',
                                           iotarm_account_credentials['admin_username'],
                                           credentials_path + 'id_rsa',
                                           admin_private_key_password,
                                           new_iotarm_nodes,
                                           iotarm_account_credentials['admin_username'] + "@" + iotarm_account_credentials['gw_public_ip']
            )
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
    iotarm_nodes = []
    iotarm_account = CloudAccount.objects.filter(id=resources['account'],tenant__daiteapuser__user_id=user_id)[0]
    iotarm_account_credentials = vault_service.read_secret(iotarm_account.credentials)
    iotarm_nodes.append(iotarm_account_credentials['gw_private_ip'])
    for node_private_ip in resources['machines']:
        iotarm_nodes.append(node_private_ip)

    with tempfile.TemporaryDirectory() as credentials_path:
        with open(os.open(credentials_path + 'id_rsa', os.O_CREAT | os.O_WRONLY, 0o600), 'a') as iotarm_account_admin_private_key_file:
            iotarm_account_admin_private_key_file.write(iotarm_account_credentials['admin_private_key'])
        with open('/var/.ssh/id_rsa.pub') as f:
            app_public_key = f.readlines()[0].rstrip()

        ansible_client = AnsibleClient()
        admin_private_key_password = ''
        if 'admin_private_key_password' in iotarm_account_credentials:
            admin_private_key_password = iotarm_account_credentials['admin_private_key_password']
        ansible_client.run_add_ssh_key(\
            user_id,
            str(cluster.id),
            cluster.title,
            app_public_key,
            'clouduser',
            iotarm_account_credentials['admin_username'],
            credentials_path + 'id_rsa',
            admin_private_key_password,
            iotarm_nodes, iotarm_account_credentials['admin_username'] + "@" + iotarm_account_credentials['gw_public_ip']
        )

    tf_variables = {}


    config = json.loads(cluster.config)

    for supported_provider in environment_providers.supported_providers:
        if supported_provider != 'iotarm' and supported_provider in config:
            shared_secret = {'iotarm' + '_' + supported_provider + '_shared_secret': random_string .get_random_alphanumeric_string(IOTARM_SHARED_VPN_PASSWORD_LENGTH)}

            cluster.vpn_secrets = json.dumps(shared_secret)

            cluster.save()

            tf_variables[supported_provider + '_' + 'iotarm' + '_shared_secret'] = shared_secret
            tf_variables[supported_provider + '_' + 'iotarm' + '_network_cidr'] = resources['vpcCidr']
            tf_variables[supported_provider + '_' + 'iotarm' + '_vpn_gateway_internet_ip'] = iotarm_account_credentials['gw_public_ip']


    return 1 + len(resources['machines']), tf_variables

def create_vpn(self):
    pass

def validate_regions_zones_instance_types(provider_data, user, environment_type):
    pass

def get_provider_config_params(payload, user):
    account = CloudAccount.objects.filter(id=payload['iotarm']['account'],tenant__daiteapuser__user=user)[0]
    iotarm_account_credentials = vault_service.read_secret(account.credentials)

    payload['iotarm']['vpcCidr'] = iotarm_account_credentials['network_cidr']

    config = {}
    config['iotarm'] = {
        'nodes': len(payload['iotarm']['machines']),
        'operatingSystem': payload['iotarm']['operatingSystem'],
        'machines': payload['iotarm']['machines'],
        'vpcCidr': payload['iotarm']['vpcCidr'],
        'account': payload['iotarm']['account']
    }

    return config

def restart_machine(config, user_id, machine):
    # TODO: Implement this method
    pass

def start_machine(config, user_id, machine):
    # TODO: Implement this method
    pass

def stop_machine(config, user_id, machine):
    # TODO: Implement this method
    pass

def get_nodes(cluster_id, user_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    nodes = {'iotarm': []}

    config = json.loads(cluster.config)
    if 'iotarm' in config:
        iotarm_account = CloudAccount.objects.filter(id=config['iotarm']['account'],tenant__daiteapuser__user_id=user_id)[0]
        iotarm_account_credentials = vault_service.read_secret(iotarm_account.credentials)
        node = {
            'user': 'clouduser',
            'public_ip': iotarm_account_credentials['gw_public_ip'],
            'private_ip': iotarm_account_credentials['gw_private_ip'],
        }

        nodes['iotarm'].append(node)

        for machine in config['iotarm']['machines']:
            node = {
                'user': 'clouduser',
                'private_ip': machine,
            }
            nodes['iotarm'].append(node)

    return nodes

def get_machine_records(resources, environment_provider, cloud, cluster_id, nodes_counter):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    iotarm_nodes_addresses = []

    machines = []

    if 'iotarm' in resources:
        for node in cloud:
            nodes_counter += 1
            if nodes_counter < 10:
                machine_name = (cluster.name + '-node-0' + str(nodes_counter) + '.iotarm')
                iotarm_nodes_addresses.append({'hostname': machine_name, 'private_ip': node['private_ip']})
            else:
                machine_name = (cluster.name + '-node-' + str(nodes_counter) + '.iotarm')
                iotarm_nodes_addresses.append({'hostname': machine_name, 'private_ip': node['private_ip']})

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
                machine.kube_name = machine_name.replace('.iotarm.' + resources['internal_dns_zone'], '')
            else:
                machine.kube_name = machine_name.replace('.iotarm', '')

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
    iotarm_account = CloudAccount.objects.filter(id=payload['accountId'], provider='iotarm')[0]
    iotarm_account_credentials = vault_service.read_secret(iotarm_account.credentials)

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
                'vpcCidr': iotarm_account_credentials['network_cidr']
            },
            {
                'os': "Debian, Debian GNU/Linux, 9 (stretch), amd64",
                'value': "debian-9-stretch",
                'vpcCidr': iotarm_account_credentials['network_cidr']
            }
        ]

def update_cloud_credentials(payload, request):
    iotarm = payload['account_params']

    if 'label' in iotarm and 'old_label' in iotarm:
        if iotarm['old_label'] == '' or len(iotarm['old_label']) < 3 or len(iotarm['old_label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter old_label.', extra=log_data)
            raise Exception('Invalid parameter old_label.')

        if iotarm['label'] != '' and len(iotarm['label']) < 3 or len(iotarm['label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter label.', extra=log_data)
            raise Exception('Invalid parameter label.')

        if iotarm['label'] != '':
            try:
                account = CloudAccount.objects.filter(id=iotarm['old_label'],tenant_id=request.daiteap_user.tenant_id)[0]
                iotarm_account_credentials = vault_service.read_secret(account.credentials)
                new_account = False
                account.label = iotarm['label']
            except:
                new_account = True
                account = CloudAccount(
                    label=iotarm['label']
                )

            if ((new_account and len(CloudAccount.objects.filter(id=iotarm['label'],tenant_id=request.daiteap_user.tenant_id)) > 0) or
                (not new_account and iotarm['label'] != iotarm['old_label'] and 
                len(CloudAccount.objects.filter(id=iotarm['label'],tenant_id=request.daiteap_user.tenant_id)) > 0)
            ):
                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                }
                logger.error('Invalid parameter label.', extra=log_data)
                raise Exception('Invalid parameter label.')

            if new_account:
                account.save()

            if 'gw_public_ip' in iotarm:
                if iotarm['gw_public_ip'] != '**********' and iotarm['gw_public_ip'] != '' and len(iotarm['gw_public_ip']) < 7 or len(iotarm['gw_public_ip']) > 15:
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                    }
                    logger.error('Invalid parameter gw_public_ip.', extra=log_data)
                    raise Exception('Invalid parameter gw_public_ip.')
                if iotarm["gw_public_ip"] != "**********":
                    iotarm_account_credentials['gw_public_ip'] = iotarm["gw_public_ip"]

            if 'gw_private_ip' in iotarm:
                if iotarm['gw_private_ip'] != '**********' and iotarm['gw_private_ip'] != '' and len(iotarm['gw_private_ip']) < 7 or len(iotarm['gw_private_ip']) > 15:
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                    }
                    logger.error('Invalid parameter gw_private_ip.', extra=log_data)
                    raise Exception('Invalid parameter gw_private_ip.')
                if iotarm["gw_private_ip"] != "**********":
                    iotarm_account_credentials['gw_private_ip'] = iotarm["gw_private_ip"]

            if 'admin_username' in iotarm:
                if iotarm['admin_username'] != '**********' and iotarm['admin_username'] != '' and (len(iotarm['admin_username']) > 36 or len(iotarm['admin_username']) < 3):
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                    }
                    logger.error('Invalid parameter admin_username.', extra=log_data)
                    raise Exception('Invalid parameter admin_username.')
                if iotarm["admin_username"] != "**********":
                    iotarm_account_credentials['admin_username'] = iotarm["admin_username"]

            if 'admin_private_key' in iotarm:
                if iotarm['admin_private_key'] != '**********' and iotarm['admin_private_key'] != '' and len(iotarm['admin_private_key']) < 3:
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                    }
                    logger.error('Invalid parameter admin_private_key.', extra=log_data)
                    raise Exception('Invalid parameter admin_private_key.')
                if iotarm["admin_private_key"] != "**********":
                    iotarm_account_credentials['admin_private_key'] = iotarm["admin_private_key"]

    else:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error('Invalid account_params parameter.', extra=log_data)
        raise Exception('Invalid account_params parameter.')

    account.regions_update_status = 1  # updating
    account.save()
    if not new_account and iotarm['label'] != iotarm['old_label']:
        clusters = Clusters.objects.filter(user=request.user.username)
        for cluster in clusters:
            config = json.loads(cluster.config)
            if 'iotarm' not in config:
                continue
            if config['iotarm']['account'] == iotarm['old_label']:
                config['iotarm']['account'] = iotarm['label']
                cluster.config = json.dumps(config)
                cluster.save()

def create_cloud_credentials(payload, request, all_account_labels):
    iotarm = payload['account_params']

    if ('label' in iotarm and 
        'gw_public_ip' in iotarm and
        'gw_private_ip' in iotarm and
        'vpcCidr' in iotarm and
        'admin_username' in iotarm and
        'admin_private_key' in iotarm):

        ip_in_network = views.check_ip_in_network(iotarm['vpcCidr'], iotarm['gw_private_ip'])

        if not ip_in_network:
            raise Exception('Private ip is not the network')

        if iotarm['label'] != '' and len(iotarm['label']) < 3 or len(iotarm['label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter label.', extra=log_data)
            raise Exception('Invalid parameter label.')

        if iotarm['gw_public_ip'] != '' and len(iotarm['gw_public_ip']) < 7 or len(iotarm['gw_public_ip']) > 15:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter gw_public_ip.', extra=log_data)
            raise Exception('Invalid parameter gw_public_ip.')

        if len(iotarm['gw_private_ip']) < 7 or len(iotarm['gw_private_ip']) > 15:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter gw_private_ip.', extra=log_data)
            raise Exception('Invalid parameter gw_private_ip.')

        if len(iotarm['admin_username']) > 36 or len(iotarm['admin_username']) < 3:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter admin_username.', extra=log_data)
            raise Exception('Invalid parameter admin_username.')

        if len(iotarm['admin_private_key']) < 3:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter admin_private_key.', extra=log_data)
            raise Exception('Invalid parameter admin_private_key.')

        if 'admin_private_key_password' in iotarm:
            if len(iotarm['admin_private_key_password']) < 3:
                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                }
                logger.error('Invalid parameter admin_private_key_password.', extra=log_data)
                raise Exception('Invalid parameter admin_private_key_password.')

        if len(iotarm['vpcCidr']) > 25 or len(iotarm['vpcCidr']) < 8:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter vpcCidr.', extra=log_data)
            raise Exception('Invalid parameter vpcCidr.')


        if iotarm['label'] != '':
            if iotarm['label'] in all_account_labels:
                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                }
                logger.error('Account label already exists.', extra=log_data)
                raise Exception('Account label already exists.')

            account = CloudAccount(
                label=iotarm['label'],
                tenant=Tenant.objects.filter(id=request.daiteap_user.tenant_id)[0],
                provider='iotarm',
                contact=request.user.email,
                description=iotarm['description']
            )

            credentials = {}
            credentials['gw_public_ip'] = iotarm["gw_public_ip"]
            credentials['gw_private_ip'] = iotarm["gw_private_ip"]
            credentials['network_cidr'] = iotarm["vpcCidr"]
            credentials['admin_username'] = iotarm["admin_username"]
            credentials['admin_private_key'] = iotarm["admin_private_key"]

            if 'admin_private_key_password' in iotarm:
                credentials['admin_private_key_password'] = iotarm["admin_private_key_password"]

            account.credentials = "none"
            account.user = request.user

            account.save()

            try:
                credentials_path = f"secret/{request.daiteap_user.tenant_id}/{account.id}/credentials"
                vault_service.upsert_secret(credentials_path, credentials)

                account.credentials = credentials_path
                account.save()

            except Exception as e:
                account.delete()
                raise Exception(e)

    else:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error('Invalid account_params parameter.', extra=log_data)
        raise Exception('Invalid account_params parameter.')

    account.regions_update_status = 0
    account.save()

def get_gateway_address_dc_private_ip_and_client_hosts(clouds, master_private_ip, gateway_address, client_hosts, config, user_id):
    if 'iotarm' in config and gateway_address == '':
        iotarm_account = CloudAccount.objects.filter(id=config['iotarm']['account'],tenant__daiteapuser__user_id=user_id)[0]
        iotarm_account_credentials = vault_service.read_secret(iotarm_account.credentials)
        master_private_ip = iotarm_account_credentials['admin_username'] + '@' + iotarm_account_credentials['gw_private_ip']
        gateway_address = iotarm_account_credentials['admin_username'] + '@' + iotarm_account_credentials['gw_public_ip']
        client_hosts.append({'private_ip': iotarm_account_credentials['gw_private_ip']})

        for iotarm_node in config['iotarm']['machines']:
            client_hosts.append({'private_ip': iotarm_node})

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
    provider = 'iotarm'

    cluster_machines = Machine.objects.filter(cluster=cluster)

    clouds['iotarm'] = []

    for cluster_machine in cluster_machines:
        if cluster_machine.provider == 'iotarm':
            node = {
                'user': 'clouduser',
                'public_ip': cluster_machine.publicIP,
                'private_ip': cluster_machine.privateIP, 
                'name': cluster_machine.kube_name
            }

            clouds['iotarm'].append(node)

    for node in clouds['iotarm']:
        provider_nodes.append(node['name'])

    ansible_client = AnsibleClient()
    ansible_client.run_nodes_labels(user_id, str(cluster.id), cluster.title, master_ip, provider_nodes, provider_lb_nodes, provider_id, gateway_address, provider)

def run_vpn_server(filtered_environment_providers, vpn_configs, resources, cluster_id, user_id):
    if 'iotarm' in filtered_environment_providers and len(filtered_environment_providers) > 1:
        cluster = Clusters.objects.filter(id=cluster_id)[0]

        vpn_providers = environment_providers.set_vpn_configs(filtered_environment_providers, vpn_configs, resources, cluster_id, user_id, 'iotarm')

        iotarm_account = CloudAccount.objects.filter(id=resources['iotarm']['account'],tenant__daiteapuser__user_id=user_id)[0]
        iotarm_account_credentials = vault_service.read_secret(iotarm_account.credentials)

        ansible_client = AnsibleClient()
        ansible_client.run_vpn_server(user_id, str(cluster.id), cluster.title, 'clouduser' + "@" + iotarm_account_credentials['gw_public_ip'], iotarm_account_credentials['gw_public_ip'], resources['iotarm']['vpcCidr'], vpn_providers)

def run_vpn_routing(resources, user_id, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    vpn_provider_networks = environment_providers.get_vpn_provider_networks(resources, ['iotarm'])

    iotarm_nodes_addresses = []

    iotarm_account = CloudAccount.objects.filter(
        label=resources['iotarm']['account'], tenant__daiteapuser__user_id=user_id)[0]
    iotarm_account_credentials = vault_service.read_secret(iotarm_account.credentials)

    iotarm_nodes_addresses.append(
        'clouduser' + '@' + iotarm_account_credentials['gw_private_ip'])

    for node in resources['iotarm']['machines']:
        iotarm_nodes_addresses.append('clouduser' + '@' + node)

    if iotarm_nodes_addresses:
        ansible_client = AnsibleClient()
        ansible_client.run_vpn_routing(user_id,
                                        str(cluster.id),
                                        cluster.title,
                                        'clouduser' + "@" + iotarm_account_credentials['gw_public_ip'],
                                        iotarm_account_credentials['gw_private_ip'],
                                        vpn_provider_networks,
                                        iotarm_nodes_addresses
                                        )

def run_added_machines_vpn_routing(resources, user_id, cluster_id, new_machines):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    vpn_provider_networks = environment_providers.get_vpn_provider_networks(resources, ['iotarm'])

    iotarm_account = CloudAccount.objects.filter(id=resources['iotarm']['account'],tenant__daiteapuser__user_id=user_id)[0]
    iotarm_account_credentials = vault_service.read_secret(iotarm_account.credentials)

    ansible_client = AnsibleClient()
    ansible_client.run_vpn_routing(user_id, str(cluster.id), cluster.title, 'clouduser' + "@" + iotarm_account_credentials['gw_public_ip'], iotarm_account_credentials['gw_private_ip'], vpn_provider_networks, new_machines['iotarmMachines'])


def set_vpn_configs(vpn_configs, resources, vpn_secrets, vpn_provider_name, user_id):
    iotarm_account = CloudAccount.objects.filter(id=resources['iotarm']['account'],tenant__daiteapuser__user_id=user_id)[0]
    iotarm_account_credentials = vault_service.read_secret(iotarm_account.credentials)
    vpn_provider = [{"remote_public_ip": iotarm_account_credentials['gw_public_ip'], "remote_right_id": iotarm_account_credentials['gw_private_ip'], "remote_subnet": resources['iotarm']['vpcCidr'], "provider_name": "iotarm", "key_exchange_version": "ikev2", "pre_shared_key": vpn_secrets[vpn_provider_name + '_iotarm_shared_secret']}]

    return vpn_provider

def get_dns_config(resources, nodes_ips, dns_servers_ips, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    machines = Machine.objects.filter(cluster=cluster)

    dns_server_nodes_addresses = []
    for machine in machines:
        if machine.provider == 'iotarm':
            dns_server_nodes_addresses.append({'hostname': machine.name, 'private_ip': machine.privateIP})

    internal_dns_zone = resources['internal_dns_zone']
    server_private_ip = nodes_ips['iotarm_server_private_ip']
    server_ip = dns_servers_ips['iotarm_server_ip']

    dns_config = {
        'iotarm': {
        'name': 'iotarm',
        'publicDnsServer': f'server=/iotarm.{ internal_dns_zone }/{ server_private_ip }\n',
        'privateDnsServer': f'server=/iotarm.{ internal_dns_zone }/{ server_private_ip }\n',
        "lastDnsServer": "server=/#/8.8.8.8\nserver=/#/8.8.4.4",
        'groups': 'iotarm-server-node',
        'serverName': f'{ server_ip }',
        'dns_server_nodes_addresses': dns_server_nodes_addresses
    }}

    return dns_config

def update_provider_regions(account_id, user_id):
    pass

def check_region_parameters(resources, user_id):
    failed_providers = {'iotarm': False}
    return failed_providers

def get_used_terraform_environment_resources(resources, user_id, nodes_counter):
    tf_variables = {}
    nodes_counter += 1 + len(resources['iotarm']['machines'])
    return tf_variables, nodes_counter


def kubernetes_storage_integration(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    pass

def get_storageclass_name():
    return ''

def add_new_machines_to_resources(machines, resources):
    for _ in range(machines['nodes']):
        resources[machines['provider']]['machines'] += machines['iotarmMachines']

    return resources

def run_add_dns_address(machines, new_nodes_privateips, clouds, user_id, cluster, server_private_ip, gateway_address):
    ansible_client = AnsibleClient()

    machines = Machine.objects.filter(cluster=cluster, provider='iotarm')

    iotarm_new_nodes = []

    for machine in machines:
        if machine.privateIP in new_nodes_privateips:
            iotarm_new_nodes.append({'private_ip': machine.privateIP, 'hostname': machine.name})

    try:
        ansible_client.run_add_dns_address(user_id, str(cluster.id), cluster.title, iotarm_new_nodes, server_private_ip, gateway_address)
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

def destroy_resources(resources, user_id, cluster_id, nodes_counter):
    tf_variables = {}
    nodes_counter += 1 + len(resources['iotarm']['machines'])
    return tf_variables, nodes_counter

def destroy_disk_resources(resources):
    pass

def run_dns(resources, nodes_ips, dns_servers_ips, cluster_id, user_id, gateway_address, providers_dns_configs, supported_provider, v2):
    dns_servers = environment_providers.get_ansible_dns_servers(supported_provider, resources, providers_dns_configs)

    ansible_client = AnsibleClient()
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    ansible_client.run_dns(user_id, str(cluster.id), cluster.title, nodes_ips, dns_servers, gateway_address, dns_servers_ips, json.loads(cluster.config)['internal_dns_zone'], supported_provider, providers_dns_configs['iotarm']['dns_server_nodes_addresses'], v2=v2)

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

def get_storage_accounts(credential_id):
    return {}

def delete_bucket_folder(payload, request):
    return {}

def get_bucket_details(payload, request):
    return {}

def get_cloud_account_info(cloud_account):
    return {}