import ast
import base64
import ipaddress
import json
import logging
import os
import pathlib
import time
import traceback

from httplib2 import Credentials

from cloudcluster import models, settings
from cloudcluster.models import CloudAccount, Clusters, Machine, Tenant
from cloudcluster.v1_0_0 import tasks
from cloudcluster.v1_0_0.services import vault_service, constants
from cloudcluster.v1_0_0.ansible.ansible_client import AnsibleClient
from cloudcluster.v1_0_0.services.cloud_providers import (
    validate_cloud_provider_regions_zones_instance_types,
    validate_cloud_provider_regions_zones_instance_types_custom_nodes)
from environment_providers import environment_providers
from environment_providers.azure.services import api_client

FILE_BASE_DIR = str(pathlib.Path(__file__).parent.absolute())

logger = logging.getLogger(__name__)

def get_created_cluster_resources(cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    tfconfig = json.loads(cluster.config)

    azure_account = CloudAccount.objects.filter(id=tfconfig['azure']['account'], provider='azure')[0]
    azure_account_credentials = vault_service.read_secret(azure_account.credentials)

    resources_dict = api_client.get_created_cluster_resources(
        azure_account_credentials['azure_tenant_id'],
        azure_account_credentials['azure_subscription_id'],
        azure_account_credentials['azure_client_id'],
        azure_account_credentials['azure_client_secret'],
        cluster.name
    )

    return resources_dict

def get_planned_resources_for_creation(terraform_plan, name_prefix):
    planned_resources = terraform_plan['planned_values']['root_module']['resources']

    print(planned_resources)

    cluster_resources = []

    for planned_resource in planned_resources:
        if planned_resource['mode'] == 'managed' and planned_resource['type'].startswith('azurerm_') and (('name' in planned_resource['values'] and planned_resource['values']['name'].startswith(name_prefix) or \
            'tags' in planned_resource['values'] and 'daiteap-env-id' in planned_resource['values']['tags'] and planned_resource['values']['tags']['daiteap-env-id'].replace('-', '').startswith(name_prefix))):
            cluster_resources.append(planned_resource)

    return cluster_resources

def destroy_resources(resources, user_id, cluster, internal_dns_zone):
    tf_variables = get_tf_variables(resources, cluster, internal_dns_zone)

    return tf_variables

def destroy_disk_resources(resources):
    pass

def get_tf_variables(resources, cluster, internal_dns_zone, tag_values=None):
    tf_variables = {}

    account = CloudAccount.objects.filter(id=resources['account'], provider='azure')[0]
    azure_account_credentials = vault_service.read_secret(account.credentials)

    vpc_network_azure = ipaddress.ip_network(resources['vpcCidr'])
    vpc_network_azure_subnets = list(vpc_network_azure.subnets())

    tf_variables['azurerm_subscription_id'] = azure_account_credentials['azure_subscription_id']
    tf_variables['azurerm_client_id'] = azure_account_credentials['azure_client_id']
    tf_variables['azurerm_client_secret'] = azure_account_credentials['azure_client_secret']
    tf_variables['azurerm_tenant_id'] = azure_account_credentials['azure_tenant_id']
    tf_variables['azurerm_internal_dns_zone'] = 'azure.' + internal_dns_zone
    tf_variables['azurerm_prefix'] = cluster.name
    tf_variables['azurerm_location'] = resources['region']
    tf_variables['azurerm_environment_id'] = str(cluster.id)
    tf_variables['azurerm_vpc_cidr'] = resources['vpcCidr']
    tf_variables['azurerm_vpc_subnet_cidr'] = str(vpc_network_azure_subnets[0])
    tf_variables['azurerm_vpc_gateway_cidr'] = str(vpc_network_azure_subnets[1])

    if tag_values:
        tf_variables['azurerm_daiteap_username'] = tag_values['username']
        tf_variables['azurerm_daiteap_user_email'] = tag_values['email']
        tf_variables['azurerm_daiteap_platform_url'] = tag_values['url']
        tf_variables['azurerm_daiteap_workspace_name'] = tag_values['tenant_name']

    region_name = resources['region']

    instances = []

    for node in resources['nodes']:
        image_publisher = node['operatingSystem'].split('/')[0]
        image_offer = node['operatingSystem'].split('/')[1]
        image_sku = node['operatingSystem'].split('/')[2]
        image_version = node['operatingSystem'].split('/')[3]
        instance_type = node['instanceType']

        account_regions = json.loads(account.regions)

        for region in account_regions:
            if region['name'] == region_name:
                for zone in region['zones']:
                    if zone['name'] == node['zone']:
                        for instance in zone['instances']:
                            if instance['name'] == instance_type:
                                instance_storage = instance['storage']

        instances.append({
            'instance_name': node['name'],
            'image_publisher': image_publisher,
            'image_offer': image_offer,
            'image_sku': image_sku,
            'image_version': image_version,
            'image_id': node['operatingSystem'],
            'instance_storage': instance_storage,
            'instance_type': instance_type
        })
    instances_str = json.dumps(instances)
    tf_variables['azure_instances'] = instances_str

    return tf_variables

def validate_regions_zones_instance_types(provider_data, user, environment_type):
    if environment_type == constants.ClusterType.CAPI.value:
        validate_cloud_provider_regions_zones_instance_types(provider_data, user)
    else:
        validate_cloud_provider_regions_zones_instance_types_custom_nodes(provider_data, user)

def get_provider_config_params(payload, user):
    config = {}
    config['azure'] = {
        'region': payload['azure']['region'],
        'nodes': payload['azure']['nodes'],
        'vpcCidr': payload['azure']['vpcCidr'],
        'account': payload['azure']['account']
    }

    return config

def restart_machine(config, user_id, machine):
    account_id = config['azure']['account']
    account = CloudAccount.objects.filter(id=account_id, provider='azure')[0]
    azure_account_credentials = vault_service.read_secret(account.credentials)

    api_client.restart_instances(
        azure_account_credentials['azure_tenant_id'],
        azure_account_credentials['azure_subscription_id'],
        azure_account_credentials['azure_client_id'],
        azure_account_credentials['azure_client_secret'],
        machine.name.split('-')[0],
        [
            machine.name.split('.')[0]
        ]
    )

def start_machine(cluster_id, user_id, machine):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)

    try:
        account_id = config['azure']['account']
        account = CloudAccount.objects.filter(id=account_id, provider='azure')[0]
        azure_account_credentials = vault_service.read_secret(account.credentials)

        api_client.start_instances(
            azure_account_credentials['azure_tenant_id'],
            azure_account_credentials['azure_subscription_id'],
            azure_account_credentials['azure_client_id'],
            azure_account_credentials['azure_client_secret'],
            machine.name.split('-')[0],
            [
                machine.name.split('.')[0]
            ]
        )
    except Exception as e:
        machine.status = -1
        machine.save()

        log_data = {
            'machine': machine.name,
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_start_machine',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

def stop_machine(cluster_id, user_id, machine):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)

    try:
        account_id = config['azure']['account']
        account = CloudAccount.objects.filter(id=account_id, provider='azure')[0]
        azure_account_credentials = vault_service.read_secret(account.credentials)

        api_client.stop_instances(
            azure_account_credentials['azure_tenant_id'],
            azure_account_credentials['azure_subscription_id'],
            azure_account_credentials['azure_client_id'],
            azure_account_credentials['azure_client_secret'],
            machine.name.split('-')[0],
            [
                machine.name.split('.')[0]
            ]
        )
    except Exception as e:
        machine.status = -2
        machine.save()

        log_data = {
            'machine': machine.name,
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_stop_machine',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

def start_all_machines(cluster_id):
    azure_machines = Machine.objects.filter(cluster_id=cluster_id, provider='azure')

    for machine in azure_machines:
        machine.status = 1
        machine.save()

    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)

    if len(azure_machines) > 0:
        try:
            account_id = config['azure']['account']
            account = CloudAccount.objects.filter(id=account_id, provider='azure')[0]
            azure_account_credentials = vault_service.read_secret(account.credentials)

            azure_instances = []
            for machine in azure_machines:
                azure_instances.append(machine.name.split('.')[0])

            api_client.start_instances(
                azure_account_credentials['azure_tenant_id'],
                azure_account_credentials['azure_subscription_id'],
                azure_account_credentials['azure_client_id'],
                azure_account_credentials['azure_client_secret'],
                azure_machines[0].name.split('-')[0],
                azure_instances
            )
        except Exception as e:
            for machine in azure_machines:
                machine.status = -1
                machine.save()

            raise Exception(e)
    
    for machine in azure_machines:
        machine.status = 0
        machine.save()

def restart_all_machines(cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)
    azure_machines = Machine.objects.filter(cluster_id=cluster_id, provider='azure')

    for machine in azure_machines:
        machine.status = 3
        machine.save()

    if len(azure_machines) > 0:
        try:
            account_id = config['azure']['account']
            account = CloudAccount.objects.filter(id=account_id, provider='azure')[0]
            azure_account_credentials = vault_service.read_secret(account.credentials)

            azure_instances = []
            for machine in azure_machines:
                azure_instances.append(machine.name.split('.')[0])

            api_client.restart_instances(
                azure_account_credentials['azure_tenant_id'],
                azure_account_credentials['azure_subscription_id'],
                azure_account_credentials['azure_client_id'],
                azure_account_credentials['azure_client_secret'],
                azure_machines[0].name.split('-')[0],
                azure_instances
            )
        except Exception as e:
            for machine in azure_machines:
                machine.status = -3
                machine.save()

            raise Exception(e)
    
    for machine in azure_machines:
        machine.status = 0
        machine.save()

def stop_all_machines(cluster_id):
    azure_machines = Machine.objects.filter(cluster_id=cluster_id, provider='azure')

    for machine in azure_machines:
        machine.status = 2
        machine.save()

    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)

    if len(azure_machines) > 0:
        try:
            account_id = config['azure']['account']
            account = CloudAccount.objects.filter(id=account_id, provider='azure')[0]
            azure_account_credentials = vault_service.read_secret(account.credentials)

            azure_instances = []
            for machine in azure_machines:
                azure_instances.append(machine.name.split('.')[0])

            api_client.stop_instances(
                azure_account_credentials['azure_tenant_id'],
                azure_account_credentials['azure_subscription_id'],
                azure_account_credentials['azure_client_id'],
                azure_account_credentials['azure_client_secret'],
                azure_machines[0].name.split('-')[0],
                azure_instances
            )
        except Exception as e:
            for machine in azure_machines:
                machine.status = -2
                machine.save()

            raise Exception(e)

    for machine in azure_machines:
        machine.status = 10
        machine.save()

def get_tfstate_resources(tfstate):
    resources = ast.literal_eval(tfstate)['resources']
    azure_nodes = []

    for resource in resources:

        if resource['type'] == 'azurerm_network_interface' and resource['name'] == 'main':
            public_ip = ''
            instances = resource['instances']
            for i in range(len(instances)):
                for ip_config in instances[i]['attributes']['ip_configuration']:
                    if 'public_ip_address_id' in ip_config:
                        for res in resources:
                            if res['type'] == 'azurerm_public_ip' and res['name'] == 'main':
                                for ins in res['instances']:
                                    if ins['attributes']['id'] == ip_config['public_ip_address_id']:
                                        public_ip = ins['attributes']['ip_address']
                                        break
                        if public_ip:
                            break

                name = ''
                for azurerm_resource in resources:
                    if azurerm_resource['type'] == 'azurerm_linux_virtual_machine' and azurerm_resource['name'] == 'main':
                        azurerm_instances = azurerm_resource['instances']
                        name = ''
                        for j in range(len(azurerm_instances)):
                            for network_interface_id in azurerm_instances[j]['attributes']['network_interface_ids']:
                                if network_interface_id == instances[i]['attributes']['id']:
                                    name = azurerm_instances[j]['attributes']['name']
                                    break
                        if name:
                            break
                node = {
                    'user': 'clouduser',
                    'private_ip': instances[i]['attributes']['private_ip_address'],
                    'region': instances[i]['attributes']['location'],
                    'zone': instances[i]['attributes']['location'],
                    'name': name
                }
                if public_ip:
                    node['public_ip'] = public_ip
                azure_nodes.append(node)

    nodes = {'azure': sorted(azure_nodes, key=lambda x: x['name'])}
    return nodes

def get_machine_records(cloud_config, environment_provider, tfstate_resources, cluster_id):
    machines = []

    if 'azure' in cloud_config:
        node_counter = 1
        for node in tfstate_resources:

            machine_name = node['name'] + '.azure'

            if 'internal_dns_zone' in cloud_config:
                machine_name += '.' + cloud_config['internal_dns_zone']

            account = CloudAccount.objects.filter(id=cloud_config['azure']['account'], provider='azure')[0]
            account_regions = json.loads(account.regions)

            region_name = cloud_config['azure']['region']
            cloud_config_instance = [resource_node for resource_node in cloud_config[environment_provider]['nodes'] if ('name' in resource_node and resource_node['name'] == node['name'])]
            if len(cloud_config_instance) != 1:
                continue
            node_counter += 1
            cloud_config_instance = cloud_config_instance[0]
            instance_type = cloud_config_instance['instanceType']

            cpu = 0
            ram = 0
            hdd = 0

            for region in account_regions:
                if region['name'] == region_name:
                    for zone in region['zones']:
                        if zone['name'] == node['zone']:
                            for instance in zone['instances']:
                                if instance['name'] == instance_type:
                                    cpu = instance['cpu']
                                    ram = instance['ram']
                                    hdd = instance['storage']

            machine = Machine(
                cluster_id=cluster_id,
                name=machine_name,
                provider=environment_provider,
                status=0,
                cpu=cpu,
                ram=ram,
                hdd=hdd
            )

            machine.kube_name = node['name']

            if 'kube_master' in node:
                machine.kube_master = node['kube_master']
            if 'kube_etcd' in node:
                machine.kube_etcd = node['kube_etcd']

            if 'public_ip' in node and node['public_ip']:
                machine.publicIP = node['public_ip']
            if 'operatingSystem' in cloud_config[environment_provider] and cloud_config[environment_provider]['operatingSystem']:
                machine.operating_system = cloud_config[environment_provider]['operatingSystem']
            elif 'operatingSystemName' in cloud_config_instance:
                machine.operating_system = cloud_config_instance['operatingSystemName']
            elif 'operatingSystem' in cloud_config_instance:
                machine.operating_system = cloud_config_instance['operatingSystem']
            if 'private_ip' in node and node['private_ip']:
                machine.privateIP = node['private_ip']
            if 'instanceType' in cloud_config[environment_provider] and cloud_config[environment_provider]['instanceType']:
                machine.type = cloud_config[environment_provider]['instanceType']
            elif 'instanceTypeName' in cloud_config_instance:
                machine.type = cloud_config_instance['instanceTypeName']
            elif 'instanceType' in cloud_config_instance:
                machine.type = cloud_config_instance['instanceType']
            if 'region' in node and node['region']:
                machine.region = node['region']
            if 'zone' in node and node['zone']:
                machine.zone = node['zone']
            if 'instance_id' in node and node['instance_id']:
                machine.instance_id = node['instance_id']

            machines.append(machine)

    return machines

def get_tf_code(environment_type):
    code = ''
    if environment_type in [constants.ClusterType.DLCM.value, constants.ClusterType.VMS.value, constants.ClusterType.COMPUTE_VMS.value]:
        with open(os.path.join(settings.BASE_DIR + '/environment_providers/azure/terraform/config_compute.tf'), 'r') as tf_file:
            code += tf_file.read()
    else:
        with open(os.path.join(settings.BASE_DIR + '/environment_providers/azure/terraform/config.tf'), 'r') as tf_file:
            code += tf_file.read()
    return code


def get_valid_operating_systems(payload, environment_type, user_id):
    account = models.CloudAccount.objects.filter(id=payload['accountId'], provider='azure')[0]
    azure_account_credentials = vault_service.read_secret(account.credentials)

    azure_client_id = azure_account_credentials['azure_client_id']
    azure_client_secret = azure_account_credentials['azure_client_secret']
    azure_tenant_id = azure_account_credentials['azure_tenant_id']
    azure_subscription_id = azure_account_credentials['azure_subscription_id']

    if environment_type == constants.ClusterType.CAPI.value:
        # CAPI
        return []
    elif environment_type == constants.ClusterType.DLCM_V2.value:
        # DLCM v2
        daiteap_image_params = settings.AZURE_DAITEAP_IMAGE_PARAMETERS
        publisher = daiteap_image_params.split('/')[0]
        offer = daiteap_image_params.split('/')[1]
        sku = daiteap_image_params.split('/')[2]
        return api_client.get_all_available_daiteap_os_parameters(
            azure_client_id,
            azure_client_secret,
            azure_tenant_id,
            azure_subscription_id,
            payload['region'].lower().replace(" ", ""),
            publisher,
            offer,
            sku
        )
    else:
        return api_client.get_all_available_os_parameters(
            azure_client_id,
            azure_client_secret,
            azure_tenant_id,
            azure_subscription_id,
            payload['region'].lower().replace(" ", "")
        )

def validate_account_permissions(credentials, user_id, storage_enabled):
    azure_missing_permissions = api_client.get_missing_client_permissions(
        credentials['azure_tenant_id'],
        credentials['azure_subscription_id'],
        credentials['azure_client_id'],
        credentials['azure_client_secret'],
        storage_enabled
    )

    if 'id' in credentials:
        tasks.worker_update_provider_regions.delay('azure', user_id, credentials['id'])

    if 'id' in credentials:
        storage_accounts = api_client.get_storage_accounts(0, credentials)
        if storage_enabled and len(storage_accounts['storage_accounts']) == 0:
            azure_missing_permissions.append('No storage accounts found.')

    if azure_missing_permissions:
        if 'id' in credentials:
            cloud_account = CloudAccount.objects.get(id=credentials['id'])
            cloud_account.valid = False
            cloud_account.save()
        return {'error': 'Missing required permissions: ' + str(azure_missing_permissions)}
    elif 'id' in credentials:
        cloud_account = CloudAccount.objects.get(id=credentials['id'])
        cloud_account.cloud_account_info = get_cloud_account_info(cloud_account)
        cloud_account.valid = True
        cloud_account.save()

    return {'dlcmV2Images': True}

def update_provider_regions(account_id, user_id):
    account = CloudAccount.objects.filter(id=account_id, provider='azure')[0]
    azure_account_credentials = vault_service.read_secret(account.credentials)

    try:
        max_retries = 10
        timeout = 10

        for i in range(max_retries):
            try:
                azure_regions = api_client.get_available_regions_parameters(azure_account_credentials['azure_tenant_id'], azure_account_credentials['azure_subscription_id'], azure_account_credentials['azure_client_id'], azure_account_credentials['azure_client_secret'])
                break
            except Exception as e:
                if i == max_retries - 1:
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(user_id),
                    }
                    logger.error('Error updating azure regions.', extra=log_data)
                    raise e
                else:
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(user_id),
                    }
                    logger.error(str(e) + 'Error updating azure regions. Retrying...', extra=log_data)
                    time.sleep(timeout)
    except Exception as e:
        log_data = {
            'account': 'azure -' + str(account_id),
            'level': 'ERROR',
            'user_id': user_id,
            'task': 'worker_update_provider_regions',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
        account = CloudAccount.objects.filter(id=account_id, provider='azure')[0]
        account.regions_update_status = -1  # failed
        account.regions_failed_msg = str(e)
        account.save()
        return

    account = CloudAccount.objects.filter(id=account_id, provider='azure')[0]
    account.regions = json.dumps(azure_regions)
    account.regions_update_status = 0  # updated
    account.save()

def check_region_parameters(resources, user_id):
    failed_providers = {'azure': True}
    regions = json.loads(CloudAccount.objects.filter(tenant__daiteapuser__user_id=user_id,label=resources['azure']['account'], provider='azure')[0].regions)
    for region in regions:
        if region['name'] == resources['azure']['region']:
            for zone in region['zones']:
                if zone['name'] == resources['azure']['zone']:
                    for instance in zone['instances']:
                        if instance['name'] == resources['azure']['instanceType']:
                            failed_providers['azure'] = False
                            break
                    break
            break

    return failed_providers

def validate_credentials(payload, request, storage_enabled):
    azure_account = None
    if 'account_id' in payload:
        azure_account = models.CloudAccount.objects.filter(id=payload['account_id'], provider='azure')[0]
        try:
            azure_account_credentials = vault_service.read_secret(azure_account.credentials)
            azure_tenant_id = azure_account_credentials['azure_tenant_id']
            azure_subscription_id = azure_account_credentials['azure_subscription_id']
            azure_client_id = azure_account_credentials['azure_client_id']
            azure_client_secret = azure_account_credentials['azure_client_secret']
        except Exception as e:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
            raise Exception('Invalid credentials parameter')
    elif 'credentials' in payload:
        try:
            azure_tenant_id = payload['credentials']['azure']['azure_tenant_id']
            azure_subscription_id = payload['credentials']['azure']['azure_subscription_id']
            azure_client_id = payload['credentials']['azure']['azure_client_id']
            azure_client_secret = payload['credentials']['azure']['azure_client_secret']
        except Exception as e:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
            raise Exception('Invalid credentials parameter')
    else:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid credentials parameter', extra=log_data)
        raise Exception('Invalid credentials parameter')

    if (azure_tenant_id is not None and len(azure_tenant_id) > 0 and
        azure_subscription_id is not None and len(azure_subscription_id) > 0 and
        azure_client_id is not None and len(azure_client_id) > 0 and
        azure_client_secret is not None and len(azure_client_secret) > 0
    ):
        azure_keys = {}

        azure_keys['azure_tenant_id'] = azure_tenant_id
        azure_keys['azure_subscription_id'] = azure_subscription_id
        azure_keys['azure_client_id'] = azure_client_id
        azure_keys['azure_client_secret'] = azure_client_secret

        if len(azure_keys['azure_tenant_id']) < 36 or len(azure_keys['azure_tenant_id']) > 36:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Invalid parameter azure_tenant_id', extra=log_data)
            raise Exception('Invalid parameter azure_tenant_id')

        if len(azure_keys['azure_subscription_id']) < 36 or len(azure_keys['azure_subscription_id']) > 36:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Invalid parameter azure_subscription_id', extra=log_data)
            raise Exception('Invalid parameter azure_subscription_id')

        if len(azure_keys['azure_client_id']) < 36 or len(azure_keys['azure_client_id']) > 36:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Invalid parameter azure_client_id', extra=log_data)
            raise Exception('Invalid parameter azure_client_id')

        if len(azure_keys['azure_client_secret']) < 5 or len(azure_keys['azure_client_secret']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Invalid parameter azure_client_secret', extra=log_data)
            raise Exception('Invalid parameter azure_client_secret')

        if azure_account is not None:
            azure_keys['id'] = azure_account.id

        azure_keys['azure'] = True

        task = tasks.worker_validate_credentials.delay(azure_keys, request.user.id, storage_enabled)
    else:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid azure parameter', extra=log_data)
        raise Exception('Invalid azure parameter')

    return task

def update_cloud_credentials(payload, request):
    azure = payload['account_params']

    if 'label' in azure and 'old_label' in azure:
        if azure['old_label'] == '' or len(azure['old_label']) < 3 or len(azure['old_label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter old_label.', extra=log_data)
            raise Exception('Invalid parameter old_label.')

        if azure['label'] != '' and len(azure['label']) < 3 or len(azure['label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter label.', extra=log_data)
            raise Exception('Invalid parameter label.')

        if azure['label'] != '':
            try:
                account = models.CloudAccount.objects.filter(label=azure['old_label'],tenant_id=request.daiteap_user.tenant_id, provider='azure')[0]

                new_account = False
                account.label = azure['label']
            except:
                new_account = True
                account = models.CloudAccount(
                    label=azure['label'],
                    user=request.user,
                    contact=request.user.email,
                    provider='azure'
                )

            if ((new_account and len(models.CloudAccount.objects.filter(label=azure['label'],tenant_id=request.daiteap_user.tenant_id, provider='azure')) > 0) or
                (not new_account and azure['label'] != azure['old_label'] and 
                len(models.CloudAccount.objects.filter(label=azure['label'],tenant_id=request.daiteap_user.tenant_id, provider='azure')) > 0)
            ):
                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                }
                logger.error('Invalid parameter label.', extra=log_data)
                raise Exception('Invalid parameter label.')

            if new_account:
                account.tenant = models.Tenant.objects.get(id=request.daiteap_user.tenant_id)
                account.save()

            credentials = {}
            credentials['azure_tenant_id'] = azure["azure_tenant_id"]
            credentials['azure_subscription_id'] = azure["azure_subscription_id"]
            credentials['azure_client_id'] = azure["azure_client_id"]
            credentials['azure_client_secret'] = azure["azure_client_secret"]

            account.credentials = "none"
            account.user = request.user
            account.save()

            storage_name = settings.AZURE_STORAGE_ACCOUNT_NAME_PREFIX + str(account.id)
            resource_group_name = settings.AZURE_STORAGE_RESOURCE_GROUP_NAME
            storage_location = settings.AZURE_STORAGE_LOCATION

            max_retries = 10
            timeout = 10

            for i in range(max_retries):
                try:
                    api_client.create_resource_group(credentials, resource_group_name, storage_location)
                    api_client.create_storage_account(credentials, storage_name, 'Standard_LRS', storage_location, resource_group_name)
                    break
                except Exception as e:
                    if i == max_retries - 1:
                        log_data = {
                            'level': 'ERROR',
                            'user_id': str(request.user.id),
                        }
                        logger.error('Error creating azure resources.', extra=log_data)
                        account.delete()
                        raise Exception('Error creating azure resources.')
                    else:
                        log_data = {
                            'level': 'ERROR',
                            'user_id': str(request.user.id),
                        }
                        logger.error(str(e) + 'Error creating azure resources. Retrying...', extra=log_data)
                        time.sleep(timeout)

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

    account.regions_update_status = 1  # updating
    account.save()
    if not new_account and azure['label'] != azure['old_label']:
        clusters = models.Clusters.objects.filter(user=request.user.username)
        for cluster in clusters:
            config = json.loads(cluster.config)
            if 'azure' not in config:
                continue
            if config['azure']['account'] == azure['old_label']:
                config['azure']['account'] = azure['label']
                cluster.config = json.dumps(config)
                cluster.save()

    tasks.worker_update_provider_regions.delay('azure', request.user.id, account.id)

def create_cloud_credentials(payload, request, all_account_labels):
    azure = payload['account_params']

    if ('label' in azure and
        'azure_tenant_id' in azure and
        'azure_subscription_id' in azure and
        'azure_client_id' in azure and
        'azure_client_secret' in azure):
        if azure['label'] != '' and len(azure['label']) < 3 or len(azure['label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter label.', extra=log_data)
            return Exception('Invalid parameter label.')

        if len(azure['azure_tenant_id']) < 36 or len(azure['azure_tenant_id']) > 36:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter azure_tenant_id.', extra=log_data)
            return Exception('Invalid parameter azure_tenant_id.')

        if len(azure['azure_subscription_id']) < 36 or len(azure['azure_subscription_id']) > 36:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter azure_subscription_id.', extra=log_data)
            return Exception('Invalid parameter azure_subscription_id.')

        if len(azure['azure_client_id']) < 36 or len(azure['azure_client_id']) > 36:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter azure_client_id.', extra=log_data)
            return Exception('Invalid parameter azure_client_id.')

        if len(azure['azure_client_secret']) < 5 or len(azure['azure_client_secret']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter azure_client_secret.', extra=log_data)
            return Exception('Invalid parameter azure_client_secret.')

        if azure['label'] != '':
            if azure['label'] in all_account_labels:
                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                }
                logger.error('Account label already exists.', extra=log_data)
                return Exception('Account label already exists.')

            account = models.CloudAccount(
                label=azure['label'],
                tenant=Tenant.objects.filter(id=request.daiteap_user.tenant_id)[0],
                provider='azure',
                contact=request.user.email,
                description=azure['description']
            )

            credentials = {}
            credentials['azure_tenant_id'] = azure["azure_tenant_id"]
            credentials['azure_subscription_id'] = azure["azure_subscription_id"]
            credentials['azure_client_id'] = azure["azure_client_id"]
            credentials['azure_client_secret'] = azure["azure_client_secret"]

            account.credentials = "none"
            account.user = request.user
            account.save()

            storage_name = settings.AZURE_STORAGE_ACCOUNT_NAME_PREFIX + str(account.id)
            resource_group_name = settings.AZURE_STORAGE_RESOURCE_GROUP_NAME
            storage_location = settings.AZURE_STORAGE_LOCATION

            api_client.create_resource_group(credentials, resource_group_name, storage_location)
            api_client.create_storage_account(credentials, storage_name, 'Standard_LRS', storage_location, resource_group_name)

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
        return Exception('Invalid account_params parameter.')

    account.cloud_account_info = get_cloud_account_info(account)
    account.regions_update_status = 1  # updating
    account.save()

    tasks.worker_update_provider_regions.delay('azure', request.user.id, account.id)

def delete_cloud_credentials(cloudaccount):
    azure_credentials = vault_service.read_secret(cloudaccount.credentials)

    storage_name = settings.AZURE_STORAGE_ACCOUNT_NAME_PREFIX + str(cloudaccount.id)
    resource_group_name = settings.AZURE_STORAGE_RESOURCE_GROUP_NAME

    try:
        api_client.delete_storage_account(azure_credentials, storage_name, resource_group_name)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(cloudaccount.user.id)
        }
        logger.error(str(e), extra=log_data)


def get_gateway_address_dc_private_ip_and_client_hosts(clouds, master_private_ip, gateway_address, client_hosts, config, user_id):
    if len(clouds['azure']) > 0:
        if master_private_ip == '':
            master_private_ip = clouds['azure'][0]['user'] + '@' + clouds['azure'][0]['private_ip']
            gateway_address = clouds['azure'][0]['user'] + '@' + clouds['azure'][0]['public_ip']
            for i in range(1, len(clouds['azure'])):
                client_hosts.append(clouds['azure'][i])
        else:
            for i in range(0, len(clouds['azure'])):
                client_hosts.append(clouds['azure'][i])

    return master_private_ip, gateway_address, client_hosts

def run_nodes_labels(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    provider_nodes = []
    provider_lb_nodes = []
    provider_id = 'azure:///subscriptions/{{ item.subscriptionId }}/resourceGroups/{{ item.resourceGroup }}/providers/Microsoft.Compute/virtualMachines/{{ item.name }}'
    provider = 'azure'

    azure_account = CloudAccount.objects.filter(id=resources['azure']['account'],tenant__daiteapuser__user_id=user_id, provider='azure')[0]
    azure_account_credentials = vault_service.read_secret(azure_account.credentials)

    for node in clouds['azure']:
        provider_lb_nodes.append({"name": node['name'], "resourceGroup": cluster.name, "subscriptionId": azure_account_credentials['azure_subscription_id']})
        provider_nodes.append(node['name'])

    ansible_client = AnsibleClient()
    ansible_client.run_nodes_labels(user_id, str(cluster.id), cluster.title, master_ip, provider_nodes, provider_lb_nodes, provider_id, gateway_address, provider)

def kubernetes_storage_integration(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    if 'azure' in resources:
        azure_lb_nodes = []
        azure_privateips = []

        for node in clouds['azure']:
            azure_lb_nodes.append({"name": node['name']})
            azure_privateips.append(node['private_ip'])

        account = CloudAccount.objects.filter(id=resources['azure']['account'], provider='azure')[0]
        azure_account_credentials = vault_service.read_secret(account.credentials)

        tenant_id = azure_account_credentials['azure_tenant_id']
        subscription_id = azure_account_credentials['azure_subscription_id']
        aad_client_id = azure_account_credentials['azure_client_id']
        aad_client_secret = azure_account_credentials['azure_client_secret']

        environment_id = str(cluster.id)
        environment_name = cluster.title
        resource_group = cluster.name
        location = resources['azure']['region']
        route_table_name = cluster.name
        security_group_name = cluster.name
        vnet_name = cluster.name
        vnet_resource_group = cluster.name
        primary_availability_set_name = cluster.name
        nodes = azure_lb_nodes
        azure_nodes = azure_privateips
        master_node_address = master_ip

        if not resource_group:
            raise Exception('Invalid parameter resource_group')
        if not location:
            raise Exception('Invalid parameter location')
        if not route_table_name:
            raise Exception('Invalid parameter route_table_name')
        if not security_group_name:
            raise Exception('Invalid parameter security_group_name')
        if not vnet_name:
            raise Exception('Invalid parameter vnet_name')
        if not vnet_resource_group:
            raise Exception('Invalid parameter vnet_resource_group')
        if not primary_availability_set_name:
            raise Exception('Invalid parameter primary_availability_set_name')
        if not nodes:
            raise Exception('Invalid parameter nodes')
        if not azure_nodes:
            raise Exception('Invalid parameter azure_nodes')
        if not master_node_address:
            raise Exception('Invalid parameter master_node_address')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        inventory_path = FILE_BASE_DIR + '/playbooks/azure_integration/storage/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/azure_integration/storage/storage.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "tenantId": tenant_id,
            "aadClientId": aad_client_id,
            "aadClientSecret": aad_client_secret,
            "subscriptionId": subscription_id,
            "resourceGroup": resource_group,
            "location": location,
            "routeTableName": route_table_name,
            "securityGroupName": security_group_name,
            "vnetName": vnet_name,
            "vnetResourceGroup": vnet_resource_group,
            "primaryAvailabilitySetName": primary_availability_set_name,
            "nodes": nodes,
            "azure_nodes": azure_nodes,
            "gateway_address": gateway_address,
            "master_node_address": master_node_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        ansible_client = AnsibleClient()
        ansible_client.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

def kubernetes_delete_loadbalancer_resources(account_id, region, resource_group_name, user_id, cluster_id):
    account = CloudAccount.objects.filter(id=account_id, provider='azure')[0]
    azure_tenant_id = vault_service.read_secret(account.credentials)['azure_tenant_id']
    azure_subscription_id = vault_service.read_secret(account.credentials)['azure_subscription_id']
    azure_client_id = vault_service.read_secret(account.credentials)['azure_client_id']
    azure_client_secret = vault_service.read_secret(account.credentials)['azure_client_secret']

    api_client.delete_load_balancers(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret, resource_group_name, user_id, cluster_id)

def kubernetes_loadbalancer_integration(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    azure_lb_nodes = []
    azure_privateips = []

    for node in clouds['azure']:
        azure_lb_nodes.append({"name": node['name']})
        azure_privateips.append(node['private_ip'])

    account = CloudAccount.objects.filter(id=resources['azure']['account'], provider='azure')[0]
    azure_account_credentials = vault_service.read_secret(account.credentials)

    environment_id = str(cluster.id)
    environment_name = cluster.title
    tenant_id=azure_account_credentials['azure_tenant_id']
    aad_client_id=azure_account_credentials['azure_client_id']
    aad_client_secret=azure_account_credentials['azure_client_secret']
    subscription_id=azure_account_credentials['azure_subscription_id']
    resource_group=cluster.name
    location=resources['azure']['region']
    route_table_name=cluster.name
    security_group_name=cluster.name
    vnet_name=cluster.name
    vnet_resource_group=cluster.name
    primary_availability_set_name=cluster.name
    nodes=azure_lb_nodes
    azure_nodes=azure_privateips
    master_node_address=master_ip

    if not tenant_id:
        raise Exception('Invalid parameter tenant_id')
    if not aad_client_id:
        raise Exception('Invalid parameter aad_client_id')
    if not aad_client_secret:
        raise Exception('Invalid parameter aad_client_secret')
    if not subscription_id:
        raise Exception('Invalid parameter subscription_id')
    if not resource_group:
        raise Exception('Invalid parameter resource_group')
    if not location:
        raise Exception('Invalid parameter location')
    if not route_table_name:
        raise Exception('Invalid parameter route_table_name')
    if not security_group_name:
        raise Exception('Invalid parameter security_group_name')
    if not vnet_name:
        raise Exception('Invalid parameter vnet_name')
    if not vnet_resource_group:
        raise Exception('Invalid parameter vnet_resource_group')
    if not primary_availability_set_name:
        raise Exception('Invalid parameter primary_availability_set_name')
    if not nodes:
        raise Exception('Invalid parameter nodes')
    if not azure_nodes:
        raise Exception('Invalid parameter azure_nodes')
    if not master_node_address:
        raise Exception('Invalid parameter master_node_address')
    if gateway_address == []:
        raise Exception('gateway_address is empty')

    inventory_path = FILE_BASE_DIR + '/playbooks/azure_integration/loadbalancer/hosts.ini'
    playbook_path = FILE_BASE_DIR + '/playbooks/azure_integration/loadbalancer/loadbalancer.yaml'

    if not os.path.exists(playbook_path):
        raise Exception('Playbook does not exist')

    if not os.path.exists(inventory_path):
        raise Exception('Inventory does not exist')

    extra_vars = json.dumps({
        "tenantId": tenant_id,
        "aadClientId": aad_client_id,
        "aadClientSecret": aad_client_secret,
        "subscriptionId": subscription_id,
        "resourceGroup": resource_group,
        "location": location,
        "routeTableName": route_table_name,
        "securityGroupName": security_group_name,
        "vnetName": vnet_name,
        "vnetResourceGroup": vnet_resource_group,
        "primaryAvailabilitySetName": primary_availability_set_name,
        "nodes": nodes,
        "azure_nodes": azure_nodes,
        "gateway_address": gateway_address,
        "master_node_address": master_node_address,
        "ansible_python_interpreter": "/usr/bin/python3",
        "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
    })

    ansible_client = AnsibleClient()
    ansible_client.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

def remove_nodeselector_from_ccm(resources, user_id, master_node_private_ip, gateway_address, cluster_id):
    pass

def add_nodeselector_to_ccm(resources, user_id, master_node_private_ip, gateway_address, cluster_id):
    pass

def get_storageclass_name():
    return '\"managed-csi\"'

def run_added_machines_vpn_routing(resources, user_id, cluster_id, new_machines):
    pass

def run_vpn_routing(resources, user_id, cluster_id):
    pass

def run_vpn_server(filtered_environment_providers, vpn_configs, resources, cluster_id, user_id):
    pass

def set_vpn_configs(vpn_configs, resources, vpn_secrets, vpn_provider_name, user_id):
    vpn_provider = [{"remote_public_ip": vpn_configs['azure'][vpn_provider_name]['public_ip'], "remote_right_id": vpn_configs['azure'][vpn_provider_name]['public_ip'], "remote_subnet": resources['azure']['vpcCidr'], "provider_name": "azure", "key_exchange_version": "ikev2", "pre_shared_key": vpn_configs['azure'][vpn_provider_name]['pre_shared_key']}]
    return vpn_provider

def get_dns_config(resources, nodes_ips, dns_servers_ips, cluster_id):
    dns_server = '168.63.129.16'
    internal_dns_zone = resources['internal_dns_zone']
    server_private_ip = nodes_ips['azure_server_private_ip']
    server_ip = dns_servers_ips['azure_server_ip']

    dns_config = {
        'azure': {
        'name': 'azure',
        'publicDnsServer': f'server=/azure.{ internal_dns_zone }/{ dns_server }\n',
        'privateDnsServer': f'server=/azure.{ internal_dns_zone }/{ server_private_ip }\n',
        'lastDnsServer': f'server=/#/{ dns_server }',
        'groups': 'azure-server-node',
        'serverName': f'{ server_ip }'
    }}

    return dns_config

def add_new_machines_to_resources(machines, resources):
    for _ in range(machines['nodes']):
        resources[machines['provider']]['nodes'].append({
            "is_control_plane": False,
            "zone": machines['zone'],
            "instanceType": machines['instanceType'],
            "operatingSystem": resources[machines['provider']]['nodes'][0]['operatingSystem'],
        })

    return resources

def run_add_dns_address(machines, new_nodes_privateips, clouds, user_id, cluster, server_private_ip, gateway_address):
    pass

def run_dns(resources, nodes_ips, dns_servers_ips, cluster_id, user_id, gateway_address, providers_dns_configs, supported_provider, v2):
    dns_servers = environment_providers.get_ansible_dns_servers(supported_provider, resources, providers_dns_configs)

    ansible_client = AnsibleClient()
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    ansible_client.run_dns(user_id, str(cluster.id), cluster.title, nodes_ips, dns_servers, gateway_address, dns_servers_ips, json.loads(cluster.config)['internal_dns_zone'], supported_provider, v2=v2)

def get_user_friendly_params(provider_config, is_capi = False, is_yaookcapi = False):
    return provider_config

def get_autosuggested_params():
    return {}

def get_storage_buckets(payload, request):
    azure_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    azure_credentials = vault_service.read_secret(azure_account.credentials)

    return api_client.get_storage_buckets(payload['credential_id'], azure_credentials, payload['storage_account_url'])

def create_storage_bucket(payload, request):
    azure_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    azure_credentials = vault_service.read_secret(azure_account.credentials)

    return api_client.create_storage_bucket(azure_credentials, payload['storage_account_url'], payload['bucket_name'])

def delete_storage_bucket(payload, request):
    azure_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    azure_credentials = vault_service.read_secret(azure_account.credentials)

    return api_client.delete_storage_bucket(azure_credentials, payload['storage_account_url'], payload['bucket_name'])

def get_bucket_files(payload, request):
    azure_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    azure_credentials = vault_service.read_secret(azure_account.credentials)

    return api_client.get_bucket_files(azure_credentials, payload['storage_account_url'], payload['bucket_name'], payload['path'])

def add_bucket_file(payload, request):
    azure_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    azure_credentials = vault_service.read_secret(azure_account.credentials)

    return api_client.add_bucket_file(azure_credentials, payload['storage_account_url'], payload['bucket_name'], payload['file_name'], payload['content_type'], payload['contents'], request.user.username, request)

def delete_bucket_file(payload, request):
    azure_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    azure_credentials = vault_service.read_secret(azure_account.credentials)

    return api_client.delete_bucket_file(azure_credentials, payload['storage_account_url'], payload['bucket_name'], payload['file_name'])

def download_bucket_file(payload, request):
    azure_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    azure_credentials = vault_service.read_secret(azure_account.credentials)

    return api_client.download_bucket_file(azure_credentials, payload['storage_account_url'], payload['bucket_name'], payload['file_name'])

def get_storage_accounts(payload, request):
    azure_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    azure_credentials = vault_service.read_secret(azure_account.credentials)

    return api_client.get_storage_accounts(payload['credential_id'], azure_credentials)

def delete_bucket_folder(payload, request):
    azure_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    azure_credentials = vault_service.read_secret(azure_account.credentials)

    return api_client.delete_bucket_folder(azure_credentials, payload['storage_account_url'], payload['bucket_name'], payload['folder_path'])

def get_bucket_details(payload, request):
    azure_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    azure_credentials = vault_service.read_secret(azure_account.credentials)

    return api_client.get_bucket_details(azure_credentials, payload['storage_account_url'], payload['bucket_name'])

def get_cloud_account_info(cloud_account):
    azure_credentials = vault_service.read_secret(cloud_account.credentials)
    return api_client.get_cloud_account_info(azure_credentials)