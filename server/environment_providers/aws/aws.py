import ast
import base64
import json
import logging
import os
import pathlib
import traceback

from azure.mgmt.resource import resources

from cloudcluster import models, settings
from cloudcluster.v1_0_0.services import vault_service, constants
from cloudcluster.models import CloudAccount, Clusters, Machine, Tenant
from cloudcluster.v1_0_0 import tasks
from cloudcluster.v1_0_0.ansible.ansible_client import AnsibleClient
from cloudcluster.v1_0_0.services.cloud_providers import (
    validate_cloud_provider_regions_zones_instance_types,
    validate_cloud_provider_regions_zones_instance_types_custom_nodes)
from cloudcluster.v1_0_0.services.cidr_splitter import split_cidr
from environment_providers import environment_providers
from environment_providers.aws.services import api_client
from netaddr.ip import IPNetwork

FILE_BASE_DIR = str(pathlib.Path(__file__).parent.absolute())

logger = logging.getLogger(__name__)

def get_created_cluster_resources(cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    tfconfig = json.loads(cluster.config)

    aws_account = CloudAccount.objects.filter(id=tfconfig['aws']['account'], provider='aws')[0]
    aws_account_credentials = vault_service.read_secret(aws_account.credentials)

    resources_dict = api_client.get_created_cluster_resources(
        aws_access_key_id=aws_account_credentials['aws_access_key_id'],
        aws_secret_access_key=aws_account_credentials['aws_secret_access_key'],
        region_name=tfconfig['aws']['region'],
        cluster_prefix=cluster.name,
        )

    return resources_dict

def get_planned_resources_for_creation(terraform_plan, name_prefix):
    planned_resources = terraform_plan['planned_values']['root_module']['resources']

    cluster_resources = []

    for planned_resource in planned_resources:
        if planned_resource['type'].startswith('aws_'):
            if 'tags' in planned_resource['values'] and \
                ('daiteap-env-id' in planned_resource['values']['tags'] and planned_resource['values']['tags']['daiteap-env-id'].replace('-', '').startswith(name_prefix) or \
                ('Name' in planned_resource['values']['tags'] and planned_resource['values']['tags']['Name'].startswith(name_prefix)) or \
                ('name' in planned_resource['values'] and planned_resource['values']['name'].startswith(name_prefix))):
                cluster_resources.append(planned_resource)

    return cluster_resources

def destroy_resources(resources, user_id, cluster, internal_dns_zone):
    tf_variables = get_tf_variables(resources, cluster, internal_dns_zone)

    return tf_variables

def destroy_disk_resources(resources):
    aws_account = CloudAccount.objects.filter(id=resources['aws']['account'], provider='aws')[0]
    aws_account_credentials = vault_service.read_secret(aws_account.credentials)
    api_client.delete_k8s_volume_resources(
        aws_account_credentials['aws_access_key_id'],
        aws_account_credentials['aws_secret_access_key'],
        resources['aws']['region']
    )

def get_tf_variables(resources, cluster, internal_dns_zone, tag_values=None):
    tf_variables = {}

    account = CloudAccount.objects.filter(id=resources['account'], provider='aws')[0]
    aws_account_credentials = vault_service.read_secret(account.credentials)

    tf_variables['aws_access_key_id'] = aws_account_credentials['aws_access_key_id']
    tf_variables['aws_secret_access_key'] = aws_account_credentials['aws_secret_access_key']
    tf_variables['aws_internal_dns_zone'] = 'aws.' + internal_dns_zone
    tf_variables['aws_environment_id'] = str(cluster.id)
    tf_variables['aws_public_key_name'] = cluster.name
    tf_variables['aws_public_key_path'] = '/var/.ssh/id_rsa.pub'
    tf_variables['aws_vpc_name'] = cluster.name
    tf_variables['aws_user'] = 'clouduser'
    tf_variables['aws_vpc_cidr'] = resources['vpcCidr']
    tf_variables['aws_region'] = resources['region']

    if tag_values:
        tf_variables['aws_daiteap_username'] = tag_values['username']
        tf_variables['aws_daiteap_user_email'] = tag_values['email']
        tf_variables['aws_daiteap_platform_url'] = tag_values['url']
        tf_variables['aws_daiteap_workspace_name'] = tag_values['tenant_name']

    region_name = resources['region']

    instances = []

    aws_subnet_zones = []

    regions = json.loads(account.regions)

    # creatre subnet for each aws region zone
    for region in regions:
        if region['name'] == region_name:
            for zone in region['zones']:
                aws_subnet_zones.append(zone['name'])
            break

    aws_subnets = []
    if len(aws_subnet_zones) > 1:
        cidr_list = split_cidr(resources['vpcCidr'], len(aws_subnet_zones))
        counter = 0
        for zone in aws_subnet_zones:
            aws_subnets.append({
                'zone': zone,
                'cidr': cidr_list[counter],
            })
            counter += 1
    else:
        aws_subnets.append({
            'zone': aws_subnet_zones[0],
            'cidr': resources['vpcCidr'],
        })
    tf_variables['aws_subnets'] = json.dumps(aws_subnets)

    for node in resources['nodes']:
        instance_operating_system = node['operatingSystem'].split('/')[0]
        instance_image = node['operatingSystem'][(len(node['operatingSystem'].split('/')[0]) + 1):]
        instance_type = node['instanceType']
        instance_storage = 50
        instance_zone = node['zone']

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
            'image_owner': instance_operating_system,
            'instance_image': instance_image,
            'instance_type': instance_type,
            'instance_storage': instance_storage,
            'zone': instance_zone,
            'subnet_cidr': aws_subnets[aws_subnet_zones.index(node['zone'])]['cidr'],
        })
    instances_str = json.dumps(instances)
    tf_variables['aws_instances'] = instances_str

    return tf_variables

def validate_regions_zones_instance_types(provider_data, user, environment_type):
    if environment_type == constants.ClusterType.CAPI.value:
        validate_cloud_provider_regions_zones_instance_types(provider_data, user)
    else:
        validate_cloud_provider_regions_zones_instance_types_custom_nodes(provider_data, user)

def get_provider_config_params(payload, user):
    config = {}
    config['aws'] = {
        'region': payload['aws']['region'],
        'nodes': payload['aws']['nodes'],
        'vpcCidr': payload['aws']['vpcCidr'],
        'account': payload['aws']['account']
    }

    return config

def restart_machine(config, user_id, machine):
    account_id = config['aws']['account']
    account = CloudAccount.objects.filter(id=account_id, provider='aws')[0]
    aws_account_credentials = vault_service.read_secret(account.credentials)

    api_client.restart_instances(
        aws_account_credentials['aws_access_key_id'],
        aws_account_credentials['aws_secret_access_key'],
        machine.region,
        [
            machine.instance_id
        ]
    )

def start_machine(cluster_id, user_id, machine):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)

    try:
        account_id = config['aws']['account']
        account = CloudAccount.objects.filter(id=account_id, provider='aws')[0]
        aws_account_credentials = vault_service.read_secret(account.credentials)

        api_client.start_instances(
            aws_account_credentials['aws_access_key_id'],
            aws_account_credentials['aws_secret_access_key'],
            machine.region,
            [
                machine.instance_id
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
        account_id = config['aws']['account']
        account = CloudAccount.objects.filter(id=account_id, provider='aws')[0]
        aws_account_credentials = vault_service.read_secret(account.credentials)

        api_client.stop_instances(
            aws_account_credentials['aws_access_key_id'],
            aws_account_credentials['aws_secret_access_key'],
            machine.region,
            [
                machine.instance_id
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
    aws_machines = Machine.objects.filter(cluster_id=cluster_id, provider='aws')

    for machine in aws_machines:
        machine.status = 1
        machine.save()

    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)

    if len(aws_machines) > 0:
        try:
            account_id = config['aws']['account']
            account = CloudAccount.objects.filter(id=account_id, provider='aws')[0]
            aws_account_credentials = vault_service.read_secret(account.credentials)

            aws_instances = []
            for machine in aws_machines:
                aws_instances.append(machine.instance_id)

            api_client.start_instances(
                aws_account_credentials['aws_access_key_id'],
                aws_account_credentials['aws_secret_access_key'],
                machine.region,
                aws_instances
            )
        except Exception as e:
            for machine in aws_machines:
                machine.status = -1
                machine.save()

            raise Exception(e)

    for machine in aws_machines:
        machine.status = 0
        machine.save()

def restart_all_machines(cluster_id):
    aws_machines = Machine.objects.filter(cluster_id=cluster_id, provider='aws')

    for machine in aws_machines:
        machine.status = 3
        machine.save()

    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)

    if len(aws_machines) > 0:
        try:
            account_id = config['aws']['account']
            account = CloudAccount.objects.filter(id=account_id, provider='aws')[0]
            aws_account_credentials = vault_service.read_secret(account.credentials)

            aws_instances = []
            for machine in aws_machines:
                aws_instances.append(machine.instance_id)

            api_client.restart_instances(
                aws_account_credentials['aws_access_key_id'],
                aws_account_credentials['aws_secret_access_key'],
                machine.region,
                aws_instances
            )
        except Exception as e:
            for machine in aws_machines:
                machine.status = -3
                machine.save()

            raise Exception(e)

    for machine in aws_machines:
        machine.status = 0
        machine.save()

def stop_all_machines(cluster_id):
    aws_machines = Machine.objects.filter(cluster_id=cluster_id, provider='aws')

    for machine in aws_machines:
        machine.status = 2
        machine.save()

    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)

    if len(aws_machines) > 0:
        try:
            account_id = config['aws']['account']
            account = CloudAccount.objects.filter(id=account_id, provider='aws')[0]
            aws_account_credentials = vault_service.read_secret(account.credentials)

            aws_instances = []
            for machine in aws_machines:
                aws_instances.append(machine.instance_id)

            api_client.stop_instances(
                aws_account_credentials['aws_access_key_id'],
                aws_account_credentials['aws_secret_access_key'],
                machine.region,
                aws_instances
            )
        except Exception as e:
            for machine in aws_machines:
                machine.status = -2
                machine.save()

            raise Exception(e)

    for machine in aws_machines:
        machine.status = 10
        machine.save()

def get_tfstate_resources(tfstate):
    resources = ast.literal_eval(tfstate)['resources']
    aws_nodes = []

    for resource in resources:
        if resource['type'] == 'aws_eip':
            eips = resource['instances']
            instances = []
            for resource_option in resources:
                if resource_option['type'] == 'aws_instance':
                    for instance in resource_option['instances']:
                        instances.append(instance)
                    break
            for i in range(len(eips)):
                public_ip = eips[i]['attributes']['public_ip']
                private_ip = instances[i]['attributes']['private_ip']
                region = instances[i]['attributes']['availability_zone'][:(
                    len(instances[i]['attributes']['availability_zone']) - 1)]
                zone = instances[i]['attributes']['availability_zone']
                instance_id = instances[i]['attributes']['id']
                name = instances[i]['attributes']['tags']['Name']
                node = {
                    'user': 'clouduser',
                    'public_ip': public_ip,
                    'private_ip': private_ip,
                    'region': region,
                    'zone': zone,
                    'instance_id': instance_id,
                    'name': name
                }
                aws_nodes.append(node)

    nodes = {'aws': aws_nodes}
    return nodes

def get_machine_records(cloud_config, environment_provider, tfstate_resources, cluster_id):
    machines = []

    if 'aws' in cloud_config:
        node_counter = 1
        for node in tfstate_resources:

            machine_name = node['name'] + '.aws'

            if 'internal_dns_zone' in cloud_config:
                machine_name += '.' + cloud_config['internal_dns_zone']

            account = CloudAccount.objects.filter(id=cloud_config['aws']['account'], provider='aws')[0]
            account_regions = json.loads(account.regions)

            region_name = cloud_config['aws']['region']
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

            machine.kube_name = node['instance_id']

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
    if environment_type == constants.ClusterType.DLCM_V2.value:
        with open(os.path.join(settings.BASE_DIR + '/environment_providers/aws/terraform/config_k8s.tf'), 'r') as tf_file:
            code += tf_file.read()
    else:
        with open(os.path.join(settings.BASE_DIR + '/environment_providers/aws/terraform/config.tf'), 'r') as tf_file:
            code += tf_file.read()
    return code

def get_valid_operating_systems(payload, environment_type, user_id):
    account = models.CloudAccount.objects.filter(id=payload['accountId'], provider='aws')[0]
    aws_account_credentials = vault_service.read_secret(account.credentials)

    aws_access_key_id = aws_account_credentials['aws_access_key_id']
    aws_secret_access_key = aws_account_credentials['aws_secret_access_key']

    if environment_type == constants.ClusterType.CAPI.value:
        # CAPI
        return []
    elif environment_type == constants.ClusterType.DLCM_V2.value:
        # DLCM v2
        return api_client.get_all_available_daiteap_os_parameters(aws_access_key_id, aws_secret_access_key, payload['region'], settings.AWS_DAITEAP_IMAGE_NAME)
    else:
        return api_client.get_all_available_os_parameters(aws_access_key_id, aws_secret_access_key, payload['region'])

def validate_account_permissions(credentials, user_id, storage_enabled):
    aws_permissions_check = api_client.check_user_permissions(credentials['aws_access_key_id'],
                                                                credentials['aws_secret_access_key'],
                                                                'eu-central-1', storage_enabled
                                                                )

    if 'id' in credentials:
        tasks.worker_update_provider_regions.delay('aws', user_id, credentials['id'])

    # dlcm_v2_images = False

    # for allowed_region in api_client.ALLOWED_REGIONS: 
    #     if len(api_client.get_all_available_daiteap_os_parameters(credentials['aws_access_key_id'], credentials['aws_secret_access_key'], allowed_region)) > 0:
    #         dlcm_v2_images = True
    #         break

    # if 'Missing' in aws_permissions_check:
    #     if 'id' in credentials:
    #         cloud_account = CloudAccount.objects.get(id=credentials['id'])
    #         cloud_account.valid = False
    #         cloud_account.save()
    #     return {'error': aws_permissions_check, 'dlcmV2Images': dlcm_v2_images}

    # if 'id' in credentials:
    #     cloud_account = CloudAccount.objects.get(id=credentials['id'])
    #     if not dlcm_v2_images:
    #         cloud_account.valid = False
    #         cloud_account.save()
    #     else:
    #         cloud_account.valid = True
    #         cloud_account.save()

    # return {'dlcmV2Images': dlcm_v2_images}

    valid = True

    for region in api_client.ALLOWED_REGIONS: 
        if api_client.check_if_imageid_exists(credentials['aws_access_key_id'], credentials['aws_secret_access_key'], region, settings.AWS_DAITEAP_IMAGE_OWNER, settings.AWS_DAITEAP_IMAGE_NAME) == False:
            valid = False
            break

    if aws_permissions_check:
        if 'id' in credentials:
            cloud_account = CloudAccount.objects.get(id=credentials['id'])
            cloud_account.valid = False
            cloud_account.save()
        return {'error': aws_permissions_check, 'dlcmV2Images': valid}
    elif 'id' in credentials:
        cloud_account = CloudAccount.objects.get(id=credentials['id'])
        cloud_account.cloud_account_info = get_cloud_account_info(cloud_account)
        cloud_account.valid = valid
        cloud_account.save()

    if not valid:
        return {'error': 'Error in LCM statuses', 'dlcmV2Images': valid}

    return {'dlcmV2Images': valid}

def update_provider_regions(account_id, user_id):
    account = CloudAccount.objects.filter(id=account_id, provider='aws')[0]
    aws_account_credentials = vault_service.read_secret(account.credentials)
    try:
        aws_regions = api_client.get_available_regions_parameters(
            aws_account_credentials['aws_access_key_id'], aws_account_credentials['aws_secret_access_key'])
    except Exception as e:
        log_data = {
            'account': 'aws -' + str(account_id),
            'level': 'ERROR',
            'user_id': user_id,
            'task': 'worker_update_provider_regions',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
        account = CloudAccount.objects.filter(id=account_id, provider='aws')[0]
        account.regions_update_status = -1  # failed
        account.regions_failed_msg = str(e)
        account.save()
        return

    account = CloudAccount.objects.filter(id=account_id, provider='aws')[0]
    account.regions = json.dumps(aws_regions)
    account.regions_update_status = 0  # updated
    account.save()

def check_region_parameters(resources, user_id):
    failed_providers = {'aws': True}
    regions = json.loads(CloudAccount.objects.filter(tenant__daiteapuser__user_id=user_id,label=resources['aws']['account'], provider='aws')[0].regions)
    for region in regions:
        if region['name'] == resources['aws']['region']:
            for zone in region['zones']:
                if zone['name'] == resources['aws']['zone']:
                    for instance in zone['instances']:
                        if instance['name'] == resources['aws']['instanceType']:
                            failed_providers['aws'] = False
                            break
                    break
            break

    return failed_providers

def validate_credentials(payload, request, storage_enabled):
    aws_account = None
    if 'account_id' in payload:
        aws_account = models.CloudAccount.objects.filter(id=payload['account_id'], provider='aws')[0]

        try:
            aws_account_credentials = vault_service.read_secret(aws_account.credentials)
            aws_access_key_id = aws_account_credentials['aws_access_key_id']
            aws_secret_access_key = aws_account_credentials['aws_secret_access_key']
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
            aws_access_key_id = payload['credentials']['aws']['aws_access_key_id']
            aws_secret_access_key = payload['credentials']['aws']['aws_secret_access_key']
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

    if aws_access_key_id is not None and len(aws_access_key_id) > 0 and aws_secret_access_key is not None and len(aws_secret_access_key) > 0:
        aws_keys = {}

        aws_keys['aws_access_key_id'] = aws_access_key_id
        aws_keys['aws_secret_access_key'] = aws_secret_access_key

        if len(aws_keys['aws_access_key_id']) < 20 or len(aws_keys['aws_access_key_id']) > 20:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Invalid parameter aws_access_key_id', extra=log_data)
            raise Exception('Invalid parameter aws_access_key_id')

        if len(aws_keys['aws_secret_access_key']) < 40 or len(aws_keys['aws_secret_access_key']) > 40:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Invalid parameter aws_secret_access_key', extra=log_data)
            raise Exception('Invalid parameter aws_secret_access_key')

        if aws_account is not None:
            aws_keys['id'] = aws_account.id

        aws_keys['aws'] = True

        task = tasks.worker_validate_credentials.delay(aws_keys, request.user.id, storage_enabled)
    else:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid provider_params parameter', extra=log_data)
        raise Exception('Invalid aws_access_key_id/aws_secret_access_key parameter')

    return task

def update_cloud_credentials(payload, request):
    aws = payload['account_params']

    if 'label' in aws and 'old_label' in aws:
        if aws['old_label'] == '' or len(aws['old_label']) < 3 or len(aws['old_label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter old_label.', extra=log_data)
            raise Exception('Invalid parameter old_label.')

        if aws['label'] != '' and len(aws['label']) < 3 or len(aws['label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter label.', extra=log_data)
            raise Exception('Invalid parameter label.')

        if aws['label'] != '':
            try:
                account = models.CloudAccount.objects.filter(id=aws['old_label'],tenant_id=request.daiteap_user.tenant_id, provider='aws')[0]
                aws_account_credentials = vault_service.read_secret(account.credentials)

                new_account = False
                account.label = aws['label']
            except:
                account = models.CloudAccount(
                    label=aws['label'],
                    provider='aws'
                )
                new_account = True

            if ((new_account and len(models.CloudAccount.objects.filter(id=aws['label'],tenant_id=request.daiteap_user.tenant_id, provider='aws')) > 0) or
                (not new_account and aws['label'] != aws['old_label'] and 
                len(models.CloudAccount.objects.filter(id=aws['label'],tenant_id=request.daiteap_user.tenant_id, provider='aws')) > 0)
            ):
                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                }
                logger.error('Invalid parameter label.', extra=log_data)
                raise Exception('Invalid parameter label.')

            if new_account:
                account.save()

            if 'aws_access_key_id' in aws:
                if aws['aws_access_key_id'] != '**********' and aws['aws_access_key_id'] != '' and len(aws['aws_access_key_id']) < 20 or len(aws['aws_access_key_id']) > 20:
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                    }
                    logger.error('Invalid parameter aws_access_key_id.', extra=log_data)
                    raise Exception('Invalid parameter aws_access_key_id.')
                if aws["aws_access_key_id"] != "**********":
                    aws_account_credentials['aws_access_key_id'] = aws["aws_access_key_id"]

            if 'aws_secret_access_key' in aws:
                if aws['aws_secret_access_key'] != '**********' and aws['aws_secret_access_key'] != '' and len(aws['aws_secret_access_key']) < 40 or len(aws['aws_secret_access_key']) > 40:
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                    }
                    logger.error('Invalid parameter aws_secret_access_key.', extra=log_data)
                    raise Exception('Invalid parameter aws_secret_access_key.')
                if aws["aws_secret_access_key"] != "**********":
                    aws_account_credentials['aws_secret_access_key'] = aws["aws_secret_access_key"]

    else:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error('Invalid account_params parameter.', extra=log_data)
        raise Exception('Invalid account_params parameter.')

    account.regions_update_status = 1  # updating
    account.save()
    if not new_account and aws['label'] != aws['old_label']:
        clusters = models.Clusters.objects.filter(user=request.user.username)
        for cluster in clusters:
            config = json.loads(cluster.config)
            if 'aws' not in config:
                continue
            if config['aws']['account'] == aws['old_label']:
                config['aws']['account'] = aws['label']
                cluster.config = json.dumps(config)
                cluster.save()

    tasks.worker_update_provider_regions.delay('aws', request.user.id, account.id)

def create_cloud_credentials(payload, request, all_account_labels):
    aws = payload['account_params']

    if ('label' in aws and
        'aws_access_key_id' in aws and
        'aws_secret_access_key' in aws):
        if aws['label'] != '' and len(aws['label']) < 3 or len(aws['label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter label.', extra=log_data)
            raise Exception('Invalid parameter label.')

        if len(aws['aws_access_key_id']) < 20 or len(aws['aws_access_key_id']) > 20:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter aws_access_key_id.', extra=log_data)
            raise Exception('Invalid parameter aws_access_key_id.')

        if len(aws['aws_secret_access_key']) < 40 or len(aws['aws_secret_access_key']) > 40:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter aws_secret_access_key.', extra=log_data)
            raise Exception('Invalid parameter aws_secret_access_key.')

        if aws['label'] != '':
            if aws['label'] in all_account_labels:
                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                }
                logger.error('Account label already exists.', extra=log_data)
                raise Exception('Account label already exists.')

            account = models.CloudAccount(
                label=aws['label'],
                tenant=Tenant.objects.filter(id=request.daiteap_user.tenant_id)[0],
                provider='aws',
                contact=request.user.email,
                description=aws['description']
            )

            credentials = {}
            credentials['aws_access_key_id'] = aws["aws_access_key_id"]
            credentials['aws_secret_access_key'] = aws["aws_secret_access_key"]

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

    account.regions_update_status = 1  # updating

    try:
        account.cloud_account_info = get_cloud_account_info(account)
        account.save()
    except Exception as e:
        account.delete()
        raise Exception(e)

    tasks.worker_update_provider_regions.delay('aws', request.user.id, account.id)

def get_gateway_address_dc_private_ip_and_client_hosts(clouds, master_private_ip, gateway_address, client_hosts, config, user_id):
    if len(clouds['aws']) > 0:
        if master_private_ip == '':
            master_private_ip = clouds['aws'][0]['user'] + '@' + clouds['aws'][0]['private_ip']
            gateway_address = clouds['aws'][0]['user'] + '@' + clouds['aws'][0]['public_ip']
            for i in range(1, len(clouds['aws'])):
                client_hosts.append(clouds['aws'][i])
        else:
            for i in range(0, len(clouds['aws'])):
                client_hosts.append(clouds['aws'][i])

    return master_private_ip, gateway_address, client_hosts

def run_nodes_labels(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    provider_nodes = []
    provider_lb_nodes = []
    provider_id = 'aws:///{{ item.region }}/{{ item.id }}'
    provider = 'aws'

    for node in clouds['aws']:
        provider_nodes.append(node['instance_id'])
        provider_lb_nodes.append({"region": node['region'], "name": node['instance_id'], "id": node['instance_id']})

    ansible_client = AnsibleClient()
    ansible_client.run_nodes_labels(user_id, str(cluster.id), cluster.title, master_ip, provider_nodes, provider_lb_nodes, provider_id, gateway_address, provider)

def kubernetes_storage_integration(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    if 'aws' in resources:
        aws_lb_nodes = []

        for node in clouds['aws']:
            aws_lb_nodes.append({"name": node['instance_id'], "id": node['instance_id']})

        account = CloudAccount.objects.filter(id=resources['aws']['account'], provider='aws')[0]
        aws_account_credentials = vault_service.read_secret(account.credentials)

        environment_id = str(cluster.id)
        environment_name = cluster.title
        key_id = aws_account_credentials['aws_access_key_id']
        key_secret = aws_account_credentials['aws_secret_access_key']
        region = resources['aws']['region']
        nodes = aws_lb_nodes
        master_node_address = master_ip

        if not key_id:
            raise Exception('Invalid parameter key_id')
        if not key_secret:
            raise Exception('Invalid parameter key_secret')
        if not region:
            raise Exception('Invalid parameter region')
        if not nodes:
            raise Exception('Invalid parameter nodes')
        if not master_node_address:
            raise Exception('Invalid parameter master_node_address')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        inventory_path = FILE_BASE_DIR + '/playbooks/aws_integration/storage/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/aws_integration/storage/storage.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "keyid": key_id,
            "keysecret": key_secret,
            "region": region,
            "nodes": nodes,
            "gateway_address": gateway_address,
            "master_node_address": master_node_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
            })

        ansible_client = AnsibleClient()
        ansible_client.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

def delete_cloud_credentials(cloudaccount):
    pass

def kubernetes_delete_loadbalancer_resources(account_id, region, vpc_name, user_id, cluster_id):
    account = models.CloudAccount.objects.filter(id=account_id, provider='aws')[0]
    aws_account_credentials = vault_service.read_secret(account.credentials)

    aws_access_key_id = aws_account_credentials['aws_access_key_id']
    aws_secret_access_key = aws_account_credentials['aws_secret_access_key']

    api_client.delete_k8s_loadbalancer_resources(aws_access_key_id, aws_secret_access_key, region, vpc_name, user_id, cluster_id)

def kubernetes_loadbalancer_integration(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    aws_lb_nodes = []

    for node in clouds['aws']:
        aws_lb_nodes.append({"name": node['instance_id']})

    account = CloudAccount.objects.filter(id=resources['aws']['account'], provider='aws')[0]
    aws_account_credentials = vault_service.read_secret(account.credentials)

    environment_id = str(cluster.id)
    environment_name = cluster.title
    key_id = aws_account_credentials['aws_access_key_id']
    key_secret = aws_account_credentials['aws_secret_access_key']
    nodes = aws_lb_nodes
    master_node_address = master_ip

    if not key_id:
        raise Exception('Invalid parameter key_id')
    if not key_secret:
        raise Exception('Invalid parameter key_secret')
    if not nodes:
        raise Exception('Invalid parameter nodes')
    if not master_node_address:
        raise Exception('Invalid parameter master_node_address')
    if gateway_address == []:
        raise Exception('gateway_address is empty')

    inventory_path = FILE_BASE_DIR + '/playbooks/aws_integration/loadbalancer/hosts.ini'
    playbook_path = FILE_BASE_DIR + '/playbooks/aws_integration/loadbalancer/loadbalancer.yaml'

    if not os.path.exists(playbook_path):
        raise Exception('Playbook does not exist')

    if not os.path.exists(inventory_path):
        raise Exception('Inventory does not exist')

    extra_vars = json.dumps({
        "keyid": key_id,
        "keysecret": key_secret,
        "nodes": nodes,
        "gateway_address": gateway_address,
        "master_node_address": master_node_address,
        "ansible_python_interpreter": "/usr/bin/python3",
        "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

    ansible_client = AnsibleClient()
    ansible_client.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

def remove_nodeselector_from_ccm(resources, user_id, master_node_private_ip, gateway_address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    try:

        user_id = user_id
        environment_id = str(cluster.id)
        environment_name = cluster.title
        master_node_address = master_node_private_ip

        if not master_node_address:
            raise Exception('Invalid parameter master_node_address')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        inventory_path = FILE_BASE_DIR + '/playbooks/remove_nodeselector_from_aws_ccm/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/remove_nodeselector_from_aws_ccm/playbook.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "master_node_address": master_node_address,
            "gateway_address": gateway_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        ansible_client = AnsibleClient()
        ansible_client.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)


    except Exception as e:
        encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")

        cluster.resizestep = -10
        error_msg = {
            'message': encoded_error
        }
        cluster.error_msg = json.dumps(error_msg)
        cluster.save()

        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

def add_nodeselector_to_ccm(resources, user_id, master_node_private_ip, gateway_address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    try:
        environment_id = str(cluster.id)
        environment_name = cluster.title
        master_node_address = master_node_private_ip

        if not master_node_address:
            raise Exception('Invalid parameter master_node_address')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        inventory_path = FILE_BASE_DIR + '/playbooks/add_nodeselector_to_aws_ccm/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/add_nodeselector_to_aws_ccm/playbook.yml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "master_node_address": master_node_address,
            "gateway_address": gateway_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        ansible_client = AnsibleClient()
        ansible_client.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

    except Exception as e:
        encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")

        cluster.resizestep = -13
        error_msg = {
            'message': encoded_error
        }
        cluster.error_msg = error_msg
        cluster.save()

        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        return

def get_storageclass_name():
    return '\"ebs-sc\"'

def run_added_machines_vpn_routing(resources, user_id, cluster_id, new_machines):
    pass

def run_vpn_routing(resources, user_id, cluster_id):
    pass

def run_vpn_server(filtered_environment_providers, vpn_configs, resources, cluster_id, user_id):
    pass

def set_vpn_configs(vpn_configs, resources, vpn_secrets, vpn_provider_name, user_id):
    vpn_providers = []
    vpn_providers.append({"remote_public_ip": vpn_configs['aws'][vpn_provider_name]['public_ip1'], "remote_right_id": vpn_configs['aws'][vpn_provider_name]['public_ip1'], "remote_subnet": resources['aws']['vpcCidr'], "provider_name": "aws1", "key_exchange_version": "ikev1", "pre_shared_key": vpn_configs['aws'][vpn_provider_name]['pre_shared_key1']})
    vpn_providers.append({"remote_public_ip": vpn_configs['aws'][vpn_provider_name]['public_ip2'], "remote_right_id": vpn_configs['aws'][vpn_provider_name]['public_ip2'], "remote_subnet": resources['aws']['vpcCidr'], "provider_name": "aws2", "key_exchange_version": "ikev1", "pre_shared_key": vpn_configs['aws'][vpn_provider_name]['pre_shared_key2']})

    return vpn_providers

def get_dns_config(resources, nodes_ips, dns_servers_ips, cluster_id):
    dns_server = str(IPNetwork(resources['aws']['vpcCidr'])[2])
    internal_dns_zone = resources['internal_dns_zone']
    server_private_ip = nodes_ips['aws_server_private_ip']
    server_ip = dns_servers_ips['aws_server_ip']

    dns_config = {
        'aws': {
        'name': 'aws',
        'publicDnsServer': f'server=/aws.{ internal_dns_zone }/{ dns_server }\n',
        'privateDnsServer': f'server=/aws.{ internal_dns_zone }/{ server_private_ip }\n',
        'lastDnsServer': f'server=/#/{ dns_server }',
        'groups': 'aws-server-node',
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
    aws_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    aws_credentials = vault_service.read_secret(aws_account.credentials)

    return api_client.get_storage_buckets(payload['credential_id'], aws_credentials)

def create_storage_bucket(payload, request):
    aws_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    aws_credentials = vault_service.read_secret(aws_account.credentials)

    return api_client.create_storage_bucket(aws_credentials, payload['bucket_name'], payload['bucket_location'], request)

def delete_storage_bucket(payload, request):
    aws_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    aws_credentials = vault_service.read_secret(aws_account.credentials)

    return api_client.delete_storage_bucket(aws_credentials, payload['bucket_name'])

def get_bucket_files(payload, request):
    aws_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    aws_credentials = vault_service.read_secret(aws_account.credentials)

    return api_client.get_bucket_files(aws_credentials, payload['bucket_name'], payload['path'])

def add_bucket_file(payload, request):
    aws_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    aws_credentials = vault_service.read_secret(aws_account.credentials)

    return api_client.add_bucket_file(aws_credentials, payload['bucket_name'], payload['file_name'], payload['content_type'], payload['contents'], request.user.username)

def delete_bucket_file(payload, request):
    aws_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    aws_credentials = vault_service.read_secret(aws_account.credentials)

    return api_client.delete_bucket_file(aws_credentials, payload['bucket_name'], payload['file_name'])

def download_bucket_file(payload, request):
    aws_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    aws_credentials = vault_service.read_secret(aws_account.credentials)

    return api_client.download_bucket_file(aws_credentials, payload['bucket_name'], payload['file_name'])

def get_storage_accounts(credential_id):
    return {}

def delete_bucket_folder(payload, request):
    aws_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    aws_credentials = vault_service.read_secret(aws_account.credentials)

    return api_client.delete_bucket_folder(aws_credentials, payload['bucket_name'], payload['folder_path'])

def get_bucket_details(payload, request):
    aws_account = CloudAccount.objects.filter(id=payload['credential_id'])[0]
    aws_credentials = vault_service.read_secret(aws_account.credentials)

    return api_client.get_bucket_details(aws_credentials, payload['bucket_name'])

def get_cloud_account_info(cloud_account):
    aws_credentials = vault_service.read_secret(cloud_account.credentials)
    return api_client.get_cloud_account_info(aws_credentials)