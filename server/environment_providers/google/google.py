import ast
import base64
import json
import logging
import os
import pathlib
import traceback
import re

from cloudcluster import models, settings
from cloudcluster.models import CloudAccount, Clusters, Machine, Tenant
from cloudcluster.v1_0_0 import tasks
from cloudcluster.v1_0_0.services import vault_service, constants
from cloudcluster.v1_0_0.ansible.ansible_client import AnsibleClient
from cloudcluster.v1_0_0.services.cloud_providers import (
    validate_cloud_provider_regions_zones_instance_types,
    validate_cloud_provider_regions_zones_instance_types_custom_nodes)
from django.http.response import JsonResponse
from environment_providers import environment_providers
from environment_providers.google.services import api_client
from google.oauth2 import service_account

FILE_BASE_DIR = str(pathlib.Path(__file__).parent.absolute())

logger = logging.getLogger(__name__)

def get_created_cluster_resources(cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    tfconfig = json.loads(cluster.config)

    google_account = CloudAccount.objects.filter(id=tfconfig['google']['account'], provider='google')[0]
    google_key = vault_service.read_secret(google_account.credentials)['google_key']

    resources_dict = api_client.get_created_cluster_resources(google_key, cluster.name)
    return resources_dict

def get_planned_resources_for_creation(terraform_plan, name_prefix):
    planned_resources = terraform_plan['planned_values']['root_module']['resources']

    cluster_resources = []

    for planned_resource in planned_resources:
        if planned_resource['type'].startswith('google_') and ('name' in planned_resource['values'] and planned_resource['values']['name'].startswith(name_prefix)):
            cluster_resources.append(planned_resource)

    return cluster_resources

def destroy_resources(resources, user_id, cluster, internal_dns_zone):
    tf_variables = get_tf_variables(resources, cluster, internal_dns_zone)

    return tf_variables

def destroy_disk_resources(resources):
    google_account = CloudAccount.objects.filter(id=resources['google']['account'], provider='google')[0]
    google_key = vault_service.read_secret(google_account.credentials)['google_key']
    # Clean disk resources
    for node in resources['google']['nodes']:
        api_client.delete_disk_resources(
            google_key,
            node['zone']
        )
    
    return

def get_tf_variables(resources, cluster, internal_dns_zone, tag_values=None):
    tf_variables = {}

    account = CloudAccount.objects.filter(id=resources['account'], provider='google')[0]
    google_key = vault_service.read_secret(account.credentials)['google_key']

    google_project = json.loads(google_key)['project_id']

    tf_variables['google_credentials_file'] = google_key
    tf_variables['google_environment_id'] = str(cluster.id)
    tf_variables['google_public_key_name'] = cluster.name
    tf_variables['google_public_key_path'] = '/var/.ssh/id_rsa.pub'
    tf_variables['google_vpc_name'] = cluster.name
    tf_variables['google_internal_dns_zone'] = 'google.' + internal_dns_zone + '.'
    tf_variables['google_user'] = 'clouduser'
    tf_variables['google_region'] = resources['region']
    tf_variables['google_project'] = google_project
    tf_variables['google_vpc_cidr'] = resources['vpcCidr']

    if tag_values:
        tf_variables['google_daiteap_username'] = (re.sub('[^0-9a-zA-Z-_]+', '_', tag_values['username']).lower())
        tf_variables['google_daiteap_user_email'] = (re.sub('[^0-9a-zA-Z-_]+', '_', tag_values['email']).lower())
        tf_variables['google_daiteap_platform_url'] = (re.sub('[^0-9a-zA-Z-_]+', '_', tag_values['url']).lower())
        tf_variables['google_daiteap_workspace_name'] = (re.sub('[^0-9a-zA-Z-_]+', '_', tag_values['tenant_name']).lower())

    region_name = resources['region']

    instances = []

    for node in resources['nodes']:
        instance_operating_system = node['operatingSystem']
        instance_type = node['instanceType']
        instance_storage = 50

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
            'instance_image': instance_operating_system,
            'instance_type': instance_type,
            'instance_storage': instance_storage,
            'zone': node['zone']
        })

    instances_str = json.dumps(instances)
    tf_variables['google_instances'] = instances_str

    return tf_variables

def validate_regions_zones_instance_types(provider_data, user, environment_type):
    if environment_type == constants.ClusterType.CAPI.value:
        validate_cloud_provider_regions_zones_instance_types(provider_data, user)
    else:
        validate_cloud_provider_regions_zones_instance_types_custom_nodes(provider_data, user)

def get_provider_config_params(payload, user):
    config = {}
    config['google'] = {
        'region': payload['google']['region'],
        'nodes': payload['google']['nodes'],
        'vpcCidr': payload['google']['vpcCidr'],
        'account': payload['google']['account']
    }

    return config

def restart_machine(config, user_id, machine):
    account_id = config['google']['account']
    account = CloudAccount.objects.filter(id=account_id, provider='google')[0]
    google_key = vault_service.read_secret(account.credentials)['google_key']

    api_client.restart_instances(
        google_key,
        machine.zone,
        [
            machine.name.split('.')[0]
        ]
    )

def start_machine(cluster_id, user_id, machine):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)

    try:
        account_id = config['google']['account']
        account = CloudAccount.objects.filter(id=account_id, provider='google')[0]
        google_key = vault_service.read_secret(account.credentials)['google_key']

        api_client.start_instances(
            google_key,
            machine.zone,
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
        account_id = config['google']['account']
        account = CloudAccount.objects.filter(id=account_id, provider='google')[0]
        google_key = vault_service.read_secret(account.credentials)['google_key']

        api_client.stop_instances(
            google_key,
            machine.zone,
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
    google_machines = Machine.objects.filter(cluster_id=cluster_id, provider='google')

    for machine in google_machines:
        machine.status = 1
        machine.save()

    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)

    if len(google_machines) > 0:
        try:
            account_id = config['google']['account']
            account = CloudAccount.objects.filter(id=account_id, provider='google')[0]
            google_key = vault_service.read_secret(account.credentials)['google_key']

            google_instances = []
            for machine in google_machines:
                google_instances.append(machine.name.split('.')[0])

            api_client.start_instances(
                google_key,
                machine.zone,
                google_instances
            )
        except Exception as e:
            for machine in google_machines:
                machine.status = -1
                machine.save()

            raise Exception(e)

    for machine in google_machines:
        machine.status = 0
        machine.save()

def restart_all_machines(cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)
    google_machines = Machine.objects.filter(cluster_id=cluster_id, provider='google')

    for machine in google_machines:
        machine.status = 3
        machine.save()

    if len(google_machines) > 0:
        try:
            account_id = config['google']['account']
            account = CloudAccount.objects.filter(id=account_id, provider='google')[0]
            google_key = vault_service.read_secret(account.credentials)['google_key']

            google_instances = []
            for machine in google_machines:
                google_instances.append(machine.name.split('.')[0])

            api_client.restart_instances(
                google_key,
                machine.zone,
                google_instances
            )
        except Exception as e:
            for machine in google_machines:
                machine.status = -3
                machine.save()
            
            raise Exception(e)
    
    for machine in google_machines:
        machine.status = 0
        machine.save()

def stop_all_machines(cluster_id):
    google_machines = Machine.objects.filter(cluster_id=cluster_id, provider='google')

    for machine in google_machines:
        machine.status = 2
        machine.save()

    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)

    if len(google_machines) > 0:
        try:
            account_id = config['google']['account']
            account = CloudAccount.objects.filter(id=account_id, provider='google')[0]
            google_key = vault_service.read_secret(account.credentials)['google_key']

            google_instances = []
            for machine in google_machines:
                google_instances.append(machine.name.split('.')[0])

            api_client.stop_instances(
                google_key,
                machine.zone,
                google_instances
            )
        except Exception as e:
            for machine in google_machines:
                machine.status = -2
                machine.save()
            
            raise Exception(e)

        for machine in google_machines:
            machine.status = 10
            machine.save()

def get_tfstate_resources(tfstate):
    resources = ast.literal_eval(tfstate)['resources']
    google_nodes = []

    for resource in resources:
        if resource['type'] == 'google_compute_instance':
            instances = resource['instances']
            for i in range(len(instances)):
                public_ip = ''
                if len(instances[i]['attributes']['network_interface'][0]['access_config']) > 0:
                    public_ip = instances[i]['attributes']['network_interface'][0]['access_config'][0]['nat_ip']
                private_ip = instances[i]['attributes']['network_interface'][0]['network_ip']
                region = instances[i]['attributes']['zone'][:(
                    len(instances[i]['attributes']['zone']) - 2)]
                zone = instances[i]['attributes']['zone']
                name = instances[i]['attributes']['name']
                node = {
                    'user': 'clouduser',
                    'private_ip': private_ip,
                    'region': region,
                    'zone': zone,
                    'name': name
                }
                if public_ip != '':
                    node['public_ip'] = public_ip
                google_nodes.append(node)

    nodes = {'google': sorted(google_nodes, key=lambda x: x['name'])}
    return nodes

def get_machine_records(cloud_config, environment_provider, tfstate_resources, cluster_id):
    machines = []

    if 'google' in cloud_config:
        node_counter = 1
        for node in tfstate_resources:

            machine_name = node['name'] + '.google'

            if 'internal_dns_zone' in cloud_config:
                machine_name += '.' + cloud_config['internal_dns_zone']

            account = CloudAccount.objects.filter(id=cloud_config['google']['account'], provider='google')[0]
            account_regions = json.loads(account.regions)

            region_name = cloud_config['google']['region']
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
    with open(os.path.join(settings.BASE_DIR + '/environment_providers/google/terraform/config.tf'), 'r') as tf_file:
        code += tf_file.read()
    return code

def get_valid_operating_systems(payload, environment_type, user_id):
    account = models.CloudAccount.objects.filter(id=payload['accountId'], provider='google')[0]
    google_key = vault_service.read_secret(account.credentials)['google_key']

    if environment_type == constants.ClusterType.CAPI.value:
        # CAPI
        return []
    elif environment_type == constants.ClusterType.DLCM_V2.value:
        # DLCM v2
        project = settings.GCP_DAITEAP_IMAGE_PROJECT
        return api_client.get_all_available_daiteap_os_parameters(google_key, project)
    elif environment_type in [constants.ClusterType.DLCM.value, constants.ClusterType.VMS.value, constants.ClusterType.COMPUTE_VMS.value]:
        # Compute
        return api_client.get_compute_all_available_os_parameters(google_key)
    else:
        return api_client.get_all_available_os_parameters(google_key)

def validate_account_permissions(credentials, user_id, storage_enabled):
    if 'id' not in credentials:
        api_client.add_cloud_account_to_daiteap_project(credentials['google_key'])

    dns_api_enabled = api_client.check_dns_api_enabled(credentials['google_key'])

    if not dns_api_enabled:
        if 'id' in credentials:
            cloud_account = CloudAccount.objects.get(id=credentials['id'])
            cloud_account.valid = False
            cloud_account.save()
        return {'error': 'DNS API is not enabled for this account'}

    compute_api_enabled = api_client.check_compute_api_enabled(credentials['google_key'])

    if not compute_api_enabled:
        if 'id' in credentials:
            cloud_account = CloudAccount.objects.get(id=credentials['id'])
            cloud_account.valid = False
            cloud_account.save()
        return {'error': 'Compute API is not enabled for this account'}

    google_permissions_check = api_client.check_user_permissions(credentials['google_key'], storage_enabled)

    cloud_asset_api_enabled = api_client.check_cloud_asset_api_enabled(credentials['google_key'])

    if not cloud_asset_api_enabled:
        if 'id' in credentials:
            cloud_account = CloudAccount.objects.get(id=credentials['id'])
            cloud_account.valid = False
            cloud_account.save()
        return {'error': 'Cloud Asset API is not enabled for this account'}

    if 'id' in credentials:
        tasks.worker_update_provider_regions.delay('google', user_id, credentials['id'])

    project = settings.GCP_DAITEAP_IMAGE_PROJECT
    dlcm_v2_images = len(api_client.get_all_available_daiteap_os_parameters(credentials['google_key'], project)) > 0

    if google_permissions_check:
        if 'id' in credentials:
            cloud_account = CloudAccount.objects.get(id=credentials['id'])
            cloud_account.valid = False
            cloud_account.save()
        else:
            api_client.remove_cloud_account_from_daiteap_project(credentials['google_key'])
        return {'error': google_permissions_check, 'dlcmV2Images': dlcm_v2_images}

    if 'id' in credentials:
        cloud_account = CloudAccount.objects.get(id=credentials['id'])
        if not dlcm_v2_images:
            cloud_account.valid = False
            cloud_account.save()
        else:
            cloud_account.valid = True
            cloud_account.save()
    else:
        api_client.remove_cloud_account_from_daiteap_project(credentials['google_key'])

    if not dlcm_v2_images:
        return {'error': 'Error in LCM statuses', 'dlcmV2Images': dlcm_v2_images}

    return {'dlcmV2Images': dlcm_v2_images}

def update_provider_regions(account_id, user_id):
    account = CloudAccount.objects.filter(id=account_id, provider='google')[0]
    google_key = vault_service.read_secret(account.credentials)['google_key']
    try:
        regions = api_client.get_available_regions_parameters(google_key)
    except Exception as e:
        log_data = {
            'account': 'google -' + str(account_id),
            'level': 'ERROR',
            'user_id': user_id,
            'task': 'worker_update_provider_regions',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
        account = CloudAccount.objects.filter(id=account_id, provider='google')[0]
        account.regions_update_status = -1  # failed
        account.regions_failed_msg = str(e)
        account.save()
        return

    account = CloudAccount.objects.filter(id=account_id, provider='google')[0]
    account.regions = json.dumps(regions)
    account.regions_update_status = 0  # updated
    account.save()

def check_region_parameters(resources, user_id):
    failed_providers = {'google': True}
    regions = json.loads(CloudAccount.objects.filter(tenant__daiteapuser__user_id=user_id,label=resources['google']['account'], provider='google')[0].regions)
    for region in regions:
        if region['name'] == resources['google']['region']:
            for zone in region['zones']:
                if zone['name'] == resources['google']['zone']:
                    for instance in zone['instances']:
                        if instance['name'] == resources['google']['instanceType']:
                            failed_providers['google'] = False
                            break
                    break
            break

    return failed_providers

def validate_credentials(payload, request, storage_enabled):
    google_account = None
    if 'account_id' in payload:
        google_account = models.CloudAccount.objects.filter(id=payload['account_id'], provider='google')[0]
        try:
            google_key = vault_service.read_secret(google_account.credentials)['google_key']
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
            google_key = payload['credentials']['google']['google_key']
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

    if google_key is not None and len(google_key) > 0:
        resources = {'google_key': google_key, 'google': True}

        if google_account is not None:
            resources['id'] = google_account.id

        task = tasks.worker_validate_credentials.delay(resources, request.user.id, storage_enabled)
    else:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid google_key parameter', extra=log_data)
        raise Exception('Invalid google_key parameter')

    return task

def update_cloud_credentials(payload, request):
    google = payload['account_params']

    if 'label' in google and 'old_label' in google:
        if google['old_label'] == '' or len(google['old_label']) < 3 or len(google['old_label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter old_label.', extra=log_data)
            raise Exception('Invalid parameter old_label.')

        if google['label'] != '' and len(google['label']) < 3 or len(google['label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter label.', extra=log_data)
            raise Exception('Invalid parameter label.')

        if google['label'] != '':
            try:
                account = models.CloudAccount.objects.filter(label=google['old_label'],tenant_id=request.daiteap_user.tenant_id, provider='google')[0]
                new_account = False
                account.label = google['label']
            except:
                new_account = True
                account = models.CloudAccount(
                    label=google['label'],
                    contact=request.user.email,
                    provider='google',
                    user=request.user,
                )

            if (
                (new_account and len(models.CloudAccount.objects.filter(label=google['label'],user=request.user, provider='google')) > 0)
                 or
                (not new_account and google['label'] != google['old_label'] and len(models.CloudAccount.objects.filter(label=google['label'],tenant_id=request.daiteap_user.tenant_id)) > 0)):
                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                }
                logger.error('Invalid parameter label.', extra=log_data)
                raise Exception('Invalid parameter label.')

            if new_account:
                account.tenant = models.Tenant.objects.get(id=request.daiteap_user.tenant_id)
                account.save()

            if 'google_key' in google:
                credentials = {'google_key': google['google_key']}

                account.credentials = "none"
                account.user = request.user

                account.save()

                try:
                    credentials_path = f"secret/{request.daiteap_user.tenant_id}/{account.id}/credentials"
                    vault_service.upsert_secret(credentials_path, credentials)

                    account.credentials = credentials_path
                    account.save()

                    api_client.add_cloud_account_to_daiteap_project(google['google_key'])

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
    if not new_account and google['label'] != google['old_label']:
        clusters = models.Clusters.objects.filter(user=request.user.username)
        for cluster in clusters:
            config = json.loads(cluster.config)
            if 'google' not in config:
                continue
            if config['google']['account'] == google['old_label']:
                config['google']['account'] = google['label']
                cluster.config = json.dumps(config)
                cluster.save()

    tasks.worker_update_provider_regions.delay('google', request.user.id, account.id)

def create_cloud_credentials(payload, request, all_account_labels):
    google = payload['account_params']

    if 'label' in google and 'google_key' in google:
        if google['label'] != '' and len(google['label']) < 3 or len(google['label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter label.', extra=log_data)
            raise Exception('Invalid parameter label.')

        if len(google['google_key']) < 10 or len(google['google_key']) > 5000:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter google_key.', extra=log_data)
            raise Exception('Invalid parameter google_key.')
        try:
            json.loads(google['google_key'])['project_id']
        except Exception as e:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter google_key.', extra=log_data)
            raise Exception('Invalid parameter google_key.')

        if google['label'] != '':
            if google['label'] in all_account_labels:
                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                }
                logger.error('Account label already exists.', extra=log_data)
                raise Exception('Account label already exists.')

            account = models.CloudAccount(
                label=google['label'],
                tenant=Tenant.objects.filter(id=request.daiteap_user.tenant_id)[0],
                provider='google',
                contact=request.user.email,
                description=google['description']
            )
            account.user = request.user
            credentials = {'google_key': google['google_key']}

            account.credentials = "none"
            account.user = request.user

            account.save()

            try:
                credentials_path = f"secret/{request.daiteap_user.tenant_id}/{account.id}/credentials"
                vault_service.upsert_secret(credentials_path, credentials)

                account.credentials = credentials_path
                account.save()

                # Add cloud account to daiteap image project
                api_client.add_cloud_account_to_daiteap_project(google['google_key'])

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

    tasks.worker_update_provider_regions.delay('google', request.user.id, account.id)

def delete_cloud_credentials(cloudaccount):
    api_client.remove_cloud_account_from_daiteap_project(vault_service.read_secret(cloudaccount.credentials)['google_key'])

def get_gateway_address_dc_private_ip_and_client_hosts(clouds, master_private_ip, gateway_address, client_hosts, config, user_id):
    if len(clouds['google']) > 0:
        if master_private_ip == '':
            master_private_ip = clouds['google'][0]['user'] + '@' + clouds['google'][0]['private_ip']
            gateway_address = clouds['google'][0]['user'] + '@' + clouds['google'][0]['public_ip']
            for i in range(1, len(clouds['google'])):
                client_hosts.append(clouds['google'][i])
        else:
            for i in range(0, len(clouds['google'])):
                client_hosts.append(clouds['google'][i])

    return master_private_ip, gateway_address, client_hosts

def run_nodes_labels(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    provider_nodes = []
    provider_lb_nodes = []
    provider_id = 'gce://{{ item.project_id }}/{{ item.zone }}/{{ item.name }}'
    provider = 'google'

    google_account = CloudAccount.objects.filter(id=resources['google']['account'],tenant__daiteapuser__user_id=user_id, provider='google')[0]
    google_project = json.loads(vault_service.read_secret(google_account.credentials)['google_key'])['project_id']

    for node in clouds['google']:
        provider_lb_nodes.append({"zone": node['zone'], "name": node['name'], "project_id": google_project})
        provider_nodes.append(node['name'])

    ansible_client = AnsibleClient()
    ansible_client.run_nodes_labels(user_id, str(cluster.id), cluster.title, master_ip, provider_nodes, provider_lb_nodes, provider_id, gateway_address, provider)

def kubernetes_storage_integration(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    if 'google' in resources:
        google_lb_nodes = []

        for node in clouds['google']:
            google_lb_nodes.append({"name": node['name']})

        account = CloudAccount.objects.filter(id=resources['google']['account'], provider='google')[0]

        environment_id = str(cluster.id)
        environment_name = cluster.title
        cloud_sa = base64.b64encode(vault_service.read_secret(account.credentials)['google_key'].encode('ascii')).decode('utf-8')
        nodes = google_lb_nodes
        master_node_address=master_ip

        if not cloud_sa:
            raise Exception('Invalid parameter cloud_sa')
        if not nodes:
            raise Exception('Invalid parameter nodes')
        if not master_node_address:
            raise Exception('Invalid parameter master_node_address')
        if not gateway_address:
            raise Exception('Invalid parameter gateway_address')

        inventory_path = FILE_BASE_DIR + '/playbooks/google_integration/storage/hosts.ini'
        playbook_path = FILE_BASE_DIR + '/playbooks/google_integration/storage/storage.yaml'

        if not os.path.exists(playbook_path):
            raise Exception('Playbook does not exist')

        if not os.path.exists(inventory_path):
            raise Exception('Inventory does not exist')

        extra_vars = json.dumps({
            "cloud_sa": cloud_sa,
            "nodes": nodes,
            "gateway_address": gateway_address,
            "master_node_address": master_node_address,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
        })

        ansible_client = AnsibleClient()
        ansible_client.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

def kubernetes_delete_loadbalancer_resources(account_id, region, vpc_name, user_id, cluster_id):
    account = CloudAccount.objects.filter(id=account_id, provider='google')[0]
    google_key = vault_service.read_secret(account.credentials)['google_key']

    api_client.delete_loadbalancer_resources(google_key, region, vpc_name, user_id, cluster_id)

def kubernetes_loadbalancer_integration(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    google_lb_nodes = []

    for node in clouds['google']:
        google_lb_nodes.append({"name": node['name']})

    account = CloudAccount.objects.filter(id=resources['google']['account'], provider='google')[0]

    google_project = json.loads(vault_service.read_secret(account.credentials)['google_key'])['project_id']

    environment_id = str(cluster.id)
    environment_name = cluster.title
    project_id = google_project
    nodes = google_lb_nodes
    master_node_address = master_ip

    if not project_id:
        raise Exception('Invalid parameter project_id')
    if not nodes:
        raise Exception('Invalid parameter nodes')
    if not master_node_address:
        raise Exception('Invalid parameter master_node_address')
    if gateway_address == []:
        raise Exception('gateway_address is empty')

    inventory_path = FILE_BASE_DIR + '/playbooks/google_integration/loadbalancer/hosts.ini'
    playbook_path = FILE_BASE_DIR + '/playbooks/google_integration/loadbalancer/loadbalancer.yaml'

    if not os.path.exists(playbook_path):
        raise Exception('Playbook does not exist')

    if not os.path.exists(inventory_path):
        raise Exception('Inventory does not exist')

    extra_vars = json.dumps({
        "project_id": project_id,
        "nodes": nodes,
        "gateway_address": gateway_address,
        "master_node_address": master_node_address,
        "ansible_python_interpreter": "/usr/bin/python3",
        "ansible_ssh_private_key_file": "/var/.ssh/id_rsa"
    })

    ansible_client = AnsibleClient()
    ansible_client.run_playbook(user_id, environment_id, environment_name, playbook_path=playbook_path, inventory_path=inventory_path, extra_vars=extra_vars)

def remove_nodeselector_from_ccm(resources, user_id, dc_ip, gateway_address, cluster_id):
    pass

def add_nodeselector_to_ccm(resources, user_id, dc_ip, gateway_address, cluster_id):
    pass

def get_storageclass_name():
    return '\"csi-gcepd\"'

def run_added_machines_vpn_routing(resources, user_id, cluster_id, new_machines):
    pass

def run_vpn_routing(resources, user_id, cluster_id):
    pass

def run_vpn_server(filtered_environment_providers, vpn_configs, resources, cluster_id, user_id):
    pass

def set_vpn_configs(vpn_configs, resources, vpn_secrets, vpn_provider_name, user_id):
    vpn_provider = [{"remote_public_ip": vpn_configs['google'][vpn_provider_name]['public_ip'], "remote_right_id": vpn_configs['google'][vpn_provider_name]['public_ip'], "remote_subnet": resources['google']['vpcCidr'], "provider_name": "google", "key_exchange_version": "ikev2", "pre_shared_key": vpn_configs['google'][vpn_provider_name]['pre_shared_key']}]

    return vpn_provider

def get_dns_config(resources, nodes_ips, dns_servers_ips, cluster_id):
    dns_server = "169.254.169.254"
    internal_dns_zone = resources['internal_dns_zone']
    server_private_ip = nodes_ips['google_server_private_ip']
    server_ip = dns_servers_ips['google_server_ip']

    dns_config = {
        'google': {
        'name': 'google',
        'publicDnsServer': f'server=/google.{ internal_dns_zone }/{ dns_server }\n',
        'privateDnsServer': f'server=/google.{ internal_dns_zone }/{ server_private_ip }\n',
        'lastDnsServer': f'server=/#/{ dns_server }',
        'groups': 'google-server-node',
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
    google_account = models.CloudAccount.objects.filter(id=payload['credential_id'])[0]

    google_key = vault_service.read_secret(google_account.credentials)['google_key']
    credentials_json = json.loads(google_key)
    google_credentials = service_account.Credentials.from_service_account_info(credentials_json)
    google_project = json.loads(vault_service.read_secret(google_account.credentials)['google_key'])['project_id']

    return api_client.get_storage_buckets(payload['credential_id'], google_credentials, google_project)

def create_storage_bucket(payload, request):
    google_account = models.CloudAccount.objects.filter(id=payload['credential_id'])[0]

    google_key = vault_service.read_secret(google_account.credentials)['google_key']
    credentials_json = json.loads(google_key)
    google_credentials = service_account.Credentials.from_service_account_info(credentials_json)
    google_project = json.loads(vault_service.read_secret(google_account.credentials)['google_key'])['project_id']

    return api_client.create_storage_bucket(google_credentials, google_project, payload['bucket_name'], payload['storage_class'], payload['bucket_location'], request)

def delete_storage_bucket(payload, request):
    google_account = models.CloudAccount.objects.filter(id=payload['credential_id'])[0]

    google_key = vault_service.read_secret(google_account.credentials)['google_key']
    credentials_json = json.loads(google_key)
    google_credentials = service_account.Credentials.from_service_account_info(credentials_json)
    google_project = json.loads(vault_service.read_secret(google_account.credentials)['google_key'])['project_id']

    return api_client.delete_storage_bucket(google_credentials, google_project, payload['bucket_name'])

def get_bucket_files(payload, request):
    google_account = models.CloudAccount.objects.filter(id=payload['credential_id'])[0]

    google_key = vault_service.read_secret(google_account.credentials)['google_key']
    credentials_json = json.loads(google_key)
    google_credentials = service_account.Credentials.from_service_account_info(credentials_json)
    google_project = json.loads(vault_service.read_secret(google_account.credentials)['google_key'])['project_id']

    return api_client.get_bucket_files(google_credentials, google_project, payload['bucket_name'], payload['path'])

def add_bucket_file(payload, request):
    google_account = models.CloudAccount.objects.filter(id=payload['credential_id'])[0]

    google_key = vault_service.read_secret(google_account.credentials)['google_key']
    credentials_json = json.loads(google_key)
    google_credentials = service_account.Credentials.from_service_account_info(credentials_json)
    google_project = json.loads(vault_service.read_secret(google_account.credentials)['google_key'])['project_id']

    return api_client.add_bucket_file(google_credentials, google_project, payload['bucket_name'], payload['file_name'], payload['content_type'], payload['contents'], request.user.username)

def delete_bucket_file(payload, request):
    google_account = models.CloudAccount.objects.filter(id=payload['credential_id'])[0]

    google_key = vault_service.read_secret(google_account.credentials)['google_key']
    credentials_json = json.loads(google_key)
    google_credentials = service_account.Credentials.from_service_account_info(credentials_json)
    google_project = json.loads(vault_service.read_secret(google_account.credentials)['google_key'])['project_id']

    return api_client.delete_bucket_file(google_credentials, google_project, payload['bucket_name'], payload['file_name'])

def download_bucket_file(payload, request):
    google_account = models.CloudAccount.objects.filter(id=payload['credential_id'])[0]

    google_key = vault_service.read_secret(google_account.credentials)['google_key']
    credentials_json = json.loads(google_key)
    google_credentials = service_account.Credentials.from_service_account_info(credentials_json)
    google_project = json.loads(vault_service.read_secret(google_account.credentials)['google_key'])['project_id']

    return api_client.download_bucket_file(google_credentials, google_project, payload['bucket_name'], payload['file_name'])

def get_storage_accounts(payload, request):
    return {}

def delete_bucket_folder(payload, request):
    google_account = models.CloudAccount.objects.filter(id=payload['credential_id'])[0]

    google_key = vault_service.read_secret(google_account.credentials)['google_key']
    credentials_json = json.loads(google_key)
    google_credentials = service_account.Credentials.from_service_account_info(credentials_json)
    google_project = json.loads(vault_service.read_secret(google_account.credentials)['google_key'])['project_id']

    return api_client.delete_bucket_folder(google_credentials, google_project, payload['bucket_name'], payload['folder_path'])

def get_bucket_details(payload, request):
    google_account = models.CloudAccount.objects.filter(id=payload['credential_id'])[0]

    google_key = vault_service.read_secret(google_account.credentials)['google_key']
    credentials_json = json.loads(google_key)
    google_credentials = service_account.Credentials.from_service_account_info(credentials_json)
    google_project = json.loads(vault_service.read_secret(google_account.credentials)['google_key'])['project_id']

    return api_client.get_bucket_details(google_credentials, google_project, payload['bucket_name'])