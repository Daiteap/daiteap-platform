import ast
import base64
import json
import logging
import os
import pathlib
import time
import traceback
import uuid

from cloudcluster import settings
from cloudcluster.models import (CapiCluster, YaookCapiCluster, CloudAccount, Clusters, Machine,
                                 Tenant, TenantSettings)
from cloudcluster.v1_0_0 import tasks
from cloudcluster.v1_0_0.services import vault_service, constants
from cloudcluster.v1_0_0.ansible.ansible_client import AnsibleClient
from cloudcluster.v1_0_0.services.cloud_providers import (
    validate_cloud_provider_regions_zones_instance_types_capi,
    validate_cloud_provider_regions_zones_instance_types_yaookcapi,
    validate_cloud_provider_regions_zones_instance_types_custom_nodes)
from django.http.response import JsonResponse
from environment_providers import environment_providers
from environment_providers.openstack.services import api_client
from environment_providers.aws.services import api_client as aws_api_client

from cloudcluster.v1_0_0.services import environment_creation_steps

FILE_BASE_DIR = str(pathlib.Path(__file__).parent.absolute())

logger = logging.getLogger(__name__)

def get_created_cluster_resources(cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    tfconfig = json.loads(cluster.config)

    openstack_account = CloudAccount.objects.filter(id=tfconfig['openstack']['account'], provider='openstack')[0]
    openstack_credentials = vault_service.read_secret(openstack_account.credentials)

    resources_dict = api_client.get_created_cluster_resources(
        openstack_credentials,
        cluster.name
    )

    return resources_dict

def get_planned_resources_for_creation(terraform_plan, name_prefix):
    planned_resources = terraform_plan['planned_values']['root_module']['resources']

    cluster_resources = []

    for planned_resource in planned_resources:
        if planned_resource['type'].startswith('openstack_') and ('name' in planned_resource['values'] and planned_resource['values']['name'].startswith(name_prefix)):

            cluster_resources.append(planned_resource)

    return cluster_resources

def destroy_resources(resources, user_id, cluster, internal_dns_zone):
    tf_variables = get_tf_variables(resources, cluster, internal_dns_zone)
    delete_disks(cluster, user_id)

    return tf_variables

def delete_disks(cluster, user_id):
    cluster = Clusters.objects.filter(id=cluster.id)
    resources = {}
    if len(cluster) == 0:
        cluster = CapiCluster.objects.filter(id=cluster.id)[0]
        if len(cluster) == 0:
            cluster = YaookCapiCluster.objects.filter(id=cluster.id)[0]
    else:
        cluster = cluster[0]

    resources = json.loads(cluster.config)

    account = CloudAccount.objects.filter(id=resources['openstack']['account'], tenant__daiteapuser__user_id=user_id, provider='openstack')[0]
    credentials = vault_service.read_secret(account.credentials)

    api_client.delete_disk_resources(
        credentials,
        str(cluster.id),
        cluster.name
    )

def destroy_disk_resources(cluster_id):
    return

def get_tf_variables(resources, cluster, internal_dns_zone, tag_values=None):
    tf_variables = {}

    account = CloudAccount.objects.filter(id=resources['account'], provider='openstack')[0]
    account_credentials = vault_service.read_secret(account.credentials)

    region_name = account_credentials['region_name']
    auth_url = account_credentials['auth_url']
    application_credential_id = account_credentials['application_credential_id']
    application_credential_secret = account_credentials['application_credential_secret']
    external_network_id = account_credentials['external_network_id']

    tf_variables['openstack_application_credential_id'] = application_credential_id
    tf_variables['openstack_application_credential_secret'] = application_credential_secret
    tf_variables['openstack_auth_url'] = auth_url
    tf_variables['openstack_region'] = region_name
    tf_variables['openstack_external_network_id'] = external_network_id
    tf_variables['openstack_user'] = settings.SSH_USERNAME
    tf_variables['openstack_environment_id'] = str(cluster.id)
    tf_variables['openstack_environment_name'] = cluster.name
    tf_variables['openstack_vpc_cidr'] = resources['vpcCidr']

    if tag_values:
        tf_variables['openstack_daiteap_username'] = tag_values['username']
        tf_variables['openstack_daiteap_user_email'] = tag_values['email']
        tf_variables['openstack_daiteap_platform_url'] = tag_values['url']
        tf_variables['openstack_daiteap_workspace_name'] = tag_values['tenant_name']

    instances = []

    for node in resources['nodes']:
        instance_type = node['instanceType']

        instance_storage = get_instance_storage(account, region_name, instance_type)

        instances.append({
            'instance_name': node['name'],
            'instance_image': node['operatingSystem'],
            'instance_type': instance_type,
            'instance_storage': instance_storage,
            'zone': ''
        })

        if 'zone' in node:
            instances[-1]['zone'] = node['zone']

    instances_str = json.dumps(instances)
    tf_variables['openstack_instances'] = instances_str
    return tf_variables

def get_instance_storage(account, region_name, instance_type):
    instance_storage = 50

    account_regions = json.loads(account.regions)

    for region in account_regions:
        if region['name'] == region_name:
            for zone in region['zones']:
                for instance in zone['instances']:
                    if instance['name'] == instance_type:
                        instance_storage = instance['storage']
                        break
    return instance_storage


def validate_regions_zones_instance_types(provider_data, user, environment_type):
    if environment_type == constants.ClusterType.CAPI.value:
        validate_cloud_provider_regions_zones_instance_types_capi(provider_data, user)
    elif environment_type == constants.ClusterType.YAOOKCAPI.value:
        validate_cloud_provider_regions_zones_instance_types_yaookcapi(provider_data, user)
    else:
        validate_cloud_provider_regions_zones_instance_types_custom_nodes(provider_data, user)

def get_provider_config_params(payload, user):
    config = {}
    config['openstack'] = {
        'region': payload['openstack']['region'],
        'nodes': payload['openstack']['nodes'],
        'vpcCidr': payload['openstack']['vpcCidr'],
        'account': payload['openstack']['account']
    }

    return config

def get_provider_capi_config_params(payload, user):
    config = {}
    config['openstack'] = {
        'region': payload['openstack']['region'],
        'workerNodes': payload['openstack']['workerNodes'],
        'controlPlane': payload['openstack']['controlPlane'],
        'account': payload['openstack']['account']
    }

    return config

def get_provider_yaookcapi_config_params(payload, user):
    config = {}
    config['openstack'] = {
        'region': payload['openstack']['region'],
        'workerNodes': payload['openstack']['workerNodes'],
        'controlPlane': payload['openstack']['controlPlane'],
        'account': payload['openstack']['account']
    }

    return config

def restart_machine(config, user_id, machine):
    account_id = config['openstack']['account']
    account = CloudAccount.objects.filter(id=account_id, provider='openstack')[0]
    credentials = vault_service.read_secret(account.credentials)

    api_client.restart_instances(
        credentials,
        [
            machine.instance_id
        ]
    )

def start_machine(cluster_id, user_id, machine):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)

    try:
        account_id = config['openstack']['account']
        account = CloudAccount.objects.filter(id=account_id, provider='openstack')[0]
        credentials = vault_service.read_secret(account.credentials)

        api_client.start_instances(
            credentials,
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
        account_id = config['openstack']['account']
        account = CloudAccount.objects.filter(id=account_id, provider='openstack')[0]
        credentials = vault_service.read_secret(account.credentials)

        api_client.stop_instances(
            credentials,
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
    openstack_machines = Machine.objects.filter(cluster_id=cluster_id, provider='openstack')

    for machine in openstack_machines:
        machine.status = 1
        machine.save()

    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)

    if len(openstack_machines) > 0:
        try:
            account_id = config['openstack']['account']
            account = CloudAccount.objects.filter(id=account_id, provider='openstack')[0]
            credentials = vault_service.read_secret(account.credentials)

            openstack_instances = []
            for machine in openstack_machines:
                openstack_instances.append(machine.instance_id)

            api_client.start_instances(
                credentials,
                openstack_instances
            )
        except Exception as e:
            for machine in openstack_machines:
                machine.status = -1
                machine.save()

            raise Exception(e)

    for machine in openstack_machines:
        machine.status = 0
        machine.save()

def restart_all_machines(cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)
    openstack_machines = Machine.objects.filter(cluster_id=cluster_id, provider='openstack')

    for machine in openstack_machines:
        machine.status = 3
        machine.save()

    if len(openstack_machines) > 0:
        try:
            account_id = config['openstack']['account']
            account = CloudAccount.objects.filter(id=account_id, provider='openstack')[0]
            credentials = vault_service.read_secret(account.credentials)

            openstack_instances = []
            for machine in openstack_machines:
                openstack_instances.append(machine.instance_id)

            api_client.restart_instances(
                credentials,
                openstack_instances
            )
        except Exception as e:
            for machine in openstack_machines:
                machine.status = -3
                machine.save()

            raise Exception(e)
    
    for machine in openstack_machines:
        machine.status = 0
        machine.save()

def stop_all_machines(cluster_id):
    openstack_machines = Machine.objects.filter(cluster_id=cluster_id, provider='openstack')

    for machine in openstack_machines:
        machine.status = 2
        machine.save()

    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)

    if len(openstack_machines) > 0:
        try:
            account_id = config['openstack']['account']
            account = CloudAccount.objects.filter(id=account_id, provider='openstack')[0]
            credentials = vault_service.read_secret(account.credentials)

            openstack_instances = []
            for machine in openstack_machines:
                openstack_instances.append(machine.instance_id)

            api_client.stop_instances(
                credentials,
                openstack_instances
            )
        except Exception as e:
            for machine in openstack_machines:
                machine.status = -2
                machine.save()

            raise Exception(e)

    for machine in openstack_machines:
        machine.status = 10
        machine.save()

def get_tfstate_resources(tfstate):
    resources = ast.literal_eval(tfstate)['resources']
    openstack_nodes = []

    for resource in resources:
        if resource['type'] == 'openstack_compute_instance_v2':
            instances = resource['instances']
            for i in range(len(instances)):
                public_ip = ''
                for sub_resource in resources:
                    if sub_resource['type'] == 'openstack_compute_floatingip_associate_v2':
                        floating_ips = sub_resource['instances']
                        for y in range(len(floating_ips)):
                            if floating_ips[y]['attributes']['instance_id'] == instances[i]['attributes']['id']:
                                public_ip = floating_ips[y]['attributes']['floating_ip']
                private_ip = instances[i]['attributes']['network'][0]['fixed_ip_v4']
                region = instances[i]['attributes']['region']
                zone = instances[i]['attributes']['availability_zone']
                name = instances[i]['attributes']['name']
                instance_id = instances[i]['attributes']['id']
                node = {
                    'user': 'clouduser',
                    'private_ip': private_ip,
                    'region': region,
                    'zone': zone,
                    'name': name,
                    'instance_id': instance_id
                }
                if public_ip != '':
                    node['public_ip'] = public_ip
                openstack_nodes.append(node)

    tfstate_resources = {'openstack': sorted(openstack_nodes, key=lambda x: x['name'])}
    return tfstate_resources

def get_machine_records(cloud_config, environment_provider, tfstate_resources, cluster_id):

    machines = []

    if 'openstack' in cloud_config:
        node_counter = 1
        for node in tfstate_resources:

            machine_name = node['name'] + '.openstack'

            if 'internal_dns_zone' in cloud_config:
                machine_name += '.' + cloud_config['internal_dns_zone']

            account = CloudAccount.objects.filter(id=cloud_config['openstack']['account'], provider='openstack')[0]
            account_regions = json.loads(account.regions)

            region_name = cloud_config['openstack']['region']
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
    with open(os.path.join(settings.BASE_DIR + '/environment_providers/openstack/terraform/config.tf'), 'r') as tf_file:
        code += tf_file.read()
    return code

def get_valid_operating_systems(payload, environment_type, user_id):
    account = CloudAccount.objects.filter(id=payload['accountId'], provider='openstack')[0]
    credentials = vault_service.read_secret(account.credentials)

    if environment_type == constants.ClusterType.CAPI.value:
        # CAPI
        return api_client.get_all_available_os_parameters(credentials, True)
    elif environment_type == constants.ClusterType.YAOOKCAPI.value:
        # YaookCapi
        return api_client.get_all_available_os_parameters(credentials, False, True)
    elif environment_type == constants.ClusterType.DLCM_V2.value:
        # DLCM v2
        return api_client.get_all_available_daiteap_os_parameters(credentials)
    else:
        return api_client.get_all_available_os_parameters(credentials, False)

def validate_account_permissions(credentials, user_id, storage_enabled):
    api_client.get_machine_types_list(credentials)

    tenant_settings = TenantSettings.objects.filter(tenant__daiteapuser__user_id=user_id)[0]
    capi_images = True
    if tenant_settings.enable_kubernetes_capi == True:
        capi_images = len(api_client.get_all_available_os_parameters(credentials, True)) > 0

    yaookcapi_images = True
    if tenant_settings.enable_kubernetes_yaookcapi == True:
        yaookcapi_images = len(api_client.get_all_available_os_parameters(credentials, False, True)) > 0

    dlcm_v2_images = len(api_client.get_all_available_daiteap_os_parameters(credentials)) > 0

    external_network = not not api_client.get_external_network_by_id(credentials)

    if 'id' in credentials:
        tasks.worker_update_provider_regions.delay('openstack', user_id, credentials['id'])

        cloud_account = CloudAccount.objects.get(id=credentials['id'])
        if not capi_images or not yaookcapi_images or not dlcm_v2_images or not external_network:
            cloud_account.valid = False
            cloud_account.save()
        else:
            cloud_account.valid = True
            cloud_account.save()

    if not capi_images or not yaookcapi_images or not dlcm_v2_images or not external_network:
        return {'error': 'Error in LCM statuses', 'capiImages': capi_images, 'yaookCapiImages': yaookcapi_images, 'dlcmV2Images': dlcm_v2_images, 'externalNetwork': external_network}

    return {'capiImages': capi_images, 'yaookCapiImages': yaookcapi_images, 'dlcmV2Images': dlcm_v2_images, 'externalNetwork': external_network}

def update_provider_regions(account_id, user_id):
    account = CloudAccount.objects.filter(id=account_id, provider='openstack')[0]
    credentials = vault_service.read_secret(account.credentials)

    if 'ssh_key_name' not in credentials:
        credentials['ssh_key_name'] = str(uuid.uuid4())
        account = CloudAccount.objects.filter(id=account_id, provider='openstack')[0]

        vault_service.upsert_secret(account.credentials, credentials)
        account.save()

    try:
        regions = api_client.get_available_regions_parameters(credentials)
        api_client.create_capi_ssh_key(credentials)
    except Exception as e:
        log_data = {
            'account': 'openstack -' + str(account_id),
            'level': 'ERROR',
            'user_id': user_id,
            'task': 'worker_update_provider_regions',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
        account = CloudAccount.objects.filter(id=account_id, provider='openstack')[0]
        account.regions_update_status = -1  # failed
        account.regions_failed_msg = str(e)
        account.save()
        return

    account = CloudAccount.objects.filter(id=account_id, provider='openstack')[0]
    account.regions = json.dumps(regions)
    account.regions_update_status = 0  # updated
    account.save()

def check_region_parameters(resources, user_id):
    failed_providers = {'openstack': True}
    regions = json.loads(CloudAccount.objects.filter(tenant__daiteapuser__user_id=user_id,label=resources['openstack']['account'], provider='openstack')[0].regions)
    for region in regions:
        if region['name'] == resources['openstack']['region']:
            for zone in region['zones']:
                if zone['name'] == resources['openstack']['zone']:
                    for instance in zone['instances']:
                        if instance['name'] == resources['openstack']['instanceType']:
                            failed_providers['openstack'] = False
                            break
                    break
            break

    return failed_providers

def validate_credentials(payload, request, storage_enabled):
    openstack_account = None
    if 'account_id' in payload:
        openstack_account = CloudAccount.objects.filter(id=payload['account_id'], provider='openstack')[0]

        try:
            region_name = vault_service.read_secret(openstack_account.credentials)['region_name']
            auth_url = vault_service.read_secret(openstack_account.credentials)['auth_url']
            application_credential_id = vault_service.read_secret(openstack_account.credentials)['application_credential_id']
            application_credential_secret = vault_service.read_secret(openstack_account.credentials)['application_credential_secret']
            external_network_id = vault_service.read_secret(openstack_account.credentials)['external_network_id']
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
            region_name = payload['credentials']['openstack']['region_name']
            auth_url = payload['credentials']['openstack']['auth_url']
            application_credential_id = payload['credentials']['openstack']['application_credential_id']
            application_credential_secret = payload['credentials']['openstack']['application_credential_secret']
            external_network_id = payload['credentials']['openstack']['external_network_id']
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


    if (region_name != '' and auth_url != '' and application_credential_id != '' and len(application_credential_id) == 32 and 
        application_credential_secret != '' and external_network_id != '' and len(external_network_id) == 36):
        resources = {
            'region_name': region_name,
            'auth_url': auth_url,
            'application_credential_id': application_credential_id,
            'application_credential_secret': application_credential_secret,
            'external_network_id': external_network_id,
            'openstack': True
        }

        if openstack_account is not None:
            resources['id'] = openstack_account.id

        task = tasks.worker_validate_credentials.delay(resources, request.user.id, storage_enabled)
    else:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid credentials parameters', extra=log_data)
        raise Exception('Invalid credentials parameters')

    return task

def update_cloud_credentials(payload, request, username):
    openstack = payload['account_params']

    if 'label' in openstack and 'old_label' in openstack:
        if openstack['old_label'] == '' or len(openstack['old_label']) < 3 or len(openstack['old_label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter old_label.', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter old_label.'
                }
            }, status=400)

        if openstack['label'] != '' and len(openstack['label']) < 3 or len(openstack['label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter label.', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter label.'
                }
            }, status=400)

        if openstack['label'] != '':
            try:
                account = CloudAccount.objects.filter(id=openstack['old_label'],tenant__daiteapuser__user__username=username, provider='openstack')[0]
                new_account = False
                account.label = openstack['label']
            except:
                new_account = True
                account = CloudAccount(
                    label=openstack['label']
                )

            if ((new_account and len(CloudAccount.objects.filter(id=openstack['label'],tenant__daiteapuser__user__username=username, provider='openstack')) > 0) or
                (not new_account and openstack['label'] != openstack['old_label'] and 
                len(CloudAccount.objects.filter(id=openstack['label'],tenant__daiteapuser__user__username=username)) > 0)
            ):
                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                }
                logger.error('Invalid parameter label.', extra=log_data)
                return JsonResponse({
                    'error': {
                        'message': 'Invalid parameter label.'
                    }
                }, status=400)

            if new_account:
                account.save()

            if 'region_name' in openstack:
                if (openstack['region_name'] != '**********' and openstack['region_name'] != '' and
                    len(openstack['region_name']) < 3 or len(openstack['region_name']) > 15):
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                    }
                    logger.error('Invalid parameter region_name.', extra=log_data)
                    return JsonResponse({
                        'error': {
                            'message': 'Invalid parameter region_name.'
                        }
                    }, status=400)
            if 'auth_url' in openstack:
                if (openstack['auth_url'] != '**********' and openstack['auth_url'] != '' and
                    len(openstack['auth_url']) < 3 or len(openstack['auth_url']) > 100):
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                    }
                    logger.error('Invalid parameter auth_url.', extra=log_data)
                    return JsonResponse({
                        'error': {
                            'message': 'Invalid parameter auth_url.'
                        }
                    }, status=400)
            if 'application_credential_id' in openstack:
                if (openstack['application_credential_id'] != '**********' and
                    openstack['application_credential_id'] != '' and len(openstack['application_credential_id']) != 32):
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                    }
                    logger.error('Invalid parameter application_credential_id.', extra=log_data)
                    return JsonResponse({
                        'error': {
                            'message': 'Invalid parameter application_credential_id.'
                        }
                    }, status=400)
            if 'external_network_id' in openstack:
                if (openstack['external_network_id'] != '**********' and
                    openstack['external_network_id'] != '' and len(openstack['external_network_id']) != 36):
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                    }
                    logger.error('Invalid parameter external_network_id.', extra=log_data)
                    return JsonResponse({
                        'error': {
                            'message': 'Invalid parameter external_network_id.'
                        }
                    }, status=400)
            if 'application_credential_secret' in openstack:
                if (openstack['application_credential_secret'] != '**********' and
                    openstack['application_credential_secret'] != '' and
                    len(openstack['application_credential_secret']) < 3 or
                    len(openstack['application_credential_secret']) > 150):
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                    }
                    logger.error('Invalid parameter application_credential_secret.', extra=log_data)
                    return JsonResponse({
                        'error': {
                            'message': 'Invalid parameter application_credential_secret.'
                        }
                    }, status=400)

    else:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error('Invalid account_params parameter.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid account_params parameter.'
            }
        }, status=400)
    
    account.regions_update_status = 1  # updating
    account.save()
    if not new_account and openstack['label'] != openstack['old_label']:
        clusters = Clusters.objects.filter(user=request.user.username)
        for cluster in clusters:
            config = json.loads(cluster.config)
            if 'openstack' not in config:
                continue
            if config['openstack']['account'] == openstack['old_label']:
                config['openstack']['account'] = openstack['label']
                cluster.config = json.dumps(config)
                cluster.save()

    tasks.worker_update_provider_regions.delay('openstack', request.user.id, account.id)

def create_cloud_credentials(payload, request, all_account_labels):
    openstack = payload['account_params']

    if ('label' in openstack and 'region_name' in openstack and 'auth_url' in openstack and 'external_network_id' in openstack and
        'application_credential_id' in openstack and 'application_credential_secret' in openstack):
        if openstack['label'] != '' and len(openstack['label']) < 3 or len(openstack['label']) > 100:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter label.', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter label.'
                }
            }, status=400)

        if openstack['region_name'] == '':
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter region_name.', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter region_name.'
                }
            }, status=400)

        if openstack['auth_url'] == '':
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter auth_url.', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter auth_url.'
                }
            }, status=400)

        if openstack['application_credential_id'] == '' or len(openstack['application_credential_id']) != 32:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter application_credential_id.', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter application_credential_id.'
                }
            }, status=400)

        if openstack['external_network_id'] == '' or len(openstack['external_network_id']) != 36:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter external_network_id.', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter external_network_id.'
                }
            }, status=400)

        if openstack['application_credential_secret'] == '':
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error('Invalid parameter application_credential_secret.', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter application_credential_secret.'
                }
            }, status=400)

        if openstack['label'] != '':
            if openstack['label'] in all_account_labels:
                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                }
                logger.error('Account label already exists.', extra=log_data)
                return JsonResponse({
                    'error': {
                        'message': 'Account label already exists.'
                    }
                }, status=400)

            account = CloudAccount(
                label=openstack['label'],
                tenant=Tenant.objects.filter(id=request.daiteap_user.tenant_id)[0],
                provider='openstack',
                contact=request.user.email,
                description=openstack['description']
            )

            credentials = {
                    'application_credential_id': openstack['application_credential_id'],
                    'application_credential_secret': openstack['application_credential_secret'],
                    'region_name': openstack['region_name'],
                    'external_network_id': openstack['external_network_id'],
                    'auth_url': openstack['auth_url']
                }

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
        return JsonResponse({
            'error': {
                'message': 'Invalid account_params parameter.'
            }
        }, status=400)

    account.regions_update_status = 1  # updating
    account.save()

    tasks.worker_update_provider_regions.delay('openstack', request.user.id, account.id)

def get_gateway_address_dc_private_ip_and_client_hosts(clouds, master_private_ip, gateway_address, client_hosts, config, user_id):
    if len(clouds['openstack']) > 0:
        if master_private_ip == '':
            master_private_ip = clouds['openstack'][0]['user'] + '@' + clouds['openstack'][0]['private_ip']
            gateway_address = clouds['openstack'][0]['user'] + '@' + clouds['openstack'][0]['public_ip']
            for i in range(1, len(clouds['openstack'])):
                client_hosts.append(clouds['openstack'][i])
        else:
            for i in range(0, len(clouds['openstack'])):
                client_hosts.append(clouds['openstack'][i])

    return master_private_ip, gateway_address, client_hosts

def run_nodes_labels(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    provider_nodes = []
    provider_lb_nodes = []
    provider_id = '' #TODO: Set provider id
    provider = 'openstack'

    for node in clouds['openstack']:
        provider_nodes.append(node['name'])

    ansible_client = AnsibleClient()
    ansible_client.run_nodes_labels(user_id, str(cluster.id), cluster.title, master_ip, provider_nodes, provider_lb_nodes, provider_id, gateway_address, provider)

def kubernetes_storage_integration(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    pass

def remove_nodeselector_from_ccm(resources, user_id, master_node_private_ip, gateway_address, cluster_id):
    pass

def get_storageclass_name():
    return '' #TODO: change value

def run_added_machines_vpn_routing(resources, user_id, cluster_id, new_machines):
    pass

def run_vpn_routing(resources, user_id, cluster_id):
    pass

def run_vpn_server(filtered_environment_providers, vpn_configs, resources, cluster_id, user_id):
    pass

def get_dns_config(resources, nodes_ips, dns_servers_ips, cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    machines = Machine.objects.filter(cluster=cluster)

    dns_server_nodes_addresses = []
    for machine in machines:
        if machine.provider == 'openstack':
            dns_server_nodes_addresses.append({'hostname': machine.name, 'private_ip': machine.privateIP})

    internal_dns_zone = resources['internal_dns_zone']
    server_private_ip = nodes_ips['openstack_server_private_ip']
    server_ip = dns_servers_ips['openstack_server_ip']

    dns_config = {
        'openstack': {
        'name': 'openstack',
        'publicDnsServer': f'server=/openstack.{ internal_dns_zone }/{ server_private_ip }\n',
        'privateDnsServer': f'server=/openstack.{ internal_dns_zone }/{ server_private_ip }\n',
        'lastDnsServer': f'server=/#/8.8.8.8',
        'groups': 'openstack-server-node',
        'serverName': f'{ server_ip }',
        'dns_server_nodes_addresses': dns_server_nodes_addresses
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
    ansible_client = AnsibleClient()

    machines = Machine.objects.filter(cluster=cluster, provider='openstack')

    openstack_new_nodes = []

    for machine in machines:
        if machine.privateIP in new_nodes_privateips:
            openstack_new_nodes.append({'private_ip': machine.privateIP, 'hostname': machine.name})

    try:
        ansible_client.run_add_dns_address(user_id, str(cluster.id), cluster.title, openstack_new_nodes, server_private_ip, gateway_address)
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

    ansible_client.run_dns(user_id, str(cluster.id), cluster.title, nodes_ips, dns_servers, gateway_address, dns_servers_ips, json.loads(cluster.config)['internal_dns_zone'], supported_provider, providers_dns_configs['openstack']['dns_server_nodes_addresses'], v2=v2)

def get_user_friendly_params(provider_config, is_capi = False, is_yaookcapi = False):
    try:
        credentials = json.loads(CloudAccount.objects.filter(id=provider_config['account'], provider='openstack')[0].credentials)
        os_parameters = api_client.get_all_available_os_parameters(credentials, is_capi)
        regions = api_client.get_available_regions_parameters(credentials)

        if is_capi:
            set_user_firendly_names(provider_config, os_parameters, regions, provider_config['workerNodes'])
            set_user_firendly_names(provider_config, os_parameters, regions, provider_config['controlPlane'])
        elif is_yaookcapi:
            set_user_firendly_names(provider_config, os_parameters, regions, provider_config['workerNodes'])
            set_user_firendly_names(provider_config, os_parameters, regions, provider_config['controlPlane'])
        else:
            set_user_firendly_names(provider_config, os_parameters, regions, provider_config['nodes'])

    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'task': 'get_user_friendly_params',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

    return provider_config

def set_user_firendly_names(provider_config, os_parameters, regions, all_nodes):
    for node in all_nodes:
        for os_parameter in os_parameters:
            if os_parameter['value'] == node['operatingSystem']:
                node['operatingSystemName'] = os_parameter['os']

        for region in regions:
            if region['name'] == provider_config['region']:
                for zone in region['zones']:
                    for instance in zone['instances']:
                        if instance['name'] == node['instanceType']:
                            node['instanceTypeName'] = instance['description']
                            break

def get_autosuggested_params():
    return {
        'region_name': settings.AUTOSUGGEST_OPENSTACK_REGION
    }

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