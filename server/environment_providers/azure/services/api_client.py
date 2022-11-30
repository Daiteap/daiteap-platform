from asyncio.log import logger
import json
import os
import time
import traceback
import jwt

import msal
from azure.common import credentials
from azure.graphrbac import GraphRbacManagementClient
from azure.identity import ClientSecretCredential
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt import network
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient as SubsClient
from azure.mgmt.resource.resources.models import ResourceGroup
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import Kind, Sku, StorageAccountCreateParameters
from azure.mgmt.subscription import SubscriptionClient
from azure.storage.blob import BlobServiceClient, ContentSettings
from msgraph.core import GraphClient
from cloudcluster.models import *
from environment_providers.azure import azure
from environment_providers.azure.services.oauth import AZURE_PERMISSIONS


def get_created_cluster_resources(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret, resource_group_name):
    """ Returns all azure resources in a resource group """
    if not azure_tenant_id:
        raise AttributeError('Invalid input parameter azure_tenant_id')
    if not azure_subscription_id:
        raise AttributeError('Invalid input parameter azure_subscription_id')
    if not azure_client_id:
        raise AttributeError('Invalid input parameter azure_client_id')
    if not azure_client_secret:
        raise AttributeError('Invalid input parameter azure_client_secret')
    if not resource_group_name:
        raise AttributeError('Invalid input parameter resource_group_name')

    creds = credentials.ServicePrincipalCredentials(client_id=azure_client_id, secret=azure_client_secret, tenant=azure_tenant_id)

    client = ResourceManagementClient(creds, azure_subscription_id)

    # check if resource group exists
    try:
        resource_group = client.resource_groups.get(resource_group_name)
    except:
        return []

    all_resources_dict = []

    if resource_group:
        all_resources_dict.append(resource_group.as_dict())

        all_resources = list(client.resources.list_by_resource_group(resource_group_name))

        for resource in all_resources:
            resource_dict = resource.as_dict()
            if resource_dict['type'] == 'Microsoft.Compute/disks':
                continue
            all_resources_dict.append(resource_dict)

    return all_resources_dict

# get all azure resources
def get_all_resource_groups(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret):
    """ Returns all azure resources """
    if not azure_tenant_id:
        raise AttributeError('Invalid input parameter azure_tenant_id')
    if not azure_subscription_id:
        raise AttributeError('Invalid input parameter azure_subscription_id')
    if not azure_client_id:
        raise AttributeError('Invalid input parameter azure_client_id')
    if not azure_client_secret:
        raise AttributeError('Invalid input parameter azure_client_secret')

    creds = credentials.ServicePrincipalCredentials(client_id=azure_client_id, secret=azure_client_secret, tenant=azure_tenant_id)

    client = ResourceManagementClient(creds, azure_subscription_id)

    all_resources = []

    try:
        all_resources = list(client.resource_groups.list())
    except Exception as e:
        print(e)
        return all_resources

    return all_resources


def delete_load_balancers(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret, resource_group_name, user_id, cluster_id):
    if not azure_tenant_id:
        raise AttributeError('Invalid input parameter azure_tenant_id')
    if not azure_subscription_id:
        raise AttributeError('Invalid input parameter azure_subscription_id')
    if not azure_client_id:
        raise AttributeError('Invalid input parameter azure_client_id')
    if not azure_client_secret:
        raise AttributeError('Invalid input parameter azure_client_secret')
    if not resource_group_name:
        raise AttributeError('Invalid input parameter resource_group_name')

    creds = credentials.ServicePrincipalCredentials(
        client_id=azure_client_id, secret=azure_client_secret, tenant=azure_tenant_id)

    network_client = network.NetworkManagementClient(creds, azure_subscription_id)

    load_balancers = network_client.load_balancers.list(resource_group_name=resource_group_name)

    try:
        azure.stop_all_machines(cluster_id)
    except Exception as e:
        print(str(e))
        pass

    try:
        load_balancers = list(load_balancers)
    except Exception as e:
        print(e)
        return True

    for load_balancer in load_balancers:
        print('Deleting azure lb', load_balancer)
        network_client.load_balancers.delete(resource_group_name=resource_group_name, load_balancer_name=load_balancer.name)
        
        # wait for load balancer to be deleted
        for _ in range(0, 30):
            try:
                network_client.load_balancers.get(resource_group_name=resource_group_name, load_balancer_name=load_balancer.name)
            except Exception as e:
                print(e)
                break
            time.sleep(5)

    public_ip_addresses = network_client.public_ip_addresses.list(resource_group_name=resource_group_name)
    try:
        public_ip_addresses = list(public_ip_addresses)
    except Exception as e:
        print(e)
        return True

    for public_ip_address in public_ip_addresses:
        if public_ip_address.name.startswith('k8s-'):
            print('Deleting azure public ip', public_ip_address)
            network_client.public_ip_addresses.delete(resource_group_name=resource_group_name, public_ip_address_name=public_ip_address.name)

    return True


def resolve_service_principal(azure_tenant_id, azure_client_id, azure_client_secret):
    """Get an object_id from a client_id."""
    graphrbac_credentials = credentials.ServicePrincipalCredentials(
        client_id=azure_client_id,
        secret=azure_client_secret,
        tenant=azure_tenant_id,
        resource="https://graph.windows.net"
    )

    graphrbac_client = GraphRbacManagementClient(
        graphrbac_credentials,
        azure_tenant_id
    )

    result = list(graphrbac_client.service_principals.list(filter="servicePrincipalNames/any(c:c eq '{}')".format(azure_client_id)))

    if result:
        return result[0].object_id
    raise RuntimeError("Unable to get object_id from client_id")


def get_missing_client_permissions(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret, storage_enabled):
    """ Returns missing client permissions that are needed for Daiteap """
    if not azure_tenant_id:
        raise AttributeError('Invalid input parameter azure_tenant_id')
    if not azure_subscription_id:
        raise AttributeError('Invalid input parameter azure_subscription_id')
    if not azure_client_id:
        raise AttributeError('Invalid input parameter azure_client_id')
    if not azure_client_secret:
        raise AttributeError('Invalid input parameter azure_client_secret')

    creds = credentials.ServicePrincipalCredentials(client_id=azure_client_id, secret=azure_client_secret, tenant=azure_tenant_id)

    client_object_id = resolve_service_principal(
        azure_tenant_id=azure_tenant_id,
        azure_client_id=azure_client_id,
        azure_client_secret=azure_client_secret
    )

    auth_client = AuthorizationManagementClient(creds, azure_subscription_id)
    roles = list(auth_client.role_assignments.list_for_scope(scope='/subscriptions/{}'.format(azure_subscription_id)))

    client_role_definition_ids = []

    for role in roles:
        if role.principal_id == client_object_id:
            client_role_definition_ids.append(role.role_definition_id)

    all_client_permissions = []

    for role_def_full_Id in client_role_definition_ids:

        role_def_id = role_def_full_Id.replace('/subscriptions/{}/providers/Microsoft.Authorization/roleDefinitions/'.format(azure_subscription_id), '')

        role_definition = auth_client.role_definitions.get(scope='/subscriptions/{}'.format(azure_subscription_id), role_definition_id=role_def_id)

        for permission in role_definition.permissions:
            for action in permission.actions:
                all_client_permissions.append(action)

    missing_permissions = []

    # Check permission for Microsoft Graph API
    app = msal.ConfidentialClientApplication(
        azure_client_id,
        authority = 'https://login.microsoftonline.com/' + azure_tenant_id,
        client_credential = azure_client_secret
    )
    accessToken = app.acquire_token_for_client(scopes=['https://graph.microsoft.com/.default'])
    decodedAccessToken = jwt.decode(accessToken['access_token'], verify=False)
    if 'Directory.Read.All' not in decodedAccessToken['roles']:
        missing_permissions.append('Missing permission for Microsoft Graph')

    if '*' in all_client_permissions:
        return missing_permissions

    for needed_azure_permission in AZURE_PERMISSIONS:
        if needed_azure_permission not in all_client_permissions:
            missing_permissions.append(needed_azure_permission)

    return missing_permissions

def stop_instances(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret, resource_group_name, instances):
    if not azure_tenant_id:
        raise AttributeError('Invalid input parameter azure_tenant_id')
    if not azure_subscription_id:
        raise AttributeError('Invalid input parameter azure_subscription_id')
    if not azure_client_id:
        raise AttributeError('Invalid input parameter azure_client_id')
    if not azure_client_secret:
        raise AttributeError('Invalid input parameter azure_client_secret')
    if not resource_group_name:
        raise AttributeError('Invalid input parameter resource_group_name')
    if instances == []:
        raise AttributeError('Invalid input parameter instances')

    creds = credentials.ServicePrincipalCredentials(
        client_id=azure_client_id, secret=azure_client_secret, tenant=azure_tenant_id)
    
    compute_client = ComputeManagementClient(creds, azure_subscription_id)

    for instance in instances:
        reponse_restart = compute_client.virtual_machines.power_off(resource_group_name, instance)

    max_retries = 24
    wait_seconds = 20
    for i in range(0, max_retries):
        all_ok = True
        time.sleep(wait_seconds)
        for instance in instances:
            reponse_get = compute_client.virtual_machines.get(resource_group_name, instance, expand='instanceView')
            if reponse_get.instance_view.statuses[1].display_status != 'VM stopped':
                all_ok = False

        if all_ok:
            break

        if i == max_retries - 1:
            raise Exception('Timeout while waiting instances to stop')

    return

def start_instances(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret, resource_group_name, instances):
    if not azure_tenant_id:
        raise AttributeError('Invalid input parameter azure_tenant_id')
    if not azure_subscription_id:
        raise AttributeError('Invalid input parameter azure_subscription_id')
    if not azure_client_id:
        raise AttributeError('Invalid input parameter azure_client_id')
    if not azure_client_secret:
        raise AttributeError('Invalid input parameter azure_client_secret')
    if not resource_group_name:
        raise AttributeError('Invalid input parameter resource_group_name')
    if instances == []:
        raise AttributeError('Invalid input parameter instances')

    creds = credentials.ServicePrincipalCredentials(
        client_id=azure_client_id, secret=azure_client_secret, tenant=azure_tenant_id)
    
    compute_client = ComputeManagementClient(creds, azure_subscription_id)

    for instance in instances:
        reponse_restart = compute_client.virtual_machines.start(resource_group_name, instance)

    max_retries = 24
    wait_seconds = 20
    for i in range(0, max_retries):
        all_ok = True
        time.sleep(wait_seconds)
        for instance in instances:
            reponse_get = compute_client.virtual_machines.get(resource_group_name, instance, expand='instanceView')
            if reponse_get.instance_view.statuses[1].display_status != 'VM running':
                all_ok = False

        if all_ok:
            break

        if i == max_retries - 1:
            raise Exception('Timeout while waiting instances to stop')

    return

def restart_instances(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret, resource_group_name, instances):
    if not azure_tenant_id:
        raise AttributeError('Invalid input parameter azure_tenant_id')
    if not azure_subscription_id:
        raise AttributeError('Invalid input parameter azure_subscription_id')
    if not azure_client_id:
        raise AttributeError('Invalid input parameter azure_client_id')
    if not azure_client_secret:
        raise AttributeError('Invalid input parameter azure_client_secret')
    if not resource_group_name:
        raise AttributeError('Invalid input parameter resource_group_name')
    if instances == []:
        raise AttributeError('Invalid input parameter instances')

    stop_instances(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret, resource_group_name, instances)
    start_instances(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret, resource_group_name, instances)

    return

def get_available_regions_parameters(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret):
    allowed_regions = [
        'eastasia',
        'eastus',
        'eastus2',
        'westus',
        'northeurope',
        'westeurope',
        'australiaeast',
        'australiasoutheast',
        'westus2',
        'francecentral',
        'australiacentral',
        'switzerlandnorth',
        'germanywestcentral',
        'westus3',
        'swedencentral'
    ]
    regions = []

    creds = credentials.ServicePrincipalCredentials(client_id=azure_client_id, secret=azure_client_secret, tenant=azure_tenant_id)

    subscription_client = SubscriptionClient(creds)
    compute_client = ComputeManagementClient(creds, azure_subscription_id)
    locations = subscription_client.subscriptions.list_locations(azure_subscription_id)

    not_supported_vm_sizes = [
        'Standard_DC1s_v2',
        'Standard_DC2s_v2',
        'Standard_DC4s_v2',
        'Standard_DC8_v2',
        'Standard_M208ms_v2',
        'Standard_M208s_v2',
        'Standard_M416ms_v2',
        'Standard_M416s_v2'
    ]

    for location in locations:
        if location.name not in allowed_regions:
            continue
        region = {
            'name': location.name,
            'zones': []
        }
        zone = {
            'name': location.name,
            'instances': []
        }

        machine_types_list = get_machine_types_list(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret, region['name'])

        try:
            machines = compute_client.virtual_machine_sizes.list(location=location.name)

            region['zones'].append(zone)

            instances = []

            for instance in machines:
                if instance.name not in not_supported_vm_sizes:
                    instance_option = {
                        'name': instance.name,
                        'description': '',
                        'cpu': 0,
                        'ram': 0
                    }

                    instance_data = get_instance_type_parameters(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret, region['name'], instance.name, machine_types_list)

                    if instance_data['ram'] % 2 == 0:
                        instance_option['cpu'] = instance_data['cpu']
                        instance_option['ram'] = instance_data['ram']
                        instances.append(instance_option)

            s_cpu = min(instances, key = lambda x: abs(int(x['cpu'])-4))
            m_cpu = min(instances, key = lambda x: abs(int(x['cpu'])-8))
            l_cpu = min(instances, key = lambda x: abs(int(x['cpu'])-16))
            xl_cpu = min(instances, key = lambda x: abs(int(x['cpu'])-48))

            s_cpu_instances = []
            m_cpu_instances = []
            l_cpu_instances = []
            xl_cpu_instances = []

            for instance_type in instances:
                instance = instance_type

                if s_cpu['cpu'] == instance['cpu'] and instance['ram'] >= 8:
                    s_cpu_instances.append(instance)
                if m_cpu['cpu'] == instance['cpu'] and instance['ram'] >= 12:
                    m_cpu_instances.append(instance)
                if l_cpu['cpu'] == instance['cpu'] and instance['ram'] >= 32:
                    l_cpu_instances.append(instance)
                if xl_cpu['cpu'] == instance['cpu'] and instance['ram'] >= 64:
                    xl_cpu_instances.append(instance)

            if s_cpu_instances:
                s_ram = min(s_cpu_instances, key = lambda x: abs(int(x['ram'])-8))
                s_ram['storage'] = '50'
                s_ram['description'] = f'Small (vCPU {int(s_ram["cpu"])} | Memory {int(s_ram["ram"])} GB | Storage {int(s_ram["storage"])} GB)'
                zone['instances'].append(s_ram)
            if m_cpu_instances:
                m_ram = min(m_cpu_instances, key = lambda x: abs(int(x['ram'])-16))
                m_ram['storage'] = '100'
                m_ram['description'] = f'Medium (vCPU {int(m_ram["cpu"])} | Memory {int(m_ram["ram"])} GB | Storage {int(m_ram["storage"])} GB)'
                zone['instances'].append(m_ram)
            if l_cpu_instances:
                l_ram = min(l_cpu_instances, key = lambda x: abs(int(x['ram'])-64))
                l_ram['storage'] = '500'
                l_ram['description'] = f'Large (vCPU {int(l_ram["cpu"])} | Memory {int(l_ram["ram"])} GB | Storage {int(l_ram["storage"])} GB)'
                zone['instances'].append(l_ram)
            if xl_cpu_instances:
                xl_ram = min(xl_cpu_instances, key = lambda x: abs(int(x['ram'])-128))
                xl_ram['storage'] = '1000'
                xl_ram['description'] = f'XLarge (vCPU {int(xl_ram["cpu"])} | Memory {int(xl_ram["ram"])} GB | Storage {int(xl_ram["storage"])} GB)'
                zone['instances'].append(xl_ram)

            regions.append(region)
        except Exception as e:
            print(str(e))
            continue

    return regions

def get_machine_types_list(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret, region_name):
    creds = credentials.ServicePrincipalCredentials(client_id=azure_client_id, secret=azure_client_secret, tenant=azure_tenant_id)

    compute_client = ComputeManagementClient(creds, azure_subscription_id)

    instances = compute_client.virtual_machine_sizes.list(location=region_name)

    return instances

def get_instance_type_parameters(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret, region_name, instance_type, instances = []):
    if not instances:
        instances = get_machine_types_list(azure_tenant_id, azure_subscription_id, azure_client_id, azure_client_secret, region_name)

    for instance in instances:
        if instance_type == instance.name:
            return {
                'cpu': instance.number_of_cores,
                'ram': instance.memory_in_mb/1024
            }

    raise Exception('Can\'t find instance type.')

def get_all_available_daiteap_os_parameters(azure_client_id, azure_client_secret, azure_tenant_id, azure_subscription_id, region, publisher, offer, sku):
    # all_os_parameters = []

    # os_params = {
    #     'publisher_name': publisher,
    #     'offer': offer,
    #     'skus': [
    #         sku
    #     ]
    # }

    # debian_images = get_available_image_parameters(
    #     azure_client_id,
    #     azure_client_secret,
    #     azure_tenant_id,
    #     azure_subscription_id,
    #     os_params,
    #     region
    # )
    # ubuntu_images = get_available_image_parameters(
    #     azure_client_id,
    #     azure_client_secret,
    #     azure_tenant_id,
    #     azure_subscription_id,
    #     os_params,
    #     region
    # )

    # all_os_parameters.extend(debian_images)
    # all_os_parameters.extend(ubuntu_images)
    all_os_parameters = [
        {
        'value': '/subscriptions/af5bb549-d639-4ea4-9632-5b6aa6881cd8/resourceGroups/Packer/providers/Microsoft.Compute/galleries/Packer_image_gallery/images/dlcm-ubuntu-1804/versions/1.0.1', 
        'os': 'Ubuntu 18 LTS'
        },
        {
        'value': '/subscriptions/af5bb549-d639-4ea4-9632-5b6aa6881cd8/resourceGroups/Packer/providers/Microsoft.Compute/galleries/Packer_image_gallery/images/dlcm-ubuntu-1804-sshbug/versions/1.0.1', 
        'os': 'Ubuntu 18 LTS (sshbug) 1.0.1'
        }
    ]

    return all_os_parameters

def get_all_available_os_parameters(azure_client_id, azure_client_secret, azure_tenant_id, azure_subscription_id, region):
    all_os_parameters = []

    debian_os_params = {
        'publisher_name': 'credativ',
        'offer': 'Debian',
        'skus': [
            '9',
            # '10'
        ]
    }
    ubuntu_os_params = {
        'publisher_name': 'Canonical',
        'offer': 'UbuntuServer',
        'skus': [
            # '16.04-LTS',
            '18.04-LTS'
        ]
    }
    # centos_os_params = [
    #     '',
    #     ''
    # ]

    debian_images = get_available_image_parameters(
        azure_client_id,
        azure_client_secret,
        azure_tenant_id,
        azure_subscription_id,
        debian_os_params,
        region
    )
    ubuntu_images = get_available_image_parameters(
        azure_client_id,
        azure_client_secret,
        azure_tenant_id,
        azure_subscription_id,
        ubuntu_os_params,
        region
    )
    # centos_images = get_available_image_parameters(azure_client_id, azure_client_secret, azure_tenant_id, azure_subscription_id, centos_os_names, region)

    all_os_parameters.extend(debian_images)
    all_os_parameters.extend(ubuntu_images)
    # all_os_parameters.extend(centos_images)

    return all_os_parameters

def get_available_image_parameters(azure_client_id, azure_client_secret, azure_tenant_id, azure_subscription_id, os_params, region):
    filtered_images = []

    creds = credentials.ServicePrincipalCredentials(client_id=azure_client_id, secret=azure_client_secret, tenant=azure_tenant_id)
    compute_client = ComputeManagementClient(creds, azure_subscription_id)
    
    for sku in os_params['skus']:
        images_response = compute_client.virtual_machine_images.list(
            region,
            os_params['publisher_name'],
            os_params['offer'],
            sku
        )
        images = []
        for image in images_response:
            images.append(image)
        images = sorted(images, key=lambda x: x.name, reverse=True)
        filtered_images.append(
            {
                'value': os_params['publisher_name'] + '/' + os_params['offer'] + '/' + sku + '/' + images[0].name,
                'os': os_params['offer'] + ' ' + sku 
            }
        )

    return filtered_images

def get_storage_buckets(credential_id, azure_credentials, storage_account_url):
    credentials = ClientSecretCredential(
        azure_credentials['azure_tenant_id'],
        azure_credentials['azure_client_id'],
        azure_credentials['azure_client_secret']
    )
    blob_service_client = BlobServiceClient(account_url=storage_account_url, credential=credentials)

    response = {'buckets': []}

    containers = blob_service_client.list_containers(include_metadata=False)
    for container in containers:
        response_bucket = {
            'name': container['name'],
            'storage_class': None,
            'location': None,
            'location_type': None,
            'time_created': None,
            'provider': "azure",
            'credential_id': credential_id,
            'storage_account_url': storage_account_url,
        }
        response['buckets'].append(response_bucket)

    return response

def create_storage_bucket(azure_credentials, storage_account_url, container_name):
    credentials = ClientSecretCredential(
        azure_credentials['azure_tenant_id'],
        azure_credentials['azure_client_id'],
        azure_credentials['azure_client_secret']
    )
    blob_service_client = BlobServiceClient(account_url=storage_account_url, credential=credentials)

    container_client=blob_service_client.get_container_client(container_name)
    try:
        container_client.create_container()
        response = {'done': True}
    except Exception as e:
        if "The specified container already exists." in str(e): 
            response = {'error': 'Bucket name taken.'}
        if "ContainerAlreadyExists" in str(e): 
            response = {'error': 'Bucket name taken.'}

    return response

def delete_storage_bucket(azure_credentials, storage_account_url, container_name):
    credentials = ClientSecretCredential(
        azure_credentials['azure_tenant_id'],
        azure_credentials['azure_client_id'],
        azure_credentials['azure_client_secret']
    )
    blob_service_client = BlobServiceClient(account_url=storage_account_url, credential=credentials)

    container_client=blob_service_client.get_container_client(container_name)
    container_client.delete_container()
    return {'done': True}

def get_bucket_files(azure_credentials, storage_account_url, container_name, path):
    credentials = ClientSecretCredential(
        azure_credentials['azure_tenant_id'],
        azure_credentials['azure_client_id'],
        azure_credentials['azure_client_secret']
    )
    blob_service_client = BlobServiceClient(account_url=storage_account_url, credential=credentials)
    
    response = {'files': []}
    container_client=blob_service_client.get_container_client(container_name)
    files = container_client.list_blobs()
    dirs_in_folder = []

    try:
        for bucket_file in files:
            split_file_name = bucket_file.name.split("/")
            file_name_slash_count = len(split_file_name) - 1

            if path == "/":
                if file_name_slash_count == 0:
                    response_file = {
                        'path': bucket_file.name,
                        'basename': bucket_file.name,
                        'type': "file",
                        'content_type': bucket_file.content_settings.content_type,
                        'size': bucket_file.size,
                    }
                    response['files'].append(response_file)
                elif split_file_name[0] not in dirs_in_folder:
                    response_file = {
                        'path': split_file_name[0] + "/",
                        'basename': split_file_name[0],
                        'type': "dir",
                        'content_type': "folder",
                        'size': 0,
                    }
                    response['files'].append(response_file)
                    dirs_in_folder.append(split_file_name[0])
            else:
                if path[0] == "/":
                    path = path[1:]
                on_path = True
                split_path = path.split("/")
                path_slash_count = len(split_path) - 1

                for index in range(path_slash_count):
                    if on_path:
                        if split_file_name[index] != split_path[index]:
                            on_path = False

                if on_path:
                    if file_name_slash_count == path_slash_count and split_file_name[-1] != "":
                        response_file = {
                            'path': bucket_file.name,
                            'basename': split_file_name[-1],
                            'type': "file",
                            'content_type': bucket_file.content_settings.content_type,
                            'size': bucket_file.size,
                        }
                        response['files'].append(response_file)
                    if file_name_slash_count > path_slash_count and split_file_name[path_slash_count] not in dirs_in_folder:
                        filepath = ""
                        for index in range(len(split_path)):
                            filepath = filepath + "/" + split_file_name[index]
                        filepath = filepath + "/"

                        response_file = {
                            'path': filepath,
                            'basename': split_file_name[path_slash_count],
                            'type': "dir",
                            'content_type': "folder",
                            'size': 0,
                        }
                        response['files'].append(response_file)
                        dirs_in_folder.append(split_file_name[path_slash_count])
    except Exception as e:
        logger.error(str(traceback.format_exc()) + '\n' + str(e))

        if "AuthorizationPermissionMismatch" in str(e):
            response = {'error': "Permission issue"}
        if "This request is not authorized to perform this operation using this permission." in str(e):
            response = {'error': "Permission issue"}

    return response

def add_bucket_file(azure_credentials, storage_account_url, container_name, file_name, content_type, contents, temporary_file, request):
    credentials = ClientSecretCredential(
        azure_credentials['azure_tenant_id'],
        azure_credentials['azure_client_id'],
        azure_credentials['azure_client_secret']
    )
    blob_service_client = BlobServiceClient(account_url=storage_account_url, credential=credentials)

    container_client=blob_service_client.get_container_client(container_name)

    try:
        if content_type == "folder":
            blob_client = container_client.upload_blob(name=file_name, data="")
        else:
            bytes_from_array = bytes(contents)
            with open(temporary_file, "wb") as binary_file:
                binary_file.write(bytes_from_array)
            with open(temporary_file, "rb") as data:
                blob_client = container_client.upload_blob(name=file_name, data=data)
                blob_properties = blob_client.get_blob_properties()
                blob_client = container_client.get_blob_client(file_name)
                blob_client.set_http_headers(content_settings=ContentSettings(content_type=content_type))

                blob_tags = dict()
                blob_tags["daiteap-workspace-id"] = str(request.daiteap_user.tenant.id)
                blob_tags["daiteap-user-id"] = str(request.daiteap_user.id)
                blob_tags["daiteap-username"] = request.user.username
                blob_tags["daiteap-user-email"] = request.user.email
                blob_tags["daiteap-platform-url"] = request.headers['Origin']
                blob_tags["daiteap-workspace-name"] = request.daiteap_user.tenant.name
                try: 
                    blob_client.set_blob_tags(tags=blob_tags)
                except Exception as e:
                    if "BlobTagsNotSupportedForAccountType" in str(e):
                        pass
                    if "AuthorizationPermissionMismatch" in str(e):
                        response = {'error': "Permission issue"}
            os.remove(temporary_file)
        response = {'done': True}
    except Exception as e:
        logger.error(str(e))
        if "AuthorizationPermissionMismatch" in str(e):
            response = {'error': "Permission issue"}
        if "This request is not authorized to perform this operation using this permission." in str(e):
            response = {'error': "Permission issue"}
        if "BlobAlreadyExists" in str(e):
            response = {'error': "File name taken"}
        if "The specified blob already exists." in str(e):
            response = {'error': "File name taken"}
    
    return response

def delete_bucket_file(azure_credentials, storage_account_url, container_name, file_name):
    credentials = ClientSecretCredential(
        azure_credentials['azure_tenant_id'],
        azure_credentials['azure_client_id'],
        azure_credentials['azure_client_secret']
    )
    blob_service_client = BlobServiceClient(account_url=storage_account_url, credential=credentials)

    container_client=blob_service_client.get_container_client(container_name)
    blob_client = container_client.delete_blob(blob=file_name)
    return {'done': True}

def download_bucket_file(azure_credentials, storage_account_url, container_name, file_name):
    credentials = ClientSecretCredential(
        azure_credentials['azure_tenant_id'],
        azure_credentials['azure_client_id'],
        azure_credentials['azure_client_secret']
    )
    blob_service_client = BlobServiceClient(account_url=storage_account_url, credential=credentials)

    container_client=blob_service_client.get_container_client(container_name)
    bucket_file = container_client.download_blob(blob=file_name)
    contents = bucket_file.readall()
    contents_bytearray = list(contents)
    blob_client = container_client.get_blob_client(file_name)
    properties = blob_client.get_blob_properties()

    return {'content_type': properties.content_settings.content_type, 'contents': contents_bytearray}

def get_storage_accounts(credential_id, azure_credentials):
    credentials = ClientSecretCredential(
        tenant_id=azure_credentials['azure_tenant_id'],
        client_id=azure_credentials['azure_client_id'],
        client_secret=azure_credentials['azure_client_secret']
    )
    storage_client = StorageManagementClient(credentials, azure_credentials['azure_subscription_id'])

    response = {'storage_accounts': []}

    storage_accounts = storage_client.storage_accounts.list()
    for storage_account in storage_accounts:
        response['storage_accounts'].append({'name': storage_account.name, 'credential_id': credential_id})

    return response

def delete_bucket_folder(azure_credentials, storage_account_url, container_name, folder_path):
    credentials = ClientSecretCredential(
        azure_credentials['azure_tenant_id'],
        azure_credentials['azure_client_id'],
        azure_credentials['azure_client_secret']
    )
    blob_service_client = BlobServiceClient(account_url=storage_account_url, credential=credentials)

    if folder_path[0] == "/":
        folder_path = folder_path[1:]
    
    files = get_bucket_files(azure_credentials, storage_account_url, container_name, folder_path)['files']
    for bucket_file in files:
        if bucket_file['content_type'] == "folder":
            delete_bucket_folder(azure_credentials, storage_account_url, container_name, bucket_file['path'])
        else:
            delete_bucket_file(azure_credentials, storage_account_url, container_name, bucket_file['path'])
    container_client=blob_service_client.get_container_client(container_name)
    blob_client = container_client.delete_blob(blob=folder_path)

    return {'done': True}

def get_bucket_details(azure_credentials, storage_account_url, container_name):
    credentials = ClientSecretCredential(
        azure_credentials['azure_tenant_id'],
        azure_credentials['azure_client_id'],
        azure_credentials['azure_client_secret']
    )
    blob_service_client = BlobServiceClient(account_url=storage_account_url, credential=credentials)

    response = {'bucket_details': []}

    container_client=blob_service_client.get_container_client(container_name)
    container_info = container_client.get_container_properties()

    return response

def create_storage_account(azure_credentials, storage_account_name, storage_account_type, location, resource_group_name):
    credentials = ClientSecretCredential(
        azure_credentials['azure_tenant_id'],
        azure_credentials['azure_client_id'],
        azure_credentials['azure_client_secret']
    )
    storage_client = StorageManagementClient(credentials, azure_credentials['azure_subscription_id'])

    storage_account = StorageAccountCreateParameters(
        sku=Sku(name=storage_account_type),
        kind=Kind.storage,
        location=location
    )

    storage_client.storage_accounts.begin_create(resource_group_name, storage_account_name, storage_account)
    return {'done': True}

def create_resource_group(azure_credentials, resource_group_name, location):
    credentials = ServicePrincipalCredentials(
        tenant = azure_credentials['azure_tenant_id'],
        client_id = azure_credentials['azure_client_id'],
        secret = azure_credentials['azure_client_secret']
    )
    resource_client = ResourceManagementClient(credentials, azure_credentials['azure_subscription_id'])

    resource_group = ResourceGroup(location=location)
    resource_client.resource_groups.create_or_update(resource_group_name, resource_group)
    return {'done': True}

def delete_storage_account(azure_credentials, storage_account_name, resource_group_name):
    credentials = ClientSecretCredential(
        azure_credentials['azure_tenant_id'],
        azure_credentials['azure_client_id'],
        azure_credentials['azure_client_secret']
    )
    storage_client = StorageManagementClient(credentials, azure_credentials['azure_subscription_id'])

    storage_client.storage_accounts.delete(resource_group_name, storage_account_name)
    return {'done': True}

def delete_resource_group(azure_credentials, resource_group_name):
    credentials = ServicePrincipalCredentials(
        tenant = azure_credentials['azure_tenant_id'],
        client_id = azure_credentials['azure_client_id'],
        secret = azure_credentials['azure_client_secret']
    )
    resource_client = ResourceManagementClient(credentials, azure_credentials['azure_subscription_id'])

    resource_client.resource_groups.delete(resource_group_name)
    return {'done': True}

def get_cloud_account_info(azure_credentials):
    graph_credentials = ClientSecretCredential(
        azure_credentials['azure_tenant_id'],
        azure_credentials['azure_client_id'],
        azure_credentials['azure_client_secret']
    )
    subscription_credentials = ServicePrincipalCredentials(
        tenant = azure_credentials['azure_tenant_id'],
        client_id = azure_credentials['azure_client_id'],
        secret = azure_credentials['azure_client_secret']
    )

    msgraph_client = GraphClient(credential=graph_credentials)
    subscription_client = SubsClient(subscription_credentials)
    
    cloud_data = dict()

    application = msgraph_client.get("/applications?$filter=appId eq '" + azure_credentials['azure_client_id'] + "'").json()
    cloud_data['application'] = application['value'][0]['displayName']
    app_id = application['value'][0]['id']

    app_owners = msgraph_client.get('/applications/' + app_id + '/owners').json()
    if len(app_owners['value']) > 0:
        cloud_data['created_by'] = app_owners['value'][0]['displayName']
        try:
            cloud_data['user_principal_name'] = app_owners['value'][0]['userPrincipalName']
        except:
            cloud_data['user_principal_name'] = ""

    cloud_data['organization'] = msgraph_client.get('/organization').json()['value'][0]['displayName']

    for subscription in subscription_client.subscriptions.list():
        if subscription.subscription_id == azure_credentials['azure_subscription_id']:
            cloud_data['subscription'] = subscription.display_name
    for tenant in subscription_client.tenants.list():
        if tenant.tenant_id == azure_credentials['azure_tenant_id']:
            if tenant.display_name:
                cloud_data['tenant'] = tenant.display_name

    return cloud_data['user_principal_name']