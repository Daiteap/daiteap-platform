import json
import time
import os
import re

from google.oauth2 import service_account
from googleapiclient import discovery
from googleapiclient.errors import HttpError
from google.cloud import storage
from environment_providers.google import google

from cloudcluster.settings import DAITEAP_GOOGLE_KEY, DAITEAP_GOOGLE_IMAGE_KEY
from cloudcluster.models import *
from cloudcluster import settings

def get_created_cluster_resources(google_key, name_prefix):
    if not google_key:
        raise AttributeError('Invalid input parameter google_key')

    credentials_json = json.loads(google_key)
    credentials = service_account.Credentials.from_service_account_info(credentials_json)
    service = discovery.build('cloudasset', 'v1', credentials=credentials)

    project = credentials_json['project_id']

    request = service.assets().list(parent='projects/' + project)
    response = request.execute()

    resources_list = []
    for resource in response['assets']:
        if 'name' in resource and resource['assetType'] != 'compute.googleapis.com/Disk':
            if resource['name'].split('/')[-1].startswith(name_prefix):
                resources_list.append(resource)

    # get dns managed zones
    dns_service = discovery.build('dns', 'v1', credentials=credentials)
    request = dns_service.managedZones().list(project=credentials_json['project_id'])
    response = request.execute()

    dns_managed_zones = []
    for zone in response['managedZones']:
        if zone['name'].startswith(name_prefix):
            dns_managed_zones.append(zone['name'])
            resources_list.append(zone)

    #  get dns managed records
    for zone in dns_managed_zones:
        request = dns_service.resourceRecordSets().list(project=credentials_json['project_id'], managedZone=zone)
        response = request.execute()

        for record in response['rrsets']:
            if record['name'].split('.')[0].startswith(name_prefix):
                resources_list.append(record)

    return resources_list

def delete_disk_resources(google_key, zone):
    if not google_key:
        raise AttributeError('Invalid input parameter google_key')
    if not zone:
        raise AttributeError('Invalid input parameter zone')

    credentials_json = json.loads(google_key)
    credentials = service_account.Credentials.from_service_account_info(
        credentials_json)
    service = discovery.build('compute', 'v1', credentials=credentials)

    project = credentials_json['project_id']

    disks_list = service.disks().list(
        project=credentials_json['project_id'], zone=zone).execute()

    if 'items' not in disks_list:
        return False

    for disk in disks_list['items']:
        if 'id' in disk and 'name' in disk and 'description' in disk and "pv-disk-daiteap-" in disk['name'] and 'Disk created by GCE-PD CSI Driver' in disk['description'] and 'users' not in disk:
            print('Deleting google disk', disk['id'])
            service.disks().delete(project=project, zone=zone,
                                   disk=disk['id']).execute()
    return True


def check_user_permissions(google_key, storage_enabled):
    if not google_key:
        raise AttributeError('Invalid input parameter google_key')

    credentials_json = json.loads(google_key)
    credentials = service_account.Credentials.from_service_account_info(credentials_json)
    service = discovery.build('cloudresourcemanager', 'v1', credentials=credentials)

    project = credentials_json['project_id']

    request = service.projects().getIamPolicy(resource=project)
    response = request.execute()

    email = credentials_json['client_email']

    missing_roles = []

    for binding in response['bindings']:
        if binding['role'] == 'roles/dns.admin':
            if not any(email in member for member in binding['members']):
                missing_roles.append('Missing role roles/dns.admin')
        if binding['role'] == 'roles/compute.admin':
            if not any(email in member for member in binding['members']):
                missing_roles.append('Missing role roles/compute.admin')
        if binding['role'] == 'roles/iam.serviceAccountUser':
            if not any(email in member for member in binding['members']):
                missing_roles.append('Missing role roles/iam.serviceAccountUser')
        if binding['role'] == 'roles/cloudasset.viewer':
            if not any(email in member for member in binding['members']):
                missing_roles.append('Missing role roles/cloudasset.viewer')
        if storage_enabled and binding['role'] == 'roles/storage.admin':
            if not any(email in member for member in binding['members']):
                missing_roles.append('Missing storage permissions.')

    if missing_roles:
        return missing_roles

    return ''

def check_compute_api_enabled(google_key):
    if not google_key:
        raise AttributeError('Invalid input parameter google_key')

    credentials_json = json.loads(google_key)
    credentials = service_account.Credentials.from_service_account_info(credentials_json)
    service = discovery.build('serviceusage', 'v1', credentials=credentials)

    project = credentials_json['project_id']

    request = service.services().get(name='projects/' + project + '/services/compute.googleapis.com')
    response = request.execute()

    if 'state' in response and response['state'] == 'DISABLED':
        return False

    return True

def check_dns_api_enabled(google_key):
    if not google_key:
        raise AttributeError('Invalid input parameter google_key')

    credentials_json = json.loads(google_key)
    credentials = service_account.Credentials.from_service_account_info(credentials_json)
    service = discovery.build('serviceusage', 'v1', credentials=credentials)

    project = credentials_json['project_id']

    request = service.services().get(name='projects/' + project + '/services/dns.googleapis.com')
    response = request.execute()

    if 'state' in response and response['state'] == 'DISABLED':
        return False

    return True

def check_cloud_asset_api_enabled(google_key):
    if not google_key:
        raise AttributeError('Invalid input parameter google_key')

    credentials_json = json.loads(google_key)
    credentials = service_account.Credentials.from_service_account_info(credentials_json)
    service = discovery.build('serviceusage', 'v1', credentials=credentials)

    project = credentials_json['project_id']

    request = service.services().get(name='projects/' + project + '/services/cloudasset.googleapis.com')
    response = request.execute()

    if 'state' in response and response['state'] == 'DISABLED':
        return False

    return True

def stop_instances(google_key, zone, instances):
    if not google_key:
        raise AttributeError('Invalid input parameter google_key')
    if not zone:
        raise AttributeError('Invalid input parameter zone')
    if instances == []:
        raise AttributeError('Invalid input parameter instances')

    credentials_json = json.loads(google_key)
    credentials = service_account.Credentials.from_service_account_info(credentials_json)
    service = discovery.build('compute', 'v1', credentials=credentials)

    project = credentials_json['project_id']

    for instance in instances:
        request = service.instances().stop(project=project, zone=zone, instance=instance)
        response = request.execute()

    max_retries = 24
    wait_seconds = 20
    for i in range(0, max_retries):
        all_ok = True
        time.sleep(wait_seconds)
        for instance in instances:
            request = service.instances().get(project=project, zone=zone, instance=instance)
            response = request.execute()
            if response['status'] != 'TERMINATED':
                all_ok = False

        if all_ok:
            break

        if i == max_retries - 1:
            raise Exception('Timeout while waiting instances to stop')

    return


def start_instances(google_key, zone, instances):
    if not google_key:
        raise AttributeError('Invalid input parameter google_key')
    if not zone:
        raise AttributeError('Invalid input parameter zone')
    if instances == []:
        raise AttributeError('Invalid input parameter instances')

    credentials_json = json.loads(google_key)
    credentials = service_account.Credentials.from_service_account_info(credentials_json)
    service = discovery.build('compute', 'v1', credentials=credentials)

    project = credentials_json['project_id']

    for instance in instances:
        request = service.instances().start(project=project, zone=zone, instance=instance)
        response = request.execute()

    max_retries = 24
    wait_seconds = 20
    for i in range(0, max_retries):
        all_ok = True
        time.sleep(wait_seconds)
        for instance in instances:
            request = service.instances().get(project=project, zone=zone, instance=instance)
            response = request.execute()
            if response['status'] != 'RUNNING':
                all_ok = False

        if all_ok:
            break

        if i == max_retries - 1:
            raise Exception('Timeout while waiting instances to stop')

    return


def restart_instances(google_key, zone, instances):
    if not google_key:
        raise AttributeError('Invalid input parameter google_key')
    if not zone:
        raise AttributeError('Invalid input parameter zone')
    if instances == []:
        raise AttributeError('Invalid input parameter instances')

    stop_instances(google_key, zone, instances)
    start_instances(google_key, zone, instances)

    return


def delete_loadbalancer_resources(google_key, region, vpc_name, user_id, cluster_id):
    if not google_key:
        raise AttributeError('Invalid input parameter google_key')
    if not region:
        raise AttributeError('Invalid input parameter region')
    if not vpc_name:
        raise AttributeError('Invalid input parameter vpc_name')

    credentials_json = json.loads(google_key)
    credentials = service_account.Credentials.from_service_account_info(credentials_json)
    service = discovery.build('compute', 'v1', credentials=credentials)
    project = credentials_json['project_id']

    # get loadbalancer name
    load_balancer_name = ""
    firewall_rules = service.firewalls()
    firewall_rules_list = firewall_rules.list(project=credentials_json['project_id']).execute()

    if 'items' not in firewall_rules_list:
        return False

    for firewall_rule in firewall_rules_list['items']:
        if 'targetTags' not in firewall_rule:
            continue
        if vpc_name in firewall_rule['targetTags']:
            if 'name' in firewall_rule and firewall_rule['name'].startswith('k8s-fw-'):
                load_balancer_name = firewall_rule['name'].split('-')[2]
                break
            if 'name' in firewall_rule and firewall_rule['name'].startswith('k8s-'):
                load_balancer_name = firewall_rule['name'].split('-')[1]
                break

    if load_balancer_name == "":
        return False

    try:
        # stop instances
        google.stop_all_machines(cluster_id)
    except Exception as e:
        print(str(e))
        pass

    # delete forwardingRules
    request = service.forwardingRules().list(project=project, region=region)
    while request is not None:
        forwarding_rules_response = request.execute()

        if 'items' in forwarding_rules_response:
            for forwarding_rule in forwarding_rules_response['items']:
                # check if forwarding rule is for the vpc
                if forwarding_rule['name'] == load_balancer_name:
                    # delete forwardingRule
                    request = service.forwardingRules().delete(project=project, region=region, forwardingRule=forwarding_rule['name'])
                    print(request.execute())

        request = service.forwardingRules().list_next(previous_request=request, previous_response=forwarding_rules_response)

    # delete health checks
    request = service.regionHealthChecks().list(project=project, region=region)
    while request is not None:
        health_checks_response = request.execute()

        if 'items' in health_checks_response:
            for health_check in health_checks_response['items']:
                # check if health check is for the vpc
                if health_check['name'] == load_balancer_name:
                    # delete health check
                    request = service.regionHealthChecks().delete(project=project, healthCheck=health_check['name'], region=region)
                    print(request.execute())

        request = service.regionHealthChecks().list_next(previous_request=request, previous_response=health_checks_response)

    # delete static IPs
    request = service.addresses().list(project=project, region=region)
    while request is not None:
        addresses_response = request.execute()

        if 'items' in addresses_response:
            for address in addresses_response['items']:
                # check if address is for the vpc
                if address['name'] == load_balancer_name:
                    # delete address
                    request = service.addresses().delete(project=project, address=address['name'], region=region)
                    print(request.execute())

        request = service.addresses().list_next(previous_request=request, previous_response=addresses_response)

    # delete firewall rules
    firewall_rules = service.firewalls()
    firewall_rules_list = firewall_rules.list(project=credentials_json['project_id']).execute()

    if 'items' not in firewall_rules_list:
        return False

    for firewall_rule in firewall_rules_list['items']:
        if 'targetTags' not in firewall_rule:
            continue
        if vpc_name in firewall_rule['targetTags']:
            if 'name' in firewall_rule and firewall_rule['name'].startswith('k8s-'):
                # delete firewall rule
                request = service.firewalls().delete(project=project, firewall=firewall_rule['name'])
                request.execute()

    return True


def add_cloud_account_to_daiteap_project(google_key):
    daiteap_google_key = open(DAITEAP_GOOGLE_IMAGE_KEY).read()

    if not google_key:
        raise AttributeError('Invalid input parameter google_key')

    credentials_json = json.loads(google_key)
    daiteap_credentials_json = json.loads(daiteap_google_key)
    credentials = service_account.Credentials.from_service_account_info(daiteap_credentials_json)
    project = daiteap_credentials_json['project_id']

    service = discovery.build(
        "cloudresourcemanager", "v1", credentials=credentials
    )
    old_policy = (
        service.projects()
        .getIamPolicy(
            resource=project,
            body={"options": {"requestedPolicyVersion": 3}},
        )
        .execute()
    )

    for binding in old_policy['bindings']:
        if binding['role'] == 'roles/compute.imageUser':
            binding['members'].append('serviceAccount:' + credentials_json['client_email'])

    policy = (
        service.projects()
        .setIamPolicy(
            resource=project,
            body={'policy': old_policy})
        .execute()
    )

    return

def remove_cloud_account_from_daiteap_project(google_key):
    daiteap_google_key = open(DAITEAP_GOOGLE_IMAGE_KEY).read()

    if not google_key:
        raise AttributeError('Invalid input parameter google_key')

    credentials_json = json.loads(google_key)
    daiteap_credentials_json = json.loads(daiteap_google_key)
    credentials = service_account.Credentials.from_service_account_info(daiteap_credentials_json)
    project = daiteap_credentials_json['project_id']

    service = discovery.build(
        "cloudresourcemanager", "v1", credentials=credentials
    )
    old_policy = (
        service.projects()
        .getIamPolicy(
            resource=project,
            body={"options": {"requestedPolicyVersion": 3}},
        )
        .execute()
    )

    for binding in old_policy['bindings']:
        if binding['role'] == 'roles/compute.imageUser':
            # remove only bindings which exists, otherwise remove() will throw ValueError
            if 'serviceAccount:' + credentials_json['client_email'] in binding['members']:
                binding['members'].remove('serviceAccount:' + credentials_json['client_email'])

    policy = (
        service.projects()
        .setIamPolicy(
            resource=project,
            body={'policy': old_policy})
        .execute()
    )

    return

def get_available_regions_parameters(google_key):
    allowed_regions = [
        'asia-east1',
        'asia-east2',
        'asia-south1',
        'asia-south2',
        'australia-southeast1',
        'australia-southeast2',
        'europe-north1',
        'europe-west1',
        'europe-west2',
        'europe-west3',
        'europe-west4',
        'europe-west6',
        'us-west1',
        'us-west2',
        'us-west3',
        'us-west4'
    ]

    regions = []

    credentials_json = json.loads(google_key)
    credentials = service_account.Credentials.from_service_account_info(
        credentials_json)
    service = discovery.build('compute', 'v1', credentials=credentials)
    regions_service = service.regions()

    regions_list = regions_service.list(project=credentials_json['project_id']).execute()
    for item in regions_list['items']:

        if item['name'] not in allowed_regions:
            continue

        region = {
            'name': item['name'],
            'zones': []
        }
        for zone in item['zones']:
            zone_str_arr = zone.split('/')
            zone_name = zone_str_arr[len(zone_str_arr)-1]
            machine_types_list = get_machine_types_list(google_key, zone_name)
            zone = {
                'name': zone_name,
                'instances': []
            }
            region['zones'].append(zone)

            instances = []

            for instance_type in machine_types_list['items']:
                instance = {
                    'name': instance_type['name'],
                    'description': instance_type['description'],
                    'cpu': 0,
                    'ram': 0
                }

                instance_data = get_instance_type_parameters(google_key, zone_name, instance_type['name'], machine_types_list)

                if instance_data['ram'] % 2 == 0:
                    instance['cpu'] = instance_data['cpu']
                    instance['ram'] = instance_data['ram']
                    instances.append(instance)

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

    return regions

def get_machine_types_list(google_key, zone_name):
    credentials_json = json.loads(google_key)
    credentials = service_account.Credentials.from_service_account_info(credentials_json)
    service = discovery.build('compute', 'v1', credentials=credentials)
    machineTypes_service = service.machineTypes()

    machineTypes_list = machineTypes_service.list(project=credentials_json['project_id'], zone=zone_name).execute()

    return machineTypes_list

def get_instance_type_parameters(google_key, zone_name, instance_type, machineTypes_list = {}):
    if not machineTypes_list:
        machineTypes_list = get_machine_types_list(google_key, zone_name)

    for instance in machineTypes_list['items']:
        if instance_type == instance['name']:
            return {
                'cpu': instance['guestCpus'],
                'ram': instance['memoryMb']/1024
            }

    raise Exception('Can\'t find instance type.')

def get_all_available_daiteap_os_parameters(google_key, project):
    all_os_parameters = []

    images = get_available_image_parameters(google_key, project)

    for image in images:
        os = {
            'value': project + '/' + image['name'],
            'os': image['name']
        }
        all_os_parameters.append(os)

    return all_os_parameters

def get_all_available_os_parameters(google_key):
    all_os_parameters = []

    debian_project = 'debian-cloud'
    ubuntu_project = 'ubuntu-os-cloud'
    # centos_project = 'centos-cloud'

    debian_images = get_available_image_parameters(google_key, debian_project)
    ubuntu_images = get_available_image_parameters(google_key, ubuntu_project)
    # centos_images = get_available_image_parameters(google_key, centos_project)

    for image in debian_images:
        if 'debian-9' in image['name']:
            os = {
                'value': debian_project + '/' + image['name'],
                'os': 'Debian 9'
            }
            all_os_parameters.append(os)
    for image in ubuntu_images:
        if 'ubuntu-1804' in image['name'] and 'arm64' not in image['name']:
            os = {
                'value': ubuntu_project + '/' + image['name'],
                'os': 'Ubuntu 18 LTS'
            }
            all_os_parameters.append(os)
    # for image in centos_images:
    #     os = {
    #         'value': centos_project + '/' + image['name'],
    #         'os': image['description'] 
    #     }
    #     all_os_parameters.append(os)

    return all_os_parameters

def get_available_image_parameters(google_key, project):
    images = []

    credentials_json = json.loads(google_key)
    credentials = service_account.Credentials.from_service_account_info(
        credentials_json)
    service = discovery.build('compute', 'v1', credentials=credentials)

    filter_expression = 'labels.' + settings.DLCM_IMAGES_TAG + ' = true'

    request = service.images().list(project=project, filter=filter_expression)
    response = request.execute()

    items = []

    if 'items' in response:
        items = response['items']

    for item in items:
        if 'deprecated' in item and 'state' in item['deprecated']:
            if item['deprecated']['state'] not in ['DEPRECATED', 'OBSOLETE']:
                images.append(item)
        else:
            images.append(item)

    return images

def get_storage_buckets(credential_id, google_credentials, google_project):
    storage_client = storage.Client(project=google_project,credentials=google_credentials)

    response = {'buckets': []}

    buckets = list(storage_client.list_buckets())
    for bucket in buckets:
        bucket_info = storage_client.get_bucket(bucket.name)
        response_bucket = {
            'name': bucket_info.name,
            'storage_class': bucket_info.storage_class,
            'location': bucket_info.location,
            'location_type': bucket_info.location_type,
            'time_created': bucket_info.time_created,
            'provider': "google",
            'credential_id': credential_id,
            'storage_account_url': None,
        }
        response['buckets'].append(response_bucket)

    return response

def create_storage_bucket(google_credentials, google_project, bucket_name, storage_class, bucket_location, request):
    storage_client = storage.Client(project=google_project,credentials=google_credentials)

    bucket = storage_client.bucket(bucket_name)
    bucket.storage_class = storage_class
    bucket.location = bucket_location

    try:
        new_bucket = storage_client.create_bucket(bucket)

        new_bucket = storage_client.get_bucket(bucket_name)
        labels = new_bucket.labels
        labels["daiteap-workspace-id"] = str(request.daiteap_user.tenant.id)
        labels["daiteap-user-id"] = str(request.daiteap_user.id)
        labels["daiteap-username"] = (re.sub('[^0-9a-zA-Z-_]+', '_', request.user.username).lower())
        labels["daiteap-user-email"] = (re.sub('[^0-9a-zA-Z-_]+', '_', request.user.email).lower())
        labels["daiteap-platform-url"] = (re.sub('[^0-9a-zA-Z-_]+', '_', request.headers['Origin']).lower())
        labels["daiteap-workspace-name"] = (re.sub('[^0-9a-zA-Z-_]+', '_', request.daiteap_user.tenant.name).lower())
        new_bucket.labels = labels
        new_bucket.patch()

        response = {'done': True}
    except Exception as e:
        if "Your previous request to create the named bucket succeeded and you already own it." in str(e): 
            response = {'error': 'Bucket name taken.'}
        elif "The requested bucket name is not available." in str(e): 
            response = {'error': 'Bucket name taken.'}
        elif "Please select a different name and try again." in str(e): 
            response = {'error': 'Bucket name taken.'}
        else:
            response = {'error': str(e)}

    return response

def delete_storage_bucket(google_credentials, google_project, bucket_name):
    storage_client = storage.Client(project=google_project,credentials=google_credentials)

    files = storage_client.list_blobs(bucket_name)
    if list(files) != []:
        return {'error': 'Bucket is not empty.'}
    
    bucket = storage_client.get_bucket(bucket_name)
    bucket.delete()
    return {'done': True}

def get_bucket_files(google_credentials, google_project, bucket_name, path):
    storage_client = storage.Client(project=google_project,credentials=google_credentials)

    response = {'files': []}
    bucket = storage_client.bucket(bucket_name)
    files = storage_client.list_blobs(bucket_name)
    dirs_in_folder = []

    for bucket_file in files:
        split_file_name = bucket_file.name.split("/")
        file_name_slash_count = len(split_file_name) - 1

        if path == "/":
            if file_name_slash_count == 0:
                file_info = bucket.get_blob(bucket_file.name)
                response_file = {
                    'path': file_info.name,
                    'basename': file_info.name,
                    'type': "file",
                    'content_type': file_info.content_type,
                    'size': file_info.size,
                }
                response['files'].append(response_file)
            elif split_file_name[0] not in dirs_in_folder:
                file_info = bucket.get_blob(bucket_file.name)
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
                    file_info = bucket.get_blob(bucket_file.name)
                    response_file = {
                        'path': file_info.name,
                        'basename': split_file_name[-1],
                        'type': "file",
                        'content_type': file_info.content_type,
                        'size': file_info.size,
                    }
                    response['files'].append(response_file)
                if file_name_slash_count > path_slash_count and split_file_name[path_slash_count] not in dirs_in_folder:
                    filepath = ""
                    for index in range(len(split_path)):
                        filepath = filepath + "/" + split_file_name[index]
                    filepath = filepath + "/"

                    file_info = bucket.get_blob(bucket_file.name)
                    response_file = {
                        'path': filepath,
                        'basename': split_file_name[path_slash_count],
                        'type': "dir",
                        'content_type': "folder",
                        'size': 0,
                    }
                    response['files'].append(response_file)
                    dirs_in_folder.append(split_file_name[path_slash_count])

    return response

def add_bucket_file(google_credentials, google_project, bucket_name, file_name, content_type, contents, temporary_file):
    storage_client = storage.Client(project=google_project,credentials=google_credentials)

    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(file_name)

    if content_type == "folder":
        blob.upload_from_string("")
    else:
        bytes_from_array = bytes(contents)
        with open(temporary_file, "wb") as binary_file:
            binary_file.write(bytes_from_array)
        blob.content_type = content_type
        blob.upload_from_filename(temporary_file)
        os.remove(temporary_file)

    return {'done': True}

def delete_bucket_file(google_credentials, google_project, bucket_name, file_name):
    storage_client = storage.Client(project=google_project,credentials=google_credentials)

    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(file_name)
    blob.delete()

    return {'done': True}

def download_bucket_file(google_credentials, google_project, bucket_name, file_name):
    storage_client = storage.Client(project=google_project,credentials=google_credentials)

    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(file_name)
    contents = blob.download_as_string()
    contents_bytearray = list(contents)
    file_info = bucket.get_blob(file_name)

    return {'content_type': file_info.content_type, 'contents': contents_bytearray}

def delete_bucket_folder(google_credentials, google_project, bucket_name, folder_path):
    storage_client = storage.Client(project=google_project,credentials=google_credentials)

    if folder_path[0] == "/":
        folder_path = folder_path[1:]

    files = get_bucket_files(google_credentials, google_project, bucket_name, folder_path)['files']
    for bucket_file in files:
        if bucket_file['content_type'] == "folder":
            delete_bucket_folder(google_credentials, google_project, bucket_name, bucket_file['path'])
        else:
            delete_bucket_file(google_credentials, google_project, bucket_name, bucket_file['path'])
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(folder_path)
    blob.delete()

    return {'done': True}

def get_bucket_details(google_credentials, google_project, bucket_name):
    storage_client = storage.Client(project=google_project,credentials=google_credentials)

    response = {'bucket_details': []}

    bucket_info = storage_client.get_bucket(bucket_name)
    response['bucket_details'].append({
        'storage_class': bucket_info.storage_class,
        'location': bucket_info.location,
        'location_type': bucket_info.location_type,
    })

    return response

def get_compute_all_available_os_parameters(google_key):
    all_os_parameters = []

    debian_project = 'debian-cloud'
    ubuntu_project = 'ubuntu-os-cloud'
    # centos_project = 'centos-cloud'

    debian_images = get_compute_available_image_parameters(google_key, debian_project)
    ubuntu_images = get_compute_available_image_parameters(google_key, ubuntu_project)
    # centos_images = get_available_image_parameters(google_key, centos_project)

    for image in debian_images:
        if 'debian-9' in image['name']:
            os = {
                'value': debian_project + '/' + image['name'],
                'os': 'Debian 9'
            }
            all_os_parameters.append(os)
    for image in ubuntu_images:
        if 'ubuntu-1804' in image['name'] and 'arm64' not in image['name']:
            os = {
                'value': ubuntu_project + '/' + image['name'],
                'os': 'Ubuntu 18 LTS'
            }
            all_os_parameters.append(os)
    # for image in centos_images:
    #     os = {
    #         'value': centos_project + '/' + image['name'],
    #         'os': image['description'] 
    #     }
    #     all_os_parameters.append(os)

    return all_os_parameters

def get_compute_available_image_parameters(google_key, project):
    images = []

    credentials_json = json.loads(google_key)
    credentials = service_account.Credentials.from_service_account_info(
        credentials_json)
    service = discovery.build('compute', 'v1', credentials=credentials)

    request = service.images().list(project=project)
    response = request.execute()

    items = []

    if 'items' in response:
        items = response['items']

    for item in items:
        if 'deprecated' in item and 'state' in item['deprecated']:
            if item['deprecated']['state'] not in ['DEPRECATED', 'OBSOLETE']:
                images.append(item)
        else:
            images.append(item)

    return images

def create_daiteap_dns_record_set(cluster_id, ip_list):
    google_key = open(DAITEAP_GOOGLE_KEY).read()

    credentials_json = json.loads(google_key)
    project = credentials_json['project_id']
    zone_name = settings.SERVICES_DNS_ZONE_NAME

    credentials = service_account.Credentials.from_service_account_info(credentials_json)
    service = discovery.build('dns', 'v1', credentials=credentials)

    entry = {
        'additions': [
            {
            'name': '*.' + str(cluster_id).replace('-','')[:10] + '.' + settings.SERVICES_DNS_DOMAIN + '.',
            'type': 'A',
            'ttl': 300,
            'rrdata': ip_list
            }
        ]
    }

    # check if exists
    request = service.resourceRecordSets().get(
        project=project,
        managedZone=zone_name,
        name='*.' + str(cluster_id) + '.' + settings.SERVICES_DNS_DOMAIN + '.',
        type='A'
    )
    try:
        response = request.execute()
    except:
        print('no record set')

    request = service.changes().create(project=project, managedZone=zone_name, body=entry)
    try:
        response = request.execute()
    except:
        raise Exception('Error while creating daiteap dns record')

    max_retries = 24
    wait_seconds = 20
    for i in range(0, max_retries):
        time.sleep(wait_seconds)

        request = service.resourceRecordSets().get(
            project=project,
            managedZone=zone_name,
            name='*.' + str(cluster_id).replace('-','')[:10] + '.' + settings.SERVICES_DNS_DOMAIN + '.',
            type='A'
        )
        try:
            response = request.execute()
            if response['kind'] == 'dns#resourceRecordSet':
                break
        except:
            if i == max_retries - 1:
                raise Exception('Timeout while waiting daiteap dns record to create')

    return

def delete_daiteap_dns_record_set(cluster_id):
    google_key = open(DAITEAP_GOOGLE_KEY).read()
    credentials_json = json.loads(google_key)
    project = credentials_json['project_id']
    zone_name = settings.SERVICES_DNS_ZONE_NAME

    credentials = service_account.Credentials.from_service_account_info(credentials_json)
    service = discovery.build('dns', 'v1', credentials=credentials)

    # check if exists
    request = service.resourceRecordSets().get(
        project=project,
        managedZone=zone_name,
        name='*.' + str(cluster_id).replace('-','')[:10] + '.' + settings.SERVICES_DNS_DOMAIN + '.',
        type='A'
    )
    try:
        response = request.execute()
    except:
        print('no record set')
        return

    request = service.resourceRecordSets().delete(
        project=project,
        managedZone=zone_name,
        name='*.' + str(cluster_id).replace('-','')[:10] + '.' + settings.SERVICES_DNS_DOMAIN + '.',
        type='A'
    )
    try:
        response = request.execute()
    except:
        raise Exception('Error while deleting daiteap dns record')

    return

def get_cloud_account_info(google_credentials):
    cloud_data = dict()

    cloud_data['project_id'] = google_credentials['project_id']
    cloud_data['email'] = google_credentials['client_email']

    return cloud_data['email']