from cloudcluster.models import *
from cloudcluster import settings
import time
import os

import openstack

def get_created_cluster_resources(credentials, name_prefix):
    if not credentials:
        raise AttributeError('Invalid input parameter credentials')
    if 'region_name' not in credentials.keys() or not credentials['region_name']:
        raise AttributeError('Missing or invalid parameter "region_name" in credentials')
    if 'auth_url' not in credentials.keys() or not credentials['auth_url']:
        raise AttributeError('Missing or invalid parameter "auth_url" in credentials')
    if 'application_credential_id' not in credentials.keys() or not credentials['application_credential_id']:
        raise AttributeError('Missing or invalid parameter "application_credential_id" in credentials')
    if 'application_credential_secret' not in credentials.keys() or not credentials['application_credential_secret']:
        raise AttributeError('Missing or invalid parameter "application_credential_secret" in credentials')

    conn = openstack.connection.Connection(
        auth_type='v3applicationcredential',
        region_name=credentials['region_name'],
        auth=dict(
            auth_url=credentials['auth_url'],
            application_credential_id=credentials['application_credential_id'],
            application_credential_secret=credentials['application_credential_secret']
        ),
        verify=False
    )

    resources = []

    servers = conn.compute.servers()
    for server in servers:
        if server.name.startswith(name_prefix):
            server_dict = server.to_dict()
            server_dict['type'] = 'server'
            resources.append(server_dict)

    routers = conn.network.routers()
    for router in routers:
        if router.name.startswith(name_prefix):
            router_dict = router.to_dict()
            router_dict['type'] = 'router'
            resources.append(router_dict)

    volumes = conn.volume.volumes()
    for volume in volumes:
        if volume.name.startswith(name_prefix):
            volume_dict = volume.to_dict()
            volume_dict['type'] = 'volume'
            resources.append(volume_dict)

    networks = conn.network.networks()
    for network in networks:
        if network.name.startswith(name_prefix):
            network_dict = network.to_dict()
            network_dict['type'] = 'network'
            resources.append(network_dict)

    subnets = conn.network.subnets()
    for subnet in subnets:
        if subnet.name.startswith(name_prefix):
            subnet_dict = subnet.to_dict()
            subnet_dict['type'] = 'subnet'
            resources.append(subnet_dict)

    security_groups = conn.network.security_groups()
    for security_group in security_groups:
        if security_group.name.startswith(name_prefix):
            security_group_dict = security_group.to_dict()
            security_group_dict['type'] = 'security_group'
            resources.append(security_group_dict)

    floating_ips = conn.network.ips()
    for floating_ip in floating_ips:
        if floating_ip.name.startswith(name_prefix):
            floating_ip_dict = floating_ip.to_dict()
            floating_ip_dict['type'] = 'floating_ip'
            resources.append(floating_ip_dict)

    keypairs = conn.compute.keypairs()
    for keypair in keypairs:
        if keypair.name.startswith(name_prefix):
            keypair_dict = keypair.to_dict()
            keypair_dict['type'] = 'keypair'
            resources.append(keypair_dict)

    return resources

def delete_disk_resources(credentials, cluster_id, cluster_name):
    if not credentials:
        raise AttributeError('Invalid input parameter credentials')
    if 'region_name' not in credentials.keys() or not credentials['region_name']:
        raise AttributeError('Missing or invalid parameter "region_name" in credentials')
    if 'auth_url' not in credentials.keys() or not credentials['auth_url']:
        raise AttributeError('Missing or invalid parameter "auth_url" in credentials')
    if 'application_credential_id' not in credentials.keys() or not credentials['application_credential_id']:
        raise AttributeError('Missing or invalid parameter "application_credential_id" in credentials')
    if 'application_credential_secret' not in credentials.keys() or not credentials['application_credential_secret']:
        raise AttributeError('Missing or invalid parameter "application_credential_secret" in credentials')

    conn = openstack.connection.Connection(
        auth_type='v3applicationcredential',
        region_name=credentials['region_name'],
        auth=dict(
            auth_url=credentials['auth_url'],
            application_credential_id=credentials['application_credential_id'],
            application_credential_secret=credentials['application_credential_secret']
        ),
        verify=False
    )

    servers = conn.compute.servers()
    cluster_server_ids = []

    for server in servers:
        if cluster_id in server.name or cluster_name + '-node-' in server.name:
            cluster_server_ids.append(server.id)

            volume_attachments = conn.compute.get_server(server).attached_volumes

            for attached_volume in volume_attachments:
                volume = conn.volume.get_volume(attached_volume)

                if 'Created by OpenStack Cinder CSI driver' in volume['description']:
                    conn.detach_volume(server, attached_volume, wait=True)
                    conn.volume.delete_volume(attached_volume)

    return

def check_user_permissions(credentials):
    return

def stop_instances(credentials, instances):
    if not credentials:
        raise AttributeError('Invalid input parameter credentials')
    if 'region_name' not in credentials.keys() or not credentials['region_name']:
        raise AttributeError('Missing or invalid parameter "region_name" in credentials')
    if 'auth_url' not in credentials.keys() or not credentials['auth_url']:
        raise AttributeError('Missing or invalid parameter "auth_url" in credentials')
    if 'application_credential_id' not in credentials.keys() or not credentials['application_credential_id']:
        raise AttributeError('Missing or invalid parameter "application_credential_id" in credentials')
    if 'application_credential_secret' not in credentials.keys() or not credentials['application_credential_secret']:
        raise AttributeError('Missing or invalid parameter "application_credential_secret" in credentials')
    if instances == []:
        raise AttributeError('Invalid input parameter instances')

    conn = openstack.connection.Connection(
        auth_type='v3applicationcredential',
        region_name=credentials['region_name'],
        auth=dict(
            auth_url=credentials['auth_url'],
            application_credential_id=credentials['application_credential_id'],
            application_credential_secret=credentials['application_credential_secret']
        ),
        verify=False
    )

    for server_id in instances:
        server = conn.compute.get_server(server_id)
        if server.status != 'SHUTOFF':
            conn.compute.stop_server(server)
    
    max_retries = 24
    wait_seconds = 20
    for i in range(0, max_retries):
        all_ok = True
        time.sleep(wait_seconds)
        for server_id in instances:
            server = conn.compute.get_server(server_id)
            if server.status != 'SHUTOFF':
                all_ok = False

        if all_ok:
            break

        if i == max_retries - 1:
            raise Exception('Timeout while waiting instances to stop')

    return

def start_instances(credentials, instances):
    if not credentials:
        raise AttributeError('Invalid input parameter credentials')
    if 'region_name' not in credentials.keys() or not credentials['region_name']:
        raise AttributeError('Missing or invalid parameter "region_name" in credentials')
    if 'auth_url' not in credentials.keys() or not credentials['auth_url']:
        raise AttributeError('Missing or invalid parameter "auth_url" in credentials')
    if 'application_credential_id' not in credentials.keys() or not credentials['application_credential_id']:
        raise AttributeError('Missing or invalid parameter "application_credential_id" in credentials')
    if 'application_credential_secret' not in credentials.keys() or not credentials['application_credential_secret']:
        raise AttributeError('Missing or invalid parameter "application_credential_secret" in credentials')
    if instances == []:
        raise AttributeError('Invalid input parameter instances')

    conn = openstack.connection.Connection(
        auth_type='v3applicationcredential',
        region_name=credentials['region_name'],
        auth=dict(
            auth_url=credentials['auth_url'],
            application_credential_id=credentials['application_credential_id'],
            application_credential_secret=credentials['application_credential_secret']
        ),
        verify=False
    )

    for server_id in instances:
        server = conn.compute.get_server(server_id)
        if server.status != 'ACTIVE':
            conn.compute.start_server(server)
    
    max_retries = 24
    wait_seconds = 20
    for i in range(0, max_retries):
        all_ok = True
        time.sleep(wait_seconds)
        for server_id in instances:
            server = conn.compute.get_server(server_id)
            if server.status != 'ACTIVE':
                all_ok = False

        if all_ok:
            break

        if i == max_retries - 1:
            raise Exception('Timeout while waiting instances to start')

    return

def restart_instances(credentials, instances):
    if not credentials:
        raise AttributeError('Invalid input parameter credentials')
    if 'region_name' not in credentials.keys() or not credentials['region_name']:
        raise AttributeError('Missing or invalid parameter "region_name" in credentials')
    if 'auth_url' not in credentials.keys() or not credentials['auth_url']:
        raise AttributeError('Missing or invalid parameter "auth_url" in credentials')
    if 'application_credential_id' not in credentials.keys() or not credentials['application_credential_id']:
        raise AttributeError('Missing or invalid parameter "application_credential_id" in credentials')
    if 'application_credential_secret' not in credentials.keys() or not credentials['application_credential_secret']:
        raise AttributeError('Missing or invalid parameter "application_credential_secret" in credentials')
    if instances == []:
        raise AttributeError('Invalid input parameter instances')

    stop_instances(credentials, instances)
    start_instances(credentials, instances)

    return

def delete_loadbalancer_resources(credentials):
    return

def get_available_regions_parameters(credentials):
    if not credentials:
        raise AttributeError('Invalid input parameter credentials')
    if 'region_name' not in credentials.keys() or not credentials['region_name']:
        raise AttributeError('Missing or invalid parameter "region_name" in credentials')
    if 'auth_url' not in credentials.keys() or not credentials['auth_url']:
        raise AttributeError('Missing or invalid parameter "auth_url" in credentials')
    if 'application_credential_id' not in credentials.keys() or not credentials['application_credential_id']:
        raise AttributeError('Missing or invalid parameter "application_credential_id" in credentials')
    if 'application_credential_secret' not in credentials.keys() or not credentials['application_credential_secret']:
        raise AttributeError('Missing or invalid parameter "application_credential_secret" in credentials')

    regions = []

    conn = openstack.connection.Connection(
        auth_type='v3applicationcredential',
        region_name=credentials['region_name'],
        auth=dict(
            auth_url=credentials['auth_url'],
            application_credential_id=credentials['application_credential_id'],
            application_credential_secret=credentials['application_credential_secret']
        ),
        verify=False
    )

    zones = conn.list_availability_zone_names()

    region = {
        'name': credentials['region_name'],
        'zones': []
    }

    for entry in zones:
        zone = {
            'name': entry,
            'instances': []
        }

        machineTypes_list = get_machine_types_list(credentials)

        region['zones'].append(zone)

        for flavour in conn.compute.flavors():
            instance = {
                'name': flavour.to_dict()['id'],
                'type': flavour.to_dict()['name'],
                'description': flavour.to_dict()['name'],
                'cpu': 0,
                'ram': 0
            }

            instance_data = get_instance_type_parameters(credentials, flavour.to_dict()['id'], machineTypes_list)

            if instance_data['cpu'] >= 2:
                instance['cpu'] = instance_data['cpu']
                instance['ram'] = instance_data['ram']
                instance['storage'] = instance_data['storage']
                zone['instances'].append(instance)

    regions.append(region)

    return regions

def get_machine_types_list(credentials):
    conn = openstack.connection.Connection(
        auth_type='v3applicationcredential',
        region_name=credentials['region_name'],
        auth=dict(
            auth_url=credentials['auth_url'],
            application_credential_id=credentials['application_credential_id'],
            application_credential_secret=credentials['application_credential_secret']
        ),
        verify=False
    )

    machineTypes_list = []

    for flavour in conn.compute.flavors():
        machineTypes_list.append(flavour.to_dict())

    return machineTypes_list

def get_instance_type_parameters(credentials, instance_type, machineTypes_list = []):
    if not credentials:
        raise AttributeError('Invalid input parameter credentials')
    if 'region_name' not in credentials.keys() or not credentials['region_name']:
        raise AttributeError('Missing or invalid parameter "region_name" in credentials')
    if 'auth_url' not in credentials.keys() or not credentials['auth_url']:
        raise AttributeError('Missing or invalid parameter "auth_url" in credentials')
    if 'application_credential_id' not in credentials.keys() or not credentials['application_credential_id']:
        raise AttributeError('Missing or invalid parameter "application_credential_id" in credentials')
    if 'application_credential_secret' not in credentials.keys() or not credentials['application_credential_secret']:
        raise AttributeError('Missing or invalid parameter "application_credential_secret" in credentials')
    if not instance_type:
        raise AttributeError('Invalid input parameter instance_type')

    if not machineTypes_list:
        machineTypes_list = get_machine_types_list(credentials)

    for instance in machineTypes_list:
        if instance_type == instance['id']:
            return {
                'cpu': instance['vcpus'],
                'ram': instance['ram']/1024,
                'storage': instance['disk']
            }

    raise Exception('Can\'t find instance type.')

def get_external_network_by_id(credentials):
    if not credentials:
        raise AttributeError('Invalid input parameter credentials')
    if 'region_name' not in credentials.keys() or not credentials['region_name']:
        raise AttributeError('Missing or invalid parameter "region_name" in credentials')
    if 'auth_url' not in credentials.keys() or not credentials['auth_url']:
        raise AttributeError('Missing or invalid parameter "auth_url" in credentials')
    if 'application_credential_id' not in credentials.keys() or not credentials['application_credential_id']:
        raise AttributeError('Missing or invalid parameter "application_credential_id" in credentials')
    if 'application_credential_secret' not in credentials.keys() or not credentials['application_credential_secret']:
        raise AttributeError('Missing or invalid parameter "application_credential_secret" in credentials')
    if 'external_network_id' not in credentials.keys() or not credentials['external_network_id']:
        raise AttributeError('Missing or invalid parameter "external_network_id" in credentials')

    conn = openstack.connection.Connection(
        auth_type='v3applicationcredential',
        region_name=credentials['region_name'],
        auth=dict(
            auth_url=credentials['auth_url'],
            application_credential_id=credentials['application_credential_id'],
            application_credential_secret=credentials['application_credential_secret']
        ),
        verify=False
    )

    network = conn.network.find_network(credentials['external_network_id'])

    if network:
        network = network.to_dict()

        if 'is_router_external' in network and network['is_router_external']:
            return network

    return None

def get_all_available_daiteap_os_parameters(credentials):
    if not credentials:
        raise AttributeError('Invalid input parameter credentials')
    if 'region_name' not in credentials.keys() or not credentials['region_name']:
        raise AttributeError('Missing or invalid parameter "region_name" in credentials')
    if 'auth_url' not in credentials.keys() or not credentials['auth_url']:
        raise AttributeError('Missing or invalid parameter "auth_url" in credentials')
    if 'application_credential_id' not in credentials.keys() or not credentials['application_credential_id']:
        raise AttributeError('Missing or invalid parameter "application_credential_id" in credentials')
    if 'application_credential_secret' not in credentials.keys() or not credentials['application_credential_secret']:
        raise AttributeError('Missing or invalid parameter "application_credential_secret" in credentials')

    conn = openstack.connection.Connection(
        auth_type='v3applicationcredential',
        region_name=credentials['region_name'],
        auth=dict(
            auth_url=credentials['auth_url'],
            application_credential_id=credentials['application_credential_id'],
            application_credential_secret=credentials['application_credential_secret']
        ),
        verify=False
    )

    cloud_images = []

    images = conn.image.images()

    for image in images:
        cloud_images.append(image.to_dict())

    all_os_parameters = []

    for cloud_image in cloud_images:
        if settings.DLCM_IMAGES_TAG in cloud_image['tags']:
            os = {
                'value': cloud_image['id'],
                'os': cloud_image['name']
            }
            all_os_parameters.append(os)

    return all_os_parameters

def get_all_available_os_parameters(credentials, is_capi = False, is_yaookcapi = False):
    if not credentials:
        raise AttributeError('Invalid input parameter credentials')
    if 'region_name' not in credentials.keys() or not credentials['region_name']:
        raise AttributeError('Missing or invalid parameter "region_name" in credentials')
    if 'auth_url' not in credentials.keys() or not credentials['auth_url']:
        raise AttributeError('Missing or invalid parameter "auth_url" in credentials')
    if 'application_credential_id' not in credentials.keys() or not credentials['application_credential_id']:
        raise AttributeError('Missing or invalid parameter "application_credential_id" in credentials')
    if 'application_credential_secret' not in credentials.keys() or not credentials['application_credential_secret']:
        raise AttributeError('Missing or invalid parameter "application_credential_secret" in credentials')

    capi_tag = settings.CAPI_IMAGES_TAG

    conn = openstack.connection.Connection(
        auth_type='v3applicationcredential',
        region_name=credentials['region_name'],
        auth=dict(
            auth_url=credentials['auth_url'],
            application_credential_id=credentials['application_credential_id'],
            application_credential_secret=credentials['application_credential_secret']
        ),
        verify=False
    )

    cloud_images = []

    all_os_parameters = []

    if is_capi:
        images = conn.image.images(tag=settings.CAPI_IMAGES_TAG)

        for image in images:
            cloud_images.append(image.to_dict())

        for cloud_image in cloud_images:
            os = {
                'value': cloud_image['id'],
                'os': cloud_image['name']
            }

            all_os_parameters.append(os)
    elif is_yaookcapi:
        images = conn.image.images()

        for image in images:
            cloud_images.append(image.to_dict())

        for cloud_image in cloud_images:
            for operating_system in settings.SUPPORTED_YAOOKCAPI_OPERATING_SYSTEMS:
                supported = True
                for word in operating_system.split(' '):
                    if word not in cloud_image['name'].lower():
                        supported = False

                if supported:
                    os = {
                        'value': cloud_image['id'],
                        'os': cloud_image['name']
                    }
                    all_os_parameters.append(os)
    else:
        images = conn.image.images()

        for image in images:
            cloud_images.append(image.to_dict())

        for cloud_image in cloud_images:
            for operating_system in settings.SUPPORTED_OPERATING_SYSTEMS:
                supported = True
                for word in operating_system.split(' '):
                    if word not in cloud_image['name'].lower():
                        supported = False

                if capi_tag in cloud_image['tags']:
                    supported = False

                if supported:
                    os = {
                        'value': cloud_image['id'],
                        'os': cloud_image['name'] 
                    }
                    all_os_parameters.append(os)

    return all_os_parameters

def create_capi_ssh_key(credentials):
    if not credentials:
        raise AttributeError('Invalid input parameter credentials')
    if 'region_name' not in credentials.keys() or not credentials['region_name']:
        raise AttributeError('Missing or invalid parameter "region_name" in credentials')
    if 'auth_url' not in credentials.keys() or not credentials['auth_url']:
        raise AttributeError('Missing or invalid parameter "auth_url" in credentials')
    if 'application_credential_id' not in credentials.keys() or not credentials['application_credential_id']:
        raise AttributeError('Missing or invalid parameter "application_credential_id" in credentials')
    if 'application_credential_secret' not in credentials.keys() or not credentials['application_credential_secret']:
        raise AttributeError('Missing or invalid parameter "application_credential_secret" in credentials')

    conn = openstack.connection.Connection(
        auth_type='v3applicationcredential',
        region_name=credentials['region_name'],
        auth=dict(
            auth_url=credentials['auth_url'],
            application_credential_id=credentials['application_credential_id'],
            application_credential_secret=credentials['application_credential_secret']
        ),
        verify=False
    )

    # if ssh key exist return
    for key in conn.compute.keypairs():
        if key.name == credentials['ssh_key_name']:
            return

    # if ssh key doesn't exist create the key
    with open(os.path.join('/var/.ssh/id_rsa.pub'), 'r') as public_key_file:
        public_key = public_key_file.read()
        conn.compute.create_keypair(name=credentials['ssh_key_name'], public_key=public_key)

    return

def create_yaookcapi_ssh_key(credentials):
    if not credentials:
        raise AttributeError('Invalid input parameter credentials')
    if 'region_name' not in credentials.keys() or not credentials['region_name']:
        raise AttributeError('Missing or invalid parameter "region_name" in credentials')
    if 'auth_url' not in credentials.keys() or not credentials['auth_url']:
        raise AttributeError('Missing or invalid parameter "auth_url" in credentials')
    if 'application_credential_id' not in credentials.keys() or not credentials['application_credential_id']:
        raise AttributeError('Missing or invalid parameter "application_credential_id" in credentials')
    if 'application_credential_secret' not in credentials.keys() or not credentials['application_credential_secret']:
        raise AttributeError('Missing or invalid parameter "application_credential_secret" in credentials')

    conn = openstack.connection.Connection(
        auth_type='v3applicationcredential',
        region_name=credentials['region_name'],
        auth=dict(
            auth_url=credentials['auth_url'],
            application_credential_id=credentials['application_credential_id'],
            application_credential_secret=credentials['application_credential_secret']
        ),
        verify=False
    )

    # if ssh key exist return
    for key in conn.compute.keypairs():
        if key.name == credentials['ssh_key_name']:
            return

    # if ssh key doesn't exist create the key
    with open(os.path.join('/var/.ssh/id_rsa.pub'), 'r') as public_key_file:
        public_key = public_key_file.read()
        conn.compute.create_keypair(name=credentials['ssh_key_name'], public_key=public_key)

    return
