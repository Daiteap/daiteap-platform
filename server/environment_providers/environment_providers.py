import ast
import base64
import json
import logging
import os
import shutil
import time
import traceback

from cloudcluster import settings
from cloudcluster.models import CloudAccount, Clusters, Machine
from cloudcluster.v1_0_0.ansible.ansible_client import AnsibleClient
from cloudcluster.v1_0_0.terraform.terraform_client import TerraformClient
from cloudcluster.v1_0_0.services import constants

from environment_providers.aws import aws
from environment_providers.aws.services import constants as aws_constants
from environment_providers.azure import azure
from environment_providers.azure.services import constants as azure_constants
from environment_providers.google import google
from environment_providers.google.services import constants as google_constants
from environment_providers.iotarm import iotarm
from environment_providers.iotarm.services import constants as iotarm_constants
from environment_providers.onpremise import onpremise
from environment_providers.onpremise.services import constants as onpremise_constants
from environment_providers.openstack import openstack
from environment_providers.openstack.services import constants as openstack_constants

logger = logging.getLogger(__name__)

supported_providers = {'aws': {'provider': aws, 'constants': aws_constants, 'name': 'Amazon Web Services'},
                       'azure': {'provider': azure, 'constants': azure_constants, 'name': 'Azure'},
                       'google': {'provider': google, 'constants': google_constants, 'name': 'Google'},
                       'onpremise': {'provider': onpremise, 'constants': onpremise_constants, 'name': 'OnPremise'},
                       'iotarm': {'provider': iotarm, 'constants': iotarm_constants, 'name': 'IotArm'},
                       'openstack': {'provider': openstack, 'constants': openstack_constants, 'name': 'Openstack'}
                       }

def get_vpn_tf_code(filtered_environment_providers):
    """Returns Terraform code for vpn creation

    Args:
        filtered_environment_providers (list): Environments used to create cluster

    Returns:
        string: Terraform code
    """
    tf_code = ''
    # Add vpn terraform configurations
    if 'aws' in filtered_environment_providers and len(filtered_environment_providers) > 1:
        with open(os.path.join(settings.BASE_DIR + '/environment_providers/terraform/vpn/vpn_aws.tf'), 'r') as tf_file:
            tf_code += tf_file.read()

    if 'azure' in filtered_environment_providers and len(filtered_environment_providers) > 1:
        with open(os.path.join(settings.BASE_DIR + '/environment_providers/terraform/vpn/vpn_azure.tf'), 'r') as tf_file:
            tf_code += tf_file.read()

    if 'google' in filtered_environment_providers and 'aws' in filtered_environment_providers:
        with open(os.path.join(settings.BASE_DIR + '/environment_providers/terraform/vpn/vpn_aws_google.tf'), 'r') as tf_file:
            tf_code += tf_file.read()

    if 'google' in filtered_environment_providers and 'azure' in filtered_environment_providers:
        with open(os.path.join(settings.BASE_DIR + '/environment_providers/terraform/vpn/vpn_google_azure.tf'), 'r') as tf_file:
            tf_code += tf_file.read()

    if 'aws' in filtered_environment_providers and 'azure' in filtered_environment_providers:
        with open(os.path.join(settings.BASE_DIR + '/environment_providers/terraform/vpn/vpn_aws_azure.tf'), 'r') as tf_file:
            tf_code += tf_file.read()

    if 'aws' in filtered_environment_providers and 'onpremise' in filtered_environment_providers:
        with open(os.path.join(settings.BASE_DIR + '/environment_providers/terraform/vpn/vpn_aws_onpremise.tf'), 'r') as tf_file:
            tf_code += tf_file.read()

    if 'azure' in filtered_environment_providers and 'onpremise' in filtered_environment_providers:
        with open(os.path.join(settings.BASE_DIR + '/environment_providers/terraform/vpn/vpn_azurerm_onpremise.tf'), 'r') as tf_file:
            tf_code += tf_file.read()

    if 'google' in filtered_environment_providers and 'onpremise' in filtered_environment_providers:
        with open(os.path.join(settings.BASE_DIR + '/environment_providers/terraform/vpn/vpn_google_onpremise.tf'), 'r') as tf_file:
            tf_code += tf_file.read()

    if 'aws' in filtered_environment_providers and 'iotarm' in filtered_environment_providers:
        with open(os.path.join(settings.BASE_DIR + '/environment_providers/terraform/vpn/vpn_aws_iotarm.tf'), 'r') as tf_file:
            tf_code += tf_file.read()

    if 'azure' in filtered_environment_providers and 'iotarm' in filtered_environment_providers:
        with open(os.path.join(settings.BASE_DIR + '/environment_providers/terraform/vpn/vpn_azurerm_iotarm.tf'), 'r') as tf_file:
            tf_code += tf_file.read()

    if 'google' in filtered_environment_providers and 'iotarm' in filtered_environment_providers:
        with open(os.path.join(settings.BASE_DIR + '/environment_providers/terraform/vpn/vpn_google_iotarm.tf'), 'r') as tf_file:
            tf_code += tf_file.read()

    return tf_code

def get_vpn_configs(cluster):
    """Returns vpn configurations for providers

    Args:
        cluster (dict): Cluster from db

    Returns:
        dict: vpn configurations for providers
    """
    vpn_configs = {
        'google': {'onpremise': {'public_ip': '', 'pre_shared_key': ''}, 'iotarm': {'public_ip': '', 'pre_shared_key': ''}},
        'aws': {'onpremise': {'public_ip1': '', 'pre_shared_key1': '', 'public_ip2': '', 'pre_shared_key2': ''},
                'iotarm': {'public_ip1': '', 'pre_shared_key1': '', 'public_ip2': '', 'pre_shared_key2': ''}},
        'azure': {'onpremise': {'public_ip': '', 'pre_shared_key': ''}, 'iotarm': {'public_ip': '', 'pre_shared_key': ''}},
        'iotarm': {'onpremise': {'pre_shared_key': ''}},
        'onpremise': {'iotarm': {'pre_shared_key': ''}}
    }

    tf_resources = ast.literal_eval(cluster.tfstate)['resources']


    if 'onpremise' in json.loads(cluster.config) and 'iotarm' in json.loads(cluster.config):
        cluster.vpn_secrets['onpremise_iotarm_shared_secret'] = cluster.vpn_secrets['iotarm_onpremise_shared_secret']
        cluster.save()

    for tf_resource in tf_resources:
        if tf_resource['type'] == 'google_compute_address' and 'onpremise' in tf_resource['name']:
            vpn_configs['google']['onpremise']['public_ip'] = tf_resource['instances'][0]['attributes']['address']
            vpn_configs['google']['onpremise']['pre_shared_key'] = cluster.vpn_secrets['google_onpremise_shared_secret']

        elif tf_resource['type'] == 'google_compute_address' and 'iotarm' in tf_resource['name']:
            vpn_configs['google']['iotarm']['public_ip'] = tf_resource['instances'][0]['attributes']['address']
            vpn_configs['google']['iotarm']['pre_shared_key'] = cluster.vpn_secrets['google_iotarm_shared_secret']

        elif tf_resource['type'] == 'aws_vpn_connection' and 'onpremise' in tf_resource['name']:
            vpn_configs['aws']['onpremise']['public_ip1'] = tf_resource['instances'][0]['attributes']['tunnel1_address']
            vpn_configs['aws']['onpremise']['pre_shared_key1'] = tf_resource['instances'][0]['attributes']['tunnel1_preshared_key']
            vpn_configs['aws']['onpremise']['public_ip2'] = tf_resource['instances'][0]['attributes']['tunnel2_address']
            vpn_configs['aws']['onpremise']['pre_shared_key2'] = tf_resource['instances'][0]['attributes']['tunnel2_preshared_key']

        elif tf_resource['type'] == 'aws_vpn_connection' and 'iotarm' in tf_resource['name']:
            vpn_configs['aws']['iotarm']['public_ip1'] = tf_resource['instances'][0]['attributes']['tunnel1_address']
            vpn_configs['aws']['iotarm']['pre_shared_key1'] = tf_resource['instances'][0]['attributes']['tunnel1_preshared_key']
            vpn_configs['aws']['iotarm']['public_ip2'] = tf_resource['instances'][0]['attributes']['tunnel2_address']
            vpn_configs['aws']['iotarm']['pre_shared_key2'] = tf_resource['instances'][0]['attributes']['tunnel2_preshared_key']

        elif tf_resource['type'] == 'azurerm_public_ip' and 'onpremise' in tf_resource['name'] and tf_resource['mode'] == 'data':
            vpn_configs['azure']['onpremise']['public_ip'] = tf_resource['instances'][0]['attributes']['ip_address']
            vpn_configs['azure']['onpremise']['pre_shared_key'] = cluster.vpn_secrets['azure_onpremise_shared_secret']

        elif tf_resource['type'] == 'azurerm_public_ip' and 'iotarm' in tf_resource['name'] and tf_resource['mode'] == 'data':
            vpn_configs['azure']['iotarm']['public_ip'] = tf_resource['instances'][0]['attributes']['ip_address']
            vpn_configs['azure']['iotarm']['pre_shared_key'] = cluster.vpn_secrets['azure_iotarm_shared_secret']
    return vpn_configs

def add_new_machines_to_resources(machines, resources):
    """Add new machines to resources dict

    Args:
        machines (dict): payload with new machines
        resources (dict): Cluster config from database

    Returns:
        dict: updated config with included new machines
    """
    if machines['provider'] in supported_providers:
        resources = supported_providers[machines['provider']]['provider'].add_new_machines_to_resources(machines, resources)

    return resources

def create_new_machines(resources, user_id, cluster_id, machines, new_indices_counter, old_machines):
    """Create new machines for existing cluster

    Args:
        resources (dict): Cluster config from database
        user_id (int): User id
        cluster_id (class 'uuid.UUID'): Cluster id
        machines (dict): New machines from request payload
        new_indices_counter (int): New machines start index
        old_machines (QuerySet): Old machines db records

    Raises:
        e: Exception
    """
    tf_variables = {}
    tf_code = ''

    filtered_environment_providers = []
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    for environment_provider in supported_providers:
        if environment_provider in resources:
            filtered_environment_providers.append(environment_provider)

            new_machines_tf_variables = supported_providers[environment_provider]['provider'].create_new_machines(
                resources,
                user_id,
                cluster_id,
                machines,
                new_indices_counter,
                old_machines
            )

            tf_variables.update(new_machines_tf_variables)

            tf_code += supported_providers[environment_provider]['provider'].get_tf_code(cluster.type)

    platform = TerraformClient()
    platform.tfstate = {}
    platform.tfvars = {}
    platform.tf_filepath = ''
    platform.code = ''

    # Add vpn terraform configurations
    tf_code += get_vpn_tf_code(filtered_environment_providers)
    platform.code = tf_code

    cluster_tfstate = cluster.tfstate

    try:
        if isinstance(cluster_tfstate, str):
            platform.tfstate = ast.literal_eval(cluster_tfstate)
        else:
            platform.tfstate = cluster_tfstate
        platform.tfvars = tf_variables
        platform.apply(user_id, str(cluster.id), cluster.title)
    except Exception as e:
        encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")

        error_msg = {
            'message': encoded_error
        }
        cluster.error_msg = error_msg
        cluster.resizestep = -1
        cluster.save()
        log_data = {
            'client_request': json.dumps(machines),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        raise e

    cluster.tfcode = str(platform.code)
    cluster.tfstate = str(platform.tfstate)
    cluster.save()

    for supported_provider in supported_providers:
        if supported_provider in filtered_environment_providers and len(filtered_environment_providers) > 1:
            supported_providers[supported_provider]['provider'].run_added_machines_vpn_routing(resources, user_id, cluster_id, machines)

def get_terraform(cluster_config, user_id, cluster_id, tag_values):
    platform = TerraformClient()
    platform.tfstate = {}
    platform.tfvars = {}
    platform.tf_filepath = ''
    platform.code = ''

    cluster = Clusters.objects.filter(id=cluster_id)[0]

    filtered_environment_providers = []

    for supported_provider in supported_providers:
        if supported_provider in cluster_config:
            filtered_environment_providers.append(supported_provider)
            envornment_tf_variables = supported_providers[supported_provider]['provider'].get_tf_variables(
                cluster_config[supported_provider],
                cluster,
                cluster_config['internal_dns_zone'],
                tag_values
            )

            platform.code += supported_providers[supported_provider]['provider'].get_tf_code(cluster.type)
            platform.tfvars.update(envornment_tf_variables)

    # Add vpn terraform configurations
    platform.code += get_vpn_tf_code(filtered_environment_providers)

    try:
        if cluster.tfstate:
            platform.tfstate = ast.literal_eval(cluster.tfstate)
    except:
        pass

    terraform_plan = platform.get_plan(user_id)
    return terraform_plan

def apply_terraform(cluster_config, user_id, cluster_id, tag_values):
    platform = TerraformClient()
    platform.tfstate = {}
    platform.tfvars = {}
    platform.tf_filepath = ''
    platform.code = ''

    cluster = Clusters.objects.filter(id=cluster_id)[0]

    filtered_environment_providers = []

    for supported_provider in supported_providers:
        if supported_provider in cluster_config:
            filtered_environment_providers.append(supported_provider)
            envornment_tf_variables = supported_providers[supported_provider]['provider'].get_tf_variables(
                cluster_config[supported_provider],
                cluster,
                cluster_config['internal_dns_zone'],
                tag_values
            )

            platform.code += supported_providers[supported_provider]['provider'].get_tf_code(cluster.type)
            platform.tfvars.update(envornment_tf_variables)

    # Add vpn terraform configurations
    platform.code += get_vpn_tf_code(filtered_environment_providers)

    try:
        if cluster.tfstate:
            platform.tfstate = ast.literal_eval(cluster.tfstate)
        # print("platform.code: ", platform.code)
        platform.apply(user_id, str(cluster.id), cluster.title)
    finally:
        cluster.tfcode = str(platform.code)
        cluster.tfstate = str(platform.tfstate)
        cluster.save()

    try:
        terraform_plan = platform.plan(user_id)
        if check_if_all_resources_are_created(user_id, cluster.id, filtered_environment_providers, terraform_plan):
            print('All resources are created')
        else:
            logger.error('Not all resources are created')
    except Exception as e:
        logger.error('Error while checking if all resources are created\n' + str(traceback.format_exc()) + '\n' + str(e))

    vpn_configs = get_vpn_configs(cluster)

    for supported_provider in supported_providers:
        if supported_provider in filtered_environment_providers and len(filtered_environment_providers) > 1:
            supported_providers[supported_provider]['provider'].run_vpn_server(filtered_environment_providers, vpn_configs, cluster_config, cluster_id, user_id)

    for supported_provider in supported_providers:
        if supported_provider in filtered_environment_providers and len(filtered_environment_providers) > 1:
            supported_providers[supported_provider]['provider'].run_vpn_routing(cluster_config, user_id, cluster_id)

def add_input_validation_schemas(schema, payload):
    """Add input validation schemas for environment providers

    Args:
        schema (dict): Validation schema
        payload (dict): Request payload data

    Returns:
        dict: Validation schema with validations for providers
    """
    for environment_provider in supported_providers:
        if environment_provider in payload:
            schema['properties'].update(supported_providers[environment_provider]['constants'].INPUT_VALIDATION_SCHEMA)
    return schema

def add_credentials_validation_schemas(schema, payload):
    """Add input validation schemas for cloud credentials

    Args:
        schema (dict): Validation schema
        payload (dict): Request payload data

    Returns:
        dict: Validation schema with validations for providers
    """
    for environment_provider in supported_providers:
        if environment_provider in payload:
            schema['properties']['credentials']['properties'].update(supported_providers[environment_provider]['constants'].CREDENTIALS_VALIDATION_SCHEMA)
    return schema

def check_if_at_least_one_provider_is_selected(resources):
    """Checks if given resources contains at least one supported provider

    Args:
        resources (dict): Providers

    Returns:
        bool: Returns true if at least one supported provider is in the dict, else returns false
    """
    for environment_provider in supported_providers:
        if environment_provider in resources:
            return True
    return False

def check_if_provider_is_supported(provider):
    """Checks if the given provider is supported

    Args:
        provider (string): Provider name

    Returns:
        bool: Returns true if provider is in supported providers, else returns false
    """
    if provider in supported_providers:
        return True
    return False

def validate_regions_zones_instance_types(payload, user, environment_type):
    """Validate regions, zones and instance types from the payload

    Args:
        payload (dict): Request payload data
        user (class 'django.contrib.auth.models.User'): User record from db
        environment_type (int): Marker showing environment type images
    """
    for environment_provider in supported_providers:
        if environment_provider in payload:
            supported_providers[environment_provider]['provider'].validate_regions_zones_instance_types(payload[environment_provider], user, environment_type)

def get_providers_config_params(payload, user):
    """Return cluster config paramaters for database record

    Args:
        payload (dict): Request payload data
        user (class 'django.contrib.auth.models.User'): User record from db

    Returns:
        dict: Cluster config paramaters for database record
    """
    config = {}
    for environment_provider in supported_providers:
        if environment_provider in payload:
            config.update(supported_providers[environment_provider]['provider'].get_provider_config_params(payload, user))

    return config

def get_providers_capi_config_params(payload, user):
    """Return cluster capi_config paramaters for database record

    Args:
        payload (dict): Request payload data
        user (class 'django.contrib.auth.models.User'): User record from db

    Returns:
        dict: Cluster config paramaters for database record
    """
    capi_config = {}
    for environment_provider in supported_providers:
        if environment_provider in payload:
            capi_config.update(supported_providers[environment_provider]['provider'].get_provider_capi_config_params(payload, user))

    return capi_config

def get_providers_yaookcapi_config_params(payload, user):
    """Return cluster yaookcapi_config paramaters for database record

    Args:
        payload (dict): Request payload data
        user (class 'django.contrib.auth.models.User'): User record from db

    Returns:
        dict: Cluster config paramaters for database record
    """
    yaookcapi_config = {}
    for environment_provider in supported_providers:
        if environment_provider in payload:
            yaookcapi_config.update(supported_providers[environment_provider]['provider'].get_provider_yaookcapi_config_params(payload, user))

    return yaookcapi_config

def get_selected_providers(payload):
    """Returns a list of selected supported providers

    Args:
        payload (dict): Request payload data

    Returns:
        list: List of selected supported providers
    """
    selectedProviders = []
    for environment_provider in supported_providers:
        if environment_provider in payload:
            selectedProviders.append(supported_providers[environment_provider]['name'])

    return selectedProviders

def restart_machine(machine, config, machine_provider, user_id):
    """Restart cluster machine

    Args:
        machine (class 'cloudcluster.models.Machine'): Machine record from db
        config (dict): Cluster config
        machine_provider (string): Machine provider name
        user_id (int): User id

    Raises:
        AttributeError: Unsupported provider
    """
    if machine_provider not in supported_providers:
        raise AttributeError(machine_provider + ' is not supported')

    supported_providers[machine_provider]['provider'].restart_machine(config, user_id, machine)

def start_machine(machine, cluster_id, machine_provider, user_id):
    """Start cluster machine

    Args:
        machine (class 'cloudcluster.models.Machine'): Machine record from db
        cluster_id (class 'uuid.UUID'): Cluster id
        machine_provider (string): Machine provider name
        user_id (int): User id

    Raises:
        AttributeError: Unsupported provider
    """
    if machine_provider not in supported_providers:
        raise AttributeError(machine_provider + ' is not supported')

    supported_providers[machine_provider]['provider'].start_machine(cluster_id, user_id, machine)

def stop_machine(machine, cluster_id, machine_provider, user_id):
    """Stop a cluster machine

    Args:
        machine (class 'cloudcluster.models.Machine'): Machine record from db
        cluster_id (class 'uuid.UUID'): Cluster id
        machine_provider (string): Machine provider name
        user_id (int): User id

    Raises:
        AttributeError: Unsupported provider
    """
    if machine_provider not in supported_providers:
        raise AttributeError(machine_provider + ' is not supported')

    supported_providers[machine_provider]['provider'].stop_machine(cluster_id, user_id, machine)

def restart_all_machines(cluster_id, user_id):
    """Restart all cluster machines

    Args:
        cluster_id (class 'uuid.UUID'): Cluster id
        user_id (int): User id
    """
    for environment_provider in supported_providers:
        supported_providers[environment_provider]['provider'].restart_all_machines(cluster_id)

def stop_all_machines(cluster_id):
    """Stop all cluster machines

    Args:
        cluster_id (class 'uuid.UUID'): Cluster id
        user_id (int): User id
    """
    for environment_provider in supported_providers:
        supported_providers[environment_provider]['provider'].stop_all_machines(cluster_id)

def start_all_machines(cluster_id, user_id):
    """Start all cluster machines

    Args:
        cluster_id (class 'uuid.UUID'): Cluster id
        user_id (int): User id
    """
    for environment_provider in supported_providers:
        supported_providers[environment_provider]['provider'].start_all_machines(cluster_id)

def get_nodes(cluster_id, user_id):
    """Get all cluster nodes

    Args:
        cluster_id (class 'uuid.UUID'): Cluster id
        user_id (int): User id

    Returns:
        dict: All cluster nodes
    """
    nodes = {}
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    resources = json.loads(cluster.config)

    for environment_provider in supported_providers:
        if environment_provider in resources:
            nodes.update(supported_providers[environment_provider]['provider'].get_nodes(cluster_id, user_id))

    return nodes

def get_tfstate_resources(tfstate, cluster_config):
    nodes = {}

    for environment_provider in supported_providers:
        if environment_provider in cluster_config:
            nodes.update(supported_providers[environment_provider]['provider'].get_tfstate_resources(tfstate))

    return nodes

def get_machine_records(cloud_config, tfstate_resources, cluster_id):
    machines = []

    for environment_provider in supported_providers:
        if environment_provider in cloud_config:
            provider_machines = supported_providers[environment_provider]['provider'].get_machine_records(
                cloud_config,
                environment_provider,
                tfstate_resources[environment_provider],
                cluster_id
            )

            machines += provider_machines

    return machines

def get_provider_machine_records(resources, clouds, cluster_id, provider, new_indices_counter=0, old_machine_counter=0):
    """Returns list of machines for db for specified provider

    Args:
        resources (dict): Request
        clouds (dict): Dictionary containing each cloud nodes info (returned from get_nodes function) 
        cluster_id (class 'uuid.UUID'): Cluster id
        provider (string): Provider name
        new_indices_counter (int, optional): New machines start index. Defaults to 0.
        old_machine_counter (int, optional): Number of old machines. Defaults to 0.

    Returns:
        list: 
    """
    machines = []

    for environment_provider in supported_providers:
        if environment_provider in resources and environment_provider == provider:
            provider_machines, new_indices_counter = supported_providers[environment_provider]['provider'].get_machine_records(
                resources,
                environment_provider,
                clouds[environment_provider],
                cluster_id,
                new_indices_counter,
                old_machine_counter
            )

            machines += provider_machines

    return machines
def get_used_terraform_environment_resources(resources, user_id, cluster_id):
    """Create graph with used terraform resources

    Args:
        resources (dict): Cluster config from database
        user_id (int): User id
        cluster_id (class 'uuid.UUID'): Cluster id
    """
    tf_variables = {}
    tf_code = ''

    filtered_environment_providers = []
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    for supported_provider in supported_providers:
        if supported_provider in resources:
            filtered_environment_providers.append(supported_provider)

            envornment_tf_variables = supported_providers[supported_provider]['provider'].get_used_terraform_environment_resources(
                resources,
                user_id
            )

            tf_code += supported_providers[supported_provider]['provider'].get_tf_code(cluster.type)
            tf_variables.update(envornment_tf_variables)

    # Add vpn terraform configurations
    platform = TerraformClient()
    platform.tfstate = {}
    platform.tfvars = {}
    platform.tf_filepath = ''
    platform.code = ''
    tf_code += get_vpn_tf_code(filtered_environment_providers)
    platform.code += tf_code
    platform.tfvars = tf_variables

    platform.get_used_resources(user_id, cluster_id)

def get_valid_operating_systems(payload, environment_type, user_id):
    """Returns a list of valid operating systems for selected provider for selected environment

    Args:
        payload (dict): Request payload data
        environment_type (int): Marker showing environment type images
        user_id (int): User id

    Returns:
        list: List of valid operating systems for selected provider for selected environment
    """
    if payload['provider'] in supported_providers:
        valid_operating_systems = supported_providers[payload['provider']]['provider'].get_valid_operating_systems(payload, environment_type, user_id)

    return valid_operating_systems

def validate_account_permissions(credentials, user_id, storage_enabled):
    """Validate account cloud permissions

    Args:
        resources (dict): Cluster config from database
        user_id (int): User id

    Returns:
        none, dict, : None or dict with error
    """
    for environment_provider in supported_providers:
        if environment_provider in credentials:
            response = supported_providers[environment_provider]['provider'].validate_account_permissions(credentials, user_id, storage_enabled)

    return response

def update_providers_regions(resources, user_id):
    """Async update all providers regions

    Args:
        resources (dict): Cluster config from database
        user_id (int): User id
    """
    for supported_provider in supported_providers:
        if supported_provider in resources:
            account = CloudAccount.objects.filter(id=resources[supported_provider]['account'], provider=supported_provider)[0].id
            update_provider_regions(supported_provider, user_id, account)

def update_provider_regions(provider, user_id, account_id):
    """Async update selected provider regions

    Args:
        provider (string): Provider name
        user_id (int): User id
        account_id (int): Cloud account id
    """
    if provider in supported_providers:
        supported_providers[provider]['provider'].update_provider_regions(account_id, user_id)

def check_region_parameters(resources, user_id):
    """Check if selected providers region and zone parameters are valid

    Args:
        resources (dict): Cluster config from database
        user_id (int): User id

    Returns:
        dict: Dictionary with the result of the check
    """
    failed_providers = {}
    for environment_provider in supported_providers:
        if environment_provider in resources:
            x = supported_providers[environment_provider]['provider'].check_region_parameters(resources, user_id)
            failed_providers.update(x)

    return failed_providers

def count_provider_machines(machines, resources):
    """Used when adding new machines, returns the number of old machines

    Args:
        machines (dict): New machines dict that have the name of the provider and new nodes counter
        resources (dict): Cluster config from database

    Returns:
        int: Number of old machines
    """
    if machines['provider'] == 'onpremise' or machines['provider'] == 'iotarm':
        machine_counter = len(resources[machines['provider']]['machines']) + 1 - machines['nodes']
    else:
        machine_counter = len(resources[machines['provider']]['nodes']) - machines['nodes']

    return machine_counter

def count_nodes(resources):
    """Count the number of nodes in the config

    Args:
        resources (dict): Cluster config from database

    Returns:
        int: Number nodes
    """
    nodes_count = 0

    for supported_provider in supported_providers:
        if supported_provider in resources and 'nodes' in resources[supported_provider]:
            nodes_count += int(resources[supported_provider]['nodes'])

    return nodes_count

def get_service_selected_providers(service_options, configuration):
    """Get the selected providers for a service

    Args:
        service_options (dict): Service options
        configuration ([type]): Service kubernetes configuration

    Returns:
        list: List of selected providers
        string: String of selected providers
    """
    providers_string = ''
    add_spaces = False
    selectedProviders = []

    if service_options['cloud_providers']['choice'] == 'single':
        for supported_provider in supported_providers:
            if supported_provider in configuration['cloud_providers']:
                providers_string += supported_provider
                selectedProviders.append(supported_providers[supported_provider]['name'])

    else:
        for supported_provider in supported_providers:
            if supported_provider in configuration['cloud_providers']:
                if add_spaces:
                    providers_string += '\n' + (56 * ' ')
                providers_string += supported_provider + ','
                selectedProviders.append(supported_providers[supported_provider]['name'])
                add_spaces = True
        providers_string = providers_string[:-1]
    return selectedProviders, providers_string

def get_dc_node(config, cluster):
    """Get the DC node public IP

    Args:
        config (dict): Cluster config
        cluster (class 'cloudcluster.models.Clusters): Cluster from db

    Returns:
        string: DC node public IP
    """
    dc_node = ''

    for supported_provider in supported_providers:
        if supported_provider in config:
            dc_node = Machine.objects.filter(
                cluster=cluster,
                provider=supported_provider
            )[0].publicIP

        if dc_node != '':
            break
    return dc_node

def get_dc_node_from_nodes_ips(nodes_ips, resources):
    """ Get DC node private IP from nodes_ips variable (check get_nodes_ips function)

    Args:
        nodes_ips (dict): From get_nodes_ips function
        resources (dict): Cluster config from database

    Returns:
        string: DC node private IP
    """
    dc_node = ''

    for supported_provider in supported_providers:
        if supported_provider in resources:
            dc_node = nodes_ips[supported_provider + '_nodes'][0]
            break

    return dc_node

def get_dc_node_name_and_private_ip(resources, old_machines, clouds):
    """Get DC node name and private IP from cluster config

    Args:
        resources (dict): Cluster config from database
        old_machines (QuerySet): QuerySet with nodes
        clouds (dict): Dictionary containing each cloud nodes info (returned from get_nodes function) 

    Returns:
        string: DC node private IP
        string: DC node hostname
    """
    dc_ip = ''
    dc_hostname = ''

    for supported_provider in supported_providers:
        if supported_provider in resources:
            if dc_hostname == '':
                dc_hostname = old_machines.filter(provider=supported_provider)[0].name

            if dc_ip == '':
                if len(clouds[supported_provider]) > 0:
                    dc_ip = clouds[supported_provider][0]['private_ip']

    return dc_ip, dc_hostname

def get_nodes_ips(clouds):
    """Returns nodes private IPs

    Args:
        clouds ([type]): [description]

    Returns:
        dict: Dictionary containing first node private ip and a list of all nodes private ips for all clouds
        list: List of all nodes private ips for all clouds
    """
    nodes_ips = {}

    all_nodes_private_ips = []

    for supported_provider in supported_providers:
        if supported_provider in clouds:
            for i in range(len(clouds[supported_provider])):
                if i == 0:
                    nodes_ips[supported_provider + '_server_private_ip'] = clouds[supported_provider][i]['private_ip']
                if supported_provider + '_nodes' not in nodes_ips:
                    nodes_ips[supported_provider + '_nodes'] = []

                nodes_ips[supported_provider + '_nodes'].append(clouds[supported_provider][i]['private_ip'])
                all_nodes_private_ips.append(clouds[supported_provider][i]['private_ip'])
    return nodes_ips, all_nodes_private_ips

def fix_hostnames(user_id, nodes_ips, gateway_address, cluster_id, v2):
    """Run fix hostname function for each cloud provider in the cluster

    Args:
        user_id (int): User id
        nodes_ips (dict): From get_nodes_ips function
        gateway_address (string): Address of the gateway node
        cluster_id (class 'uuid.UUID'): Cluster id
    """
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    nodes_counter = 1

    for supported_provider in supported_providers:
        if supported_provider + '_nodes' in nodes_ips:
            provider_nodes_ips = {'provider': supported_provider, 'nodes': nodes_ips[supported_provider + '_nodes']}

            ansible_client = AnsibleClient()
            ansible_client.run_fix_hostnames(user_id,
                                             str(cluster.id),
                                             cluster.title,
                                             provider_nodes_ips,
                                             cluster.name,
                                             gateway_address,
                                             json.loads(cluster.config)['internal_dns_zone'],
                                             nodes_counter,
                                             v2=v2
                                             )

            nodes_counter += len(provider_nodes_ips['nodes'])

def fix_added_machines_hostnames(machines, user_id, new_nodes, cluster_id, gateway_address, new_indices_counter, v2=False):
    """Fix hostnames on new cluster machines

    Args:
        machines (dict): New machines from request payload
        user_id (int): User id
        new_nodes (list): Array of new nodes addresses
        cluster_id (class 'uuid.UUID'): Cluster id
        gateway_address (string): Address of the gateway node
        new_indices_counter (int): New machines start index
    """
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    for supported_provider in supported_providers:
        if supported_provider == machines['provider']:
            provider_nodes_ips = {'provider': supported_provider, 'nodes': new_nodes}

            ansible_client = AnsibleClient()
            ansible_client.run_fix_hostnames(user_id,
                                             str(cluster.id),
                                             cluster.title,
                                             provider_nodes_ips,
                                             cluster.name,
                                             gateway_address,
                                             json.loads(cluster.config)['internal_dns_zone'],
                                             new_indices_counter,
                                             v2=v2
                                             )

            new_indices_counter += len(provider_nodes_ips)

def get_gateway_address_dc_private_ip_and_client_hosts(clouds, cluster_id, user_id):
    """Returns gateway address, dc private ip and list of nodes private ips

        clouds (dict): Dictionary containing each cloud nodes info (returned from get_nodes function) 
        cluster_id (class 'uuid.UUID'): Cluster id
        user_id (int): User id

    Returns:
        string: Gateway node public address
        string: DC node private ip
        list: List of all nodes private ips
    """
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)
    master_private_ip = ''
    gateway_address = ''
    client_hosts = []

    for supported_provider in supported_providers:
        if supported_provider in clouds:

            master_private_ip, gateway_address, client_hosts = supported_providers[supported_provider]['provider'].get_gateway_address_dc_private_ip_and_client_hosts(clouds, master_private_ip, gateway_address, client_hosts, config, user_id)

    return gateway_address, master_private_ip, client_hosts

def delete_loadbalancer_resources(cluster_id, user_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    resources = json.loads(cluster.config)

    if 'load_balancer_integration' in resources:
        lb_provider = resources['load_balancer_integration']
        supported_providers[lb_provider]['provider'].kubernetes_delete_loadbalancer_resources(
            resources[lb_provider]['account'],
            resources[lb_provider]['region'],
            str(cluster_id).replace('-','')[:10],
            user_id,
            cluster_id
        )

def destroy_resources(cluster_id, user_id):
    """Destroy cluster created resources

    Args:
        cluster_id (class 'uuid.UUID'): Cluster id
        user_id (int): User id
    """
    tf_variables = {}
    tf_code = ''

    cluster = Clusters.objects.filter(id=cluster_id)[0]
    resources = json.loads(cluster.config)

    try:
        delete_loadbalancer_resources(cluster_id, user_id)
    except Exception as e:
        encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")

        cluster.error_msg_delete = encoded_error

        cluster.installstep = -100
        cluster.save()
        log_data = {
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_delete_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        return False

    platform = TerraformClient()
    platform.tfstate = {}
    platform.tfvars = {}
    platform.tf_filepath = ''
    platform.code = ''

    # Check if there is allocated resources
    if not cluster.tfstate or cluster.tfstate == '{}':
        filtered_environment_providers = []

        for environment_provider in supported_providers:
            if environment_provider in resources:
                filtered_environment_providers.append(environment_provider)
                envornment_tf_variables = supported_providers[environment_provider]['provider'].destroy_resources(
                    resources[environment_provider],
                    user_id,
                    cluster,
                    resources['internal_dns_zone']
                )

                tf_code += supported_providers[environment_provider]['provider'].get_tf_code(cluster.type)
                tf_variables.update(envornment_tf_variables)

        platform = TerraformClient()
        platform.tfstate = {}
        platform.tfvars = {}
        platform.tf_filepath = ''
        platform.code = ''
        destroyed = True
    else:
        filtered_environment_providers = []

        try:
            for environment_provider in supported_providers:
                if environment_provider in resources:
                    filtered_environment_providers.append(environment_provider)
                    envornment_tf_variables = supported_providers[environment_provider]['provider'].destroy_resources(
                        resources[environment_provider],
                        user_id,
                        cluster,
                        resources['internal_dns_zone']
                    )

                    tf_code += supported_providers[environment_provider]['provider'].get_tf_code(cluster.type)
                    tf_variables.update(envornment_tf_variables)

            platform = TerraformClient()
            platform.tfstate = {}
            platform.tfvars = {}
            platform.tf_filepath = ''
            platform.code = ''

            # Add vpn terraform configurations
            tf_code += get_vpn_tf_code(filtered_environment_providers)
            platform.code = tf_code
            platform.tfstate = ast.literal_eval(cluster.tfstate)

            platform.tfvars = tf_variables

            destroyed = True

            platform.destroy(user_id, str(cluster.id), cluster.title)

            # Clean disk resources
            for environment_provider in filtered_environment_providers:
                supported_providers[environment_provider]['provider'].destroy_disk_resources(resources)

        except Exception as e:

            destroyed = False

            cluster.tfstate = str(platform.tfstate)

            encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
            encoded_error = str(encoded_error_bytes, "utf-8")

            cluster.error_msg_delete = encoded_error

            cluster.installstep = -100
            cluster.save()
            log_data = {
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_delete_cluster',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

    if destroyed:
        try:
            max_retries = 30
            wait_seconds = 20
            for i in range(0, max_retries):
                time.sleep(wait_seconds)
                if check_if_all_resources_are_deleted(user_id, cluster_id, filtered_environment_providers):
                    return True

                elif i == max_retries - 1:
                    cluster.tfstate = str(platform.tfstate)

                    encoded_error_bytes = base64.b64encode("Failed to delete all resources".encode("utf-8"))
                    encoded_error = str(encoded_error_bytes, "utf-8")

                    cluster.error_msg_delete = encoded_error
                    cluster.installstep = -100

                    cluster.save()

                    log_data = {
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_delete_cluster',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + "Failed to delete all resources", extra=log_data)

        except Exception as e:
            cluster.tfstate = str(platform.tfstate)

            encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
            encoded_error = str(encoded_error_bytes, "utf-8")

            cluster.error_msg_delete = encoded_error

            cluster.installstep = -100
            cluster.save()
            log_data = {
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_delete_cluster',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        return False

def check_if_all_resources_are_created(user_id, cluster_id, filtered_environment_providers, terraform_plan):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    for environment_provider in filtered_environment_providers:
        provider_resources_from_api = supported_providers[environment_provider]['provider'].get_created_cluster_resources(cluster_id)
        provider_resources_from_terraform_plan = supported_providers[environment_provider]['provider'].get_planned_resources_for_creation(terraform_plan, cluster.name)

        if len(provider_resources_from_api) != len(provider_resources_from_terraform_plan):
            log_msg = {'Provider': environment_provider,
             'resourcesFromAPI': json.dumps(provider_resources_from_api),
             'resourcesFromTerraformPlan': json.dumps(provider_resources_from_terraform_plan),
             'resourcesFromAPICount': str(len(provider_resources_from_api)),
             'resourcesFromTerraformCount': str(len(provider_resources_from_terraform_plan))
             }

            log_data = {
                'level': 'ERROR',
                'user_id': str(user_id),
            }
            logger.error(json.dumps(log_msg), extra=log_data)
            return False

    return True

def check_if_all_resources_are_deleted(user_id, cluster_id, filtered_environment_providers):
    for environment_provider in filtered_environment_providers:
        provider_resources_from_api = supported_providers[environment_provider]['provider'].get_created_cluster_resources(cluster_id)

        # check if vm state is terminating

        if len(provider_resources_from_api) != 0:
            log_msg = {'Provider': environment_provider,
             'notDeletedResources': json.dumps(provider_resources_from_api),
             }

            log_data = {
                'level': 'ERROR',
                'user_id': str(user_id),
            }
            logger.error(json.dumps(log_msg), extra=log_data)
            return False

    print('All resources are deleted')
    return True

def get_account_labels(request):
    """Returns cloud accounts that have associated cluster

    Args:
        request (dict): User Request

    Returns:
        list: Cloud accounts that have associated cluster
    """
    account_labels = []
    environments = Clusters.objects.filter(project__tenant_id=request.daiteap_user.tenant_id)
    for environment in environments:
        config = json.loads(environment.config)
        for suppported_provider in supported_providers:
            if suppported_provider in config:
                account_labels.append(config[suppported_provider]['account'])
    return account_labels

def validate_credentials(payload, request, storage_enabled):
    """Async task. Validate credentials against the cloud provider. Checks if the credentials are valid, and if the user have required access to the provider.

    Args:
        payload (dict): Request payload data
        request (dict): User Request

    Raises:
        Exception: Unsupported provider

    Returns:
        class 'celery.app.task': Celery task
    """
    if 'account_id' in payload:
        account = CloudAccount.objects.filter(id=payload['account_id'])[0]

        if account.provider in supported_providers:
            task = supported_providers[account.provider]['provider'].validate_credentials(payload, request, storage_enabled)
            return task

    elif 'credentials' in payload:
        for provider in payload['credentials']:
            if provider in supported_providers:
                task = supported_providers[provider]['provider'].validate_credentials(payload, request, storage_enabled)
                return task

    raise Exception('provider is not supported')

def update_cloud_credentials(payload, request):
    """Updates cloud provider account credentials

    Args:
        payload (dict): Request payload data
        request (dict): User Request

    Raises:
        Exception: Unsupported provider
    """
    if payload['provider'] in supported_providers:
        supported_providers[payload['provider']]['provider'].update_cloud_credentials(payload, request)
    else:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error('Invalid provider parameter.', extra=log_data)
        raise Exception('Invalid provider parameter.')


def create_cloud_credentials(payload, request, all_account_labels):
    """Create cloud provider account credentials

    Args:
        payload (dict): Request payload data
        request (dict): User Request
        all_account_labels (list): All used account labels

    Raises:
        Exception: Unsupported provider
    """
    if payload['provider'] in supported_providers:
        supported_providers[payload['provider']]['provider'].create_cloud_credentials(payload, request, all_account_labels)
    else:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error('Invalid provider parameter.', extra=log_data)
        raise Exception('Invalid provider parameter.')

def delete_cloud_credentials(cloudaccount):
    """Delete cloud provider account credentials

    Args:
        cloudaccount (class 'django.db.models.Model'): Cloud account model
    """
    if cloudaccount.provider in supported_providers:
        supported_providers[cloudaccount.provider]['provider'].delete_cloud_credentials(cloudaccount)
    else:
        log_data = {
            'level': 'ERROR',
        }
        logger.error('Invalid provider parameter.', extra=log_data)
        raise Exception('Invalid provider parameter.')

def get_provider_accounts(payload, request):
    """Get user cloud provider accounts

    Args:
        payload (dict): Request payload data
        request (dict): User Request

    Returns:
        list: List of user cloud provider accounts
    """
    accounts = []
    if payload['provider'] in supported_providers:
        provider_accounts = CloudAccount.objects.filter(provider=payload['provider'], valid=True)
        for provider_account in provider_accounts:
            if provider_account.checkUserAccess(request.daiteap_user):
                accounts.append({
                    'label': provider_account.label,
                    'id': provider_account.id,
                })
    return accounts

def get_valid_regions(payload, request):
    """Returns a list of regions that are valid for the account

    Args:
        payload (dict): Request payload data
        request (dict): User Request

    Raises:
        Exception: Account does not exist

    Returns:
        list: List of regions that are valid for the account
    """
    if payload['provider'] in supported_providers:
        try:
            account = CloudAccount.objects.filter(id=payload['accountId'],tenant_id=request.daiteap_user.tenant_id, provider=payload['provider'])[0]
        except:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Account does not exist.', extra=log_data)
            raise Exception('Account does not exist.')

        regions = []

        account_regions = account.regions
        regions_dict = json.loads(account_regions)
        for region in regions_dict:
            regions.append(region['name'])
    return regions

def get_valid_zones(payload, request):
    """Returns a list of zones that are valid for the account

    Args:
        payload (dict): Request payload data
        request (dict): User Request

    Raises:
        Exception: Account does not exist

    Returns:
        list: List of zones that are valid for the account
    """
    if payload['provider'] in supported_providers:
        try:
            account = CloudAccount.objects.filter(id=payload['accountId'],tenant_id=request.daiteap_user.tenant_id, provider=payload['provider'])[0]
        except:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Account does not exist.', extra=log_data)
            raise Exception('Account does not exist.')
        account_regions = account.regions
        regions_dict = json.loads(account_regions)
        zones = []
        for region in regions_dict:
            if region['name'] == payload['region']:
                for zone in region['zones']:
                    zones.append(zone['name'])
                break
    return zones


def get_valid_instances(payload, request):
    """Returns a list of instance types that are valid for the account

    Args:
        payload (dict): Request payload data
        request (dict): User Request

    Raises:
        Exception: Account does not exist

    Returns:
        list: List of instance types that are valid for the account
    """
    if payload['provider'] in supported_providers:
        try:
            account = CloudAccount.objects.filter(id=payload['accountId'], tenant_id=request.daiteap_user.tenant_id, provider=payload['provider'])[0]
        except:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Account does not exist.', extra=log_data)
            raise Exception('Account does not exist.')
        account_regions = account.regions
        regions_dict = json.loads(account_regions)

        instances = []

        if 'zone' in payload:
            for region in regions_dict:
                if region['name'] == payload['region']:
                    for zone in region['zones']:
                        if zone['name'] == payload['zone']:
                            for instance_type in zone['instances']:
                                instances.append(instance_type)
                            break

        else:
            for region in regions_dict:
                if region['name'] == payload['region']:
                    for zone in region['zones']:
                        for instance_type in zone['instances']:
                            if instance_type not in instances:
                                instances.append(instance_type)
                    break
    return instances

def get_cluster_machines(cluster, request, payload, config):
    """Get the list of machines in a cluster

    Args:
        cluster (class 'cloudcluster.models.Clusters): Cluster from db
        request (dict): User Request
        payload (dict): Request payload data
        config (dict): Cluster config

    Raises:
        Exception: Can\'t find any of the cluster\'s machines.

    Returns:
        list: List of machines in a cluster
    """
    try:
        cluster_machines = Machine.objects.filter(cluster=cluster).values(
            'id',
            'name',
            'type',
            'publicIP',
            'privateIP',
            'provider',
            'region',
            'zone',
            'operating_system',
            'status',
            'cpu',
            'ram',
            'hdd',
            'kube_master',
            'kube_name',
            'sync_ssh_status',
            'sync_ssh_error_message'
        )
        if cluster.installstep not in [1, -1, -100, 100] and len(cluster_machines) < 1 and cluster.type == constants.ClusterType.COMPUTE_VMS.value:
            raise Exception('Can\'t find any of the cluster\'s machines.')
    except Exception as e:
        print(e)
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Can\'t find any of the cluster\'s machines.', extra=log_data)
        raise Exception('Can\'t find any of the cluster\'s machines.')

    # Get regions and zones
    cluster_machines = list(cluster_machines)
    providers = {}

    for machine in cluster_machines:
        providers[machine['provider'] + 'Selected'] = True
        providers[machine['provider']] = {
            'region': machine['region'],
            'zone': machine['zone'],
            'vpcCidr': config[machine['provider']]['vpcCidr'],
            'account': config[machine['provider']]['account'],
            'accountLabel': CloudAccount.objects.get(id=config[machine['provider']]['account']).label
        }
        machine['network'] = config[machine['provider']]['vpcCidr']

    return providers, cluster_machines

def get_providers_networks(payload):
    """Extracts the network requested by each provider

    Args:
        payload (dict): Request payload data

    Returns:
        list: List of networks
    """
    networks = []

    for provider in supported_providers:
        if provider in payload:
            networks.append(payload[provider]['vpcCidr'])

    return networks

def check_provided_credentials(request):
    """Checks if credentials for each cloud provider are provided

    Args:
        request (dict): User Request

    Returns:
        dict: Dictionary that contains information for each provider if the credentials for that provider are added
    """
    response = {}

    for supported_provider in supported_providers:
        if len(CloudAccount.objects.filter(tenant_id=request.daiteap_user.tenant_id, provider=supported_provider, valid=True).exclude(credentials='')) > 0:
            response[supported_provider + '_key_provided'] = True
        else:
            response[supported_provider + '_key_provided'] = False

    return response

def check_controlplane_nodes(resources):
    """Checks if controlplane node count is legal

    Args:
        resources (dict): Environment resources

    Returns:
        bool: Returns true if controlplane node count is legal, else returns false
    """
    nodes_count = 0
    for environment_provider in supported_providers:
        if environment_provider in resources:
            for node in resources[environment_provider]['nodes']:
                if node['is_control_plane']:
                    nodes_count += 1

    if nodes_count % 2 == 0:
        return False

    return True

def get_dns_servers_ips(nodes_ips):
    """Returns a dictionary containing all dns servers ips

    Args:
        nodes_ips (dict): From get_nodes_ips function

    Returns:
        dict: Dictionary containing all dns servers ips
    """
    dns_servers_ips = {}

    for supported_provider in supported_providers:
        if supported_provider + '_nodes' in nodes_ips:
            dns_servers_ips[supported_provider + '_server_ip'] = nodes_ips[supported_provider + '_nodes'][0]

    return dns_servers_ips

def nodes_labels(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    """Add label to each kubernetes node provider={provider name}

    Args:
        resources (dict): Cluster config
        user_id (int): User id
        clouds (dict): Dictionary containing each cloud nodes info (returned from get_nodes function) 
        master_ip (string): DC private IP
        gateway_address (string): Address of the gateway node
        cluster_id (class 'uuid.UUID'): Cluster id
    """
    for supported_provider in supported_providers:
        if supported_provider in clouds:
            supported_providers[supported_provider]['provider'].run_nodes_labels(resources, user_id, clouds, master_ip, gateway_address, cluster_id)

def get_vpn_provider_networks(resources, skip_network_providers):
    """Get the vpn providers networks

    Args:
        resources (dict): Cluster config
        skip_network_providers (list)): List of providers to skip

    Returns:
        list: List of networks
    """
    vpn_provider_networks = []

    for supported_provider in supported_providers:
        if supported_provider in resources and supported_provider not in skip_network_providers:
            vpn_provider_networks.append({"remote_network": resources[supported_provider]['vpcCidr']})

    return vpn_provider_networks

def kubernetes_storage_integration(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    """Add cloud native storage integrations on kubernetes cluster

    Args:
        resources (dict): Cluster config
        user_id (int): User id
        clouds (dict): Dictionary containing each cloud nodeinfo (returned from get_nodes function) 
        master_ip (string): DC private IP
        gateway_address (string): Address of the gateway node
        cluster_id (class 'uuid.UUID'): Cluster id
    """
    for supported_provider in supported_providers:
        if supported_provider in resources:
            supported_providers[supported_provider]['provider'].kubernetes_storage_integration(resources, user_id, clouds, master_ip, gateway_address, cluster_id)

def kubernetes_loadbalancer_integration(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    """Add kubernetes loadbalancer intergration for selected cloud provider

    Args:
        resources (dict): Cluster config
        user_id (int): User id
        clouds (dict): Dictionary containing each cloud nodes info (returned from get_nodes function) 
        master_ip (string): DC private IP
        gateway_address (string): Address of the gateway node
        cluster_id (class 'uuid.UUID'): Cluster id
    """
    if 'load_balancer_integration' in resources:
        for supported_provider in supported_providers:
            if resources['load_balancer_integration'] == supported_provider and supported_provider in resources:
                supported_providers[supported_provider]['provider'].kubernetes_loadbalancer_integration(resources, user_id, clouds, master_ip, gateway_address, cluster_id)

def remove_nodeselector_from_ccm(resources, user_id, master_node_private_ip, gateway_address, cluster_id):
    """Remove nodeselector from the cloud controller manager kubernetes cluster (used when adding new machines)

    Args:
        resources (dict): Cluster config
        user_id (int): User id
        master_node_private_ip (string): Master kubernetes node private ip
        gateway_address (string): Address of the gateway node
        cluster_id (class 'uuid.UUID'): Cluster id
    """
    if 'load_balancer_integration' in resources:
        for supported_provider in supported_providers:
            if resources['load_balancer_integration'] == supported_provider and supported_provider in resources:
                supported_providers[supported_provider]['provider'].remove_nodeselector_from_ccm(resources, user_id, master_node_private_ip, gateway_address, cluster_id)

def add_nodeselector_to_ccm(resources, user_id, master_node_private_ip, gateway_address, cluster_id):
    """Add a nodeselector to the cluster

    Args:
        resources (dict): Cluster config
        user_id (int): User id
        master_node_private_ip (string): Master kubernetes node private ip
        gateway_address (string): Address of the gateway node
        cluster_id (class 'uuid.UUID'): Cluster id
    """
    if 'load_balancer_integration' in resources:
        for supported_provider in supported_providers:
            if resources['load_balancer_integration'] == supported_provider and supported_provider in resources:
                supported_providers[supported_provider]['provider'].add_nodeselector_to_ccm(resources, user_id, master_node_private_ip, gateway_address, cluster_id)

def get_storageclass_name(resources):
    """Returns the kubernetes storageclass name

    Args:
        resources (dict): Cluster config

    Returns:
        string: Kubernetes storageclass name
    """
    for supported_provider in supported_providers:
        if supported_provider in resources:
            storage_class = supported_providers[supported_provider]['provider'].get_storageclass_name()

    return storage_class

def set_vpn_configs(filtered_environment_providers, vpn_configs, resources, cluster_id, user_id, vpn_provider_name):
    """Returns vpn configurations

    Args:
        filtered_environment_providers (list): Environments used to create cluster
        vpn_configs (dict): vpn configurations
        resources (dict): Cluster config
        cluster_id (class 'uuid.UUID'): Cluster id
        user_id (int): User id
        vpn_provider_name (string): VPN provider name

    Returns:
        dict: VPN configurations
    """
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    vpn_secrets = json.loads(cluster.vpn_secrets)
    vpn_providers = []

    if len(filtered_environment_providers) > 1:
        for filtered_environment_provider in filtered_environment_providers:
            if vpn_provider_name != filtered_environment_provider:
                vpn_providers += supported_providers[filtered_environment_provider]['provider'].set_vpn_configs(vpn_configs, resources, vpn_secrets, vpn_provider_name, user_id)

    return vpn_providers

def get_dns_configs(resources, nodes_ips, dns_servers_ips, cluster_id):
    """Returns DNS configs for selected providers

    Args:
        resources (dict): Cluster config
        nodes_ips (dict): From get_nodes_ips function
        dns_servers_ips ([type]): Response 
        cluster_id (class 'uuid.UUID'): Cluster id

    Returns:
        [type]: [description]
    """
    providers_dns_configs = {}

    for supported_provider in supported_providers:
        if supported_provider in resources:
            providers_dns_configs.update(supported_providers[supported_provider]['provider'].get_dns_config(resources, nodes_ips, dns_servers_ips, cluster_id))

    return providers_dns_configs

def run_dns(resources, nodes_ips, dns_servers_ips, cluster_id, user_id, gateway_address, v2):
    """Installs and configures dns server each provider. Also configures all nodes to use the servers

    Args:
        resources (dict): Cluster config
        nodes_ips (dict): From get_nodes_ips function
        dns_servers_ips (DICT): Dictionary containing all dns servers ips (returned from get_dns_servers_ips function)
        cluster_id (class 'uuid.UUID'): Cluster id
        user_id (int): User id
        gateway_address (string): Address of the gateway node
    """
    providers_dns_configs = get_dns_configs(resources, nodes_ips, dns_servers_ips, cluster_id)

    for supported_provider in supported_providers:
        if supported_provider in resources:
            supported_providers[supported_provider]['provider'].run_dns(resources, nodes_ips, dns_servers_ips, cluster_id, user_id, gateway_address, providers_dns_configs, supported_provider, v2=v2)

def get_ansible_dns_servers(current_provider, resources, providers_dns_configs):
    """Returns DNS configurations for selected provider

    Args:
        current_provider (string): The provider for which the returned dns configuration is created
        resources (dict): Cluster config
        providers_dns_configs (dict): All providers dns configurations (returned from get_dns_configs function)

    Returns:
        string: DNS configurations for selected provider
    """
    selected_providers_configs = []
    selected_providers_configs.append(providers_dns_configs[current_provider])
    for provider in providers_dns_configs:
        if provider not in selected_providers_configs and provider in resources and provider in supported_providers:
            selected_providers_configs.append(providers_dns_configs[provider])

    dns_servers = ""
    counter = 0
    for i, _ in enumerate(selected_providers_configs):
        if counter == 0:
            dns_servers = dns_servers + selected_providers_configs[i]['publicDnsServer']
        else:
            dns_servers = dns_servers + selected_providers_configs[i]['privateDnsServer']
        counter += 1
    dns_servers = dns_servers + selected_providers_configs[0]['lastDnsServer']

    return dns_servers

def run_add_dns_address(machines, new_nodes_privateips, clouds, user_id, cluster, server_private_ip, gateway_address):
    if machines['provider'] in supported_providers:
        supported_providers[machines['provider']]['provider'].run_add_dns_address(machines, new_nodes_privateips, clouds, user_id, cluster, server_private_ip, gateway_address)

def get_user_friendly_params(config, is_capi = False, is_yaookcapi = False):
    for provider in config:
        if provider in supported_providers:
            config[provider] = supported_providers[provider]['provider'].get_user_friendly_params(config[provider], is_capi, is_yaookcapi)

    return config

def get_autosuggested_params(provider):
    if provider in supported_providers:
        return supported_providers[provider]['provider'].get_autosuggested_params()

    return {}

def get_storage_buckets(payload, request):
    if payload['provider'] in supported_providers:
        return supported_providers[payload['provider']]['provider'].get_storage_buckets(payload, request)
    else:
        return {'error': "Invalid provider parameter."}

def create_storage_bucket(payload, request):
    if payload['provider'] in supported_providers:
        return supported_providers[payload['provider']]['provider'].create_storage_bucket(payload, request)
    else:
        return {'error': "Invalid provider parameter."}

def delete_storage_bucket(payload, request):
    if payload['provider'] in supported_providers:
        return supported_providers[payload['provider']]['provider'].delete_storage_bucket(payload, request)
    else:
        return {'error': "Invalid provider parameter."}

def get_bucket_files(payload, request):
    if payload['provider'] in supported_providers:
        return supported_providers[payload['provider']]['provider'].get_bucket_files(payload, request)
    else:
        return {'error': "Invalid provider parameter."}

def add_bucket_file(payload, request):
    if payload['provider'] in supported_providers:
        return supported_providers[payload['provider']]['provider'].add_bucket_file(payload, request)
    else:
        return {'error': "Invalid provider parameter."}

def delete_bucket_file(payload, request):
    if payload['provider'] in supported_providers:
        return supported_providers[payload['provider']]['provider'].delete_bucket_file(payload, request)
    else:
        return {'error': "Invalid provider parameter."}

def download_bucket_file(payload, request):
    if payload['provider'] in supported_providers:
        return supported_providers[payload['provider']]['provider'].download_bucket_file(payload, request)
    else:
        return {'error': "Invalid provider parameter."}

def get_storage_accounts(provider, credential_id):
    if provider in supported_providers:
        return supported_providers[provider]['provider'].get_storage_accounts(credential_id)
    else:
        return {'error': "Invalid provider parameter."}

def delete_bucket_folder(payload, request):
    if payload['provider'] in supported_providers:
        return supported_providers[payload['provider']]['provider'].delete_bucket_folder(payload, request)
    else:
        return {'error': "Invalid provider parameter."}

def get_bucket_details(payload, request):
    if payload['provider'] in supported_providers:
        return supported_providers[payload['provider']]['provider'].get_bucket_details(payload, request)
    else:
        return {'error': "Invalid provider parameter."}

def get_cloud_account_info(cloud_account):
    if cloud_account.provider in supported_providers:
        return supported_providers[cloud_account.provider]['provider'].get_cloud_account_info(cloud_account)
    else:
        return {'error': "Invalid provider parameter."}