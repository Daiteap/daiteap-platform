def destroy_resources(resources, user_id, cluster_id, nodes_counter):
    """Returns Terraform variables for cluster deletion

    Args:
        resources ([object]): [Config parameters used for cluster creation]
        user_id ([int]): [User ID]
        cluster_id ([string]): [Cluster ID]
        nodes_counter ([type]): [Nodes counter]

    Raises:
        Exception: [Exception]

    Returns:
        tf_variables[string]: [Terraform variables]
        nodes_counter [type]: [Nodes counter]
    """

def destroy_disk_resources(resources):
    """Destroy disk resources that are not managed by Terraform

    Args:
        resources ([object]): [Config parameters used for cluster creation]
    """

def create_new_machines(resources, user_id, cluster_id, machines, new_indices_counter, old_machines):
    """Create Terraform variables for the new machines

    Args:
        resources ([object]): [Config parameters used for cluster creation]
        user_id ([int]): [User ID]
        cluster_id ([string]): [Cluster ID]
        machines ([object]): [Request body data]
        new_indices_counter ([type]): [Counter for new machines]
        old_machines ([type]): [Counter for old machines]

    Returns:
        [object]: [Terraform variables]
    """

def create_resources(resources, user_id, cluster_id, internal_dns_zone, nodes_counter):
    """Returns Terraform variables for cluster creation

    Args:
        resources ([object]): [Config parameters used for cluster creation]
        user_id ([int]): [User ID]
        cluster_id ([string]): [Cluster ID]
        internal_dns_zone ([string]): [Internal DNS zone]
        nodes_counter ([type]): [Nodes counter]

    Returns:
        [tf_variables]: [Terraform variables]
        [nodes_counter]: [Counts cluster nodes]
    """

def validate_regions_zones_instance_types(provider_data, user, environment_type):
    """Validates that all zones instance types are valid for regions.

    Args:
        provider_data ([string]): [Provider payload data]
        user ([int]): [User ID]
        environment_type (int): [Environment type]
    """

def get_provider_config_params(payload, user):
    """Get Configuration params from the request.

    Args:
        payload ([string]): [Request body data]
        user ([int]): [User ID]

    Returns:
        [type]: [description]
    """

def restart_machine(config, user_id, machine):
    """Restart a machine

    Args:
        config ([object]): [Cluster configuration]
        user_id ([int]): [User ID]
        machine ([int]): [Machine ID]
    """

def start_machine(cluster_id, user_id, machine):
    """Start a machine

    Args:
        cluster_id ([string]): [Cluster ID]
        user_id ([int]): [User ID]
        machine ([int]): [Machine ID]
    """

def stop_machine(cluster_id, user_id, machine):
    """Stop a machine

    Args:
        cluster_id ([string]): [Cluster ID]
        user_id ([int]): [User ID]
        machine ([int]): [Machine ID]
    """

def start_all_machines(cluster_id):
    """Start all running machines on a cluster

    Args:
        cluster_id ([string]): [Cluster ID]
    """

def restart_all_machines(cluster_id):
    """Restart all machines in a cluster

    Args:
        cluster_id ([string]): [Cluster ID]
    """


def stop_all_machines(cluster_id):
    """Stop all running machines on a cluster

    Args:
        cluster_id ([string]): [Cluster ID]
    """

def get_nodes(cluster_id, user_id):
    """Get all nodes from a cluster

    Args:
        cluster_id ([string]): [Cluster ID]
        user_id ([int]): [User ID]

    Returns:
        [object]: [Nodes]
    """

def get_machine_records(resources, environment_provider, cloud, cluster_id, nodes_counter, old_machine_counter=0):
    """Create machine records for DB

    Args:
        resources ([object]): [Config parameters used for cluster creation]
        environment_provider ([string]): [Environment provider name]
        cloud ([array]): [Array of nodes]
        cluster_id ([string]): [Cluster ID]
        nodes_counter ([int]): [Nodes counter]
        old_machine_counter (int, optional): [Old machines counter]. Defaults to 0.

    Returns:
        [type]: [description]
    """

def get_used_terraform_environment_resources(resources, user_id, nodes_counter):
    """Returns Terraform variables

    Args:
        resources ([object]): [Config parameters used for cluster creation]
        user_id ([int]): [User ID]
        nodes_counter ([type]): [description]

    Returns:
        [type]: [description]
    """

def get_tf_code(environment_type):
    """Get Terraform code for the environment

    Args:
        environment_type (int): Marker showing environment type

    Returns:
        [string]: [Terraform code]
    """

def get_valid_operating_systems(payload, environment_type, user_id):
    """Get a list of valid operating systems

    Args:
        payload ([type]): [Request body]
        environment_type (int): Marker showing environment type images
        user_id ([int]): [User ID]

    Returns:
        [array]: [List of available operating systems]
    """

def validate_account_permissions(credentials, user_id):
    """Validate cloud account permissions

    Args:
        credentials ([object]): [cloud credentials]
        user_id ([int]): [User ID]

    Returns:
        [object]: [None or Error]
    """

def update_provider_regions(account_id, user_id):
    """Update region parameters for cloud account

    Args:
        account_id ([int]): [Account ID]
        user_id ([int]): [User ID]
    """

def check_region_parameters(resources, user_id):
    """Check if selected regions are valid

    Args:
        resources ([object]): [Config parameters used for cluster creation]
        user_id ([int]): [User ID]

    Returns:
        [object]: ['provider': 'bool']
    """

def validate_credentials(payload, request):
    """Validate user cloud account credentials

    Args:
        payload ([object]): [Request body]
        request ([object]): [Request data]

    Raises:
        Exception: [Exception]

    Returns:
        [string]: [Async task]
    """

def update_cloud_credentials(payload, request):
    """Update user cloud account credentials

    Args:
        payload ([object]): [Request body]
        request ([object]): [Request data]
    """

def create_cloud_credentials(payload, request, all_account_labels):
    """Create Cloud Account credentials for a given user

    Args:
        payload ([object]): [Request body]
        request ([object]): [Request data]
        all_account_labels ([array]): [All used account labels]
    """

def get_gateway_address_dc_private_ip_and_client_hosts(clouds, master_private_ip, gateway_address, client_hosts, config, user_id):
    """Helper function to get the gateway IP and client hosts

    Args:
        clouds ([string]): [Cloud nodes from get_nodes function]
        master_private_ip ([string]): [Master node private ip]
        gateway_address ([string]): [Public address of the gateway node]
        client_hosts ([array]): [Client hosts list]
        config ([object]): [Config parameters used for cluster creation]
        user_id ([int]): [User ID]

    Returns:
        master_private_ip [string]: [Master node private ip]
        gateway_address [string]: [Public address of the gateway node]
        client_hosts [string]: [Client hosts list]
    """

def run_nodes_labels(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    """Add on each kubernetes node label "provider: {provider}" and "providerID: {provider_id}"

    Args:
        resources ([object]): [Config parameters used for cluster creation]
        user_id ([int]): [User ID]
        clouds ([string]): [Cloud nodes from get_nodes function]
        master_ip ([string]): [Master IP private address]
        gateway_address ([string]): [Public address of the gateway node]
        cluster_id ([string]): [Cluster ID]
    """

def kubernetes_storage_integration(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    """Adds a kubernetes storage integration

    Args:
        resources ([object]): [Config parameters used for cluster creation]
        user_id ([int]): [User ID]
        clouds ([string]): [Cloud nodes from get_nodes function]
        master_ip ([string]): [Master IP private address]
        gateway_address ([string]): [Public address of the gateway node]
        cluster_id ([string]): [Cluster ID]

    Raises:
        Exception: [Exception]
    """

def kubernetes_loadbalancer_integration(resources, user_id, clouds, master_ip, gateway_address, cluster_id):
    """Adds a kubernetes load balancer integration

    Args:
        resources ([object]): [Config parameters used for cluster creation]
        user_id ([int]): [User ID]
        clouds ([string]): [Cloud nodes from get_nodes function]
        master_ip ([string]): [Master IP private address]
        gateway_address ([string]): [Public address of the gateway node]
        cluster_id ([string]): [Cluster ID]

    Raises:
        Exception: [Exception]
    """

def remove_nodeselector_from_ccm(resources, user_id, master_node_private_ip, gateway_address, cluster_id):
    """Remove a nodeselector from cloud controller manager

    Args:
        resources ([object]): [Config parameters used for cluster creation]
        user_id ([int]): [User ID]
        master_node_private_ip ([type]): [One of the master nodes private IP]
        gateway_address ([string]): [Public address of the gateway node]
        cluster_id ([string]): [Cluster ID]
    """

def add_nodeselector_to_ccm(resources, user_id, master_node_private_ip, gateway_address, cluster_id):
    """Add a nodeselector cloud controller manager.

    Args:
        resources ([object]): [Config parameters used for cluster creation]
        user_id ([int]): [User ID]
        master_node_private_ip ([type]): [One of the master nodes private IP]
        gateway_address ([string]): [Public address of the gateway node]
        cluster_id ([string]): [Cluster ID]
    """

def get_storageclass_name():
    """Returns the kubernetes storage class name

    Returns:
        [string]: [Storage class name]
    """

def run_added_machines_vpn_routing(resources, user_id, cluster_id, new_machines):
    """Create vpn routes on nodes that are added to already created environment (use it if routing is not created with Terraform)

    Args:
        resources ([object]): [Config parameters used for cluster creation]
        user_id ([int]): [User ID]
        cluster_id ([string]): [Cluster ID]
        new_machines ([object]): [Object that contains all new machines]
    """

def run_vpn_routing(resources, user_id, cluster_id):
    """Create vpn routes (use it if routing is not created with Terraform)

    Args:
        resources ([object]): [Config parameters used for cluster creation]
        user_id ([int]): [User ID]
        cluster_id ([string]): [Cluster ID]
        new_machines ([object]): [Object that contains all new machines]
    """

def run_vpn_server(filtered_environment_providers, vpn_configs, resources, cluster_id, user_id):
    """Create vpn routes (use it if routing is not created with Terraform)

    Args:
        filtered_environment_providers ([object]): [Environments used to create cluster]
        vpn_configs ([object]): [VPN configurations]
        resources ([object]): [Config parameters used for cluster creation]
        cluster_id ([string]): [Cluster ID]
        user_id ([int]): [User ID]
    """

def add_new_machines_to_resources(machines, resources):
    """Add new machines to resources dict

    Args:
        machines (dict): payload with new machines
        resources (dict): Cluster config from database

    Returns:
        dict: updated config with included new machines
    """

def run_dns(resources, nodes_ips, dns_servers_ips, cluster_id, user_id, gateway_address, providers_dns_configs, supported_provider, v2):
    """Installs and configures dns server on the provider. Also configures all nodes to use the servers

    Args:
        resources (dict): Cluster config
        nodes_ips (dict): From get_nodes_ips function
        dns_servers_ips (DICT): Dictionary containing all dns servers ips (returned from get_dns_servers_ips function)
        cluster_id (class 'uuid.UUID'): Cluster id
        user_id (int): User id
        gateway_address (string): Address of the gateway node
        providers_dns_configs ([type]): Providers dns configs
        supported_provider ([type]): Provider name
    """