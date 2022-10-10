import json
from cloudcluster import models
from cloudcluster.v1_0_0.services import constants
from django.http import JsonResponse

import environment_providers.environment_providers as environment_providers


def authorize(payload, operation_type, daiteap_user_id, logger, existing_nodes_count=0, existing_kubernetes_cluster = False):
    """ Authorize user to perform operation """
    used_quota = get_used_quota(daiteap_user_id)

    used_quota['nodes'] = used_quota['nodes'] - existing_nodes_count

    if existing_kubernetes_cluster:
        used_quota['kubernetes_cluster_environments'] = used_quota['kubernetes_cluster_environments'] - 1

    used_nodes = used_quota['nodes']
    used_services = used_quota['services']
    used_kubernetes_cluster_environments = used_quota['kubernetes_cluster_environments']
    used_compute_vms_environments = used_quota['compute_vms_environments']

    operation_data = payload
    exceeded_resources = []

    try:
        user_usage_data = models.UserConfiguration.objects.filter(daiteap_user_id=daiteap_user_id)[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'daiteap_user_id': daiteap_user_id,
            'client_request': payload
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid daiteap user id',
            }
        }, status=400)

    if operation_type == 'add_machines_to_vms':
        new_nodes_count = operation_data['nodes']

        # Check if user have reached resource limit
        if user_usage_data.limit_nodes < used_nodes + new_nodes_count:
            exceeded_resources.append({
                'resource_type': 'Nodes',
                'used': used_nodes,
                'limit': user_usage_data.limit_nodes,
                'requested': new_nodes_count
            })

        # Update usage
        if not exceeded_resources:
            used_nodes += new_nodes_count
            user_usage_data.save()

    elif operation_type == 'add_machines_to_kubernetes':
        new_nodes_count = operation_data['nodes']

        # Check if user have reached resource limit
        if user_usage_data.limit_nodes < used_nodes + new_nodes_count:
            exceeded_resources.append({
                'resource_type': 'Nodes',
                'used': used_nodes,
                'limit': user_usage_data.limit_nodes,
                'requested': new_nodes_count
            })

        # Update usage
        if not exceeded_resources:
            used_nodes += new_nodes_count
            user_usage_data.save()

    elif operation_type == 'add_service':
        # Check if user have reached resource limit
        if user_usage_data.limit_services < used_services + 1:
            exceeded_resources.append({
                'resource_type': 'Kubernetes services',
                'used': used_services,
                'limit': user_usage_data.limit_services,
                'requested': 1
            })

        # Update usage
        if not exceeded_resources:
            used_services += 1
            user_usage_data.save()

    elif operation_type == 'create_kubernetes_cluster':
        try:
            new_nodes_count = CountNodes(operation_data)
        except Exception as e:
            return JsonResponse({
                'error': {
                    'message': str(e),
                }
            }, status=400)

        # Check if user have reached resource limit
        if user_usage_data.limit_kubernetes_cluster_environments < used_kubernetes_cluster_environments + 1:
            exceeded_resources.append({
                'resource_type': 'Kubernetes clusters',
                'used': used_kubernetes_cluster_environments,
                'limit': user_usage_data.limit_kubernetes_cluster_environments,
                'requested': 1
            })

        # Check if user have reached resource limit
        if user_usage_data.limit_nodes < used_nodes + new_nodes_count:
                exceeded_resources.append({
                    'resource_type': 'Nodes',
                    'used': used_nodes,
                    'limit': user_usage_data.limit_nodes,
                    'requested': new_nodes_count
                })

        # Update usage
        if not exceeded_resources:
            used_kubernetes_cluster_environments += 1
            used_nodes += new_nodes_count
            user_usage_data.save()

    elif operation_type == 'create_capi_cluster':
        try:
            new_nodes_count = CountCapiNodes(operation_data)
        except Exception as e:
            return JsonResponse({
                'error': {
                    'message': str(e),
                }
            }, status=400)

        # Check if user have reached resource limit
        if user_usage_data.limit_kubernetes_cluster_environments < used_kubernetes_cluster_environments + 1:
            exceeded_resources.append({
                'resource_type': 'Kubernetes clusters',
                'used': used_kubernetes_cluster_environments,
                'limit': user_usage_data.limit_kubernetes_cluster_environments,
                'requested': 1
            })

        # Check if user have reached resource limit
        if user_usage_data.limit_nodes < used_nodes + new_nodes_count:
                exceeded_resources.append({
                    'resource_type': 'Nodes',
                    'used': used_nodes,
                    'limit': user_usage_data.limit_nodes,
                    'requested': new_nodes_count
                })

        # Update usage
        if not exceeded_resources:
            used_kubernetes_cluster_environments += 1
            used_nodes += new_nodes_count
            user_usage_data.save()

    elif operation_type == 'create_yaookcapi_cluster':
        try:
            new_nodes_count = CountYaookCapiNodes(operation_data)
        except Exception as e:
            return JsonResponse({
                'error': {
                    'message': str(e),
                }
            }, status=400)

        # Check if user have reached resource limit
        if user_usage_data.limit_kubernetes_cluster_environments < used_kubernetes_cluster_environments + 1:
            exceeded_resources.append({
                'resource_type': 'Kubernetes clusters',
                'used': used_kubernetes_cluster_environments,
                'limit': user_usage_data.limit_kubernetes_cluster_environments,
                'requested': 1
            })

        # Check if user have reached resource limit
        if user_usage_data.limit_nodes < used_nodes + new_nodes_count:
                exceeded_resources.append({
                    'resource_type': 'Nodes',
                    'used': used_nodes,
                    'limit': user_usage_data.limit_nodes,
                    'requested': new_nodes_count
                })

        # Update usage
        if not exceeded_resources:
            used_kubernetes_cluster_environments += 1
            used_nodes += new_nodes_count
            user_usage_data.save()


    elif operation_type == 'create_VMs':
        # Check if user have reached resource limit
        if user_usage_data.limit_compute_vms_environments < used_compute_vms_environments + 1:
            exceeded_resources.append({
                'resource_type': 'Virtual Machines environments',
                'used': used_compute_vms_environments,
                'limit': user_usage_data.limit_compute_vms_environments,
                'requested': 1
            })

        try:
            new_nodes_count = CountNodes(operation_data)
        except Exception as e:
            return JsonResponse({
                'error': {
                    'message': str(e),
                }
            }, status=400)

        # Check if user have reached resource limit
        if user_usage_data.limit_nodes < used_nodes + new_nodes_count:
            exceeded_resources.append({
                'resource_type': 'Nodes',
                'used': used_nodes,
                'limit': user_usage_data.limit_nodes,
                'requested': new_nodes_count
            })

        # Update usage
        if not exceeded_resources:
            used_compute_vms_environments += 1
            used_nodes += new_nodes_count
            user_usage_data.save()
    
    elif operation_type == 'create_compute_VMs':
        # Check if user have reached resource limit
        if user_usage_data.limit_compute_vms_environments < used_compute_vms_environments + 1:
            exceeded_resources.append({
                'resource_type': 'Virtual Machines environments',
                'used': used_compute_vms_environments,
                'limit': user_usage_data.limit_compute_vms_environments,
                'requested': 1
            })

        try:
            new_nodes_count = CountNodes(operation_data)
        except Exception as e:
            return JsonResponse({
                'error': {
                    'message': str(e),
                }
            }, status=400)

        # Check if user have reached resource limit
        if user_usage_data.limit_nodes < used_nodes + new_nodes_count:
            exceeded_resources.append({
                'resource_type': 'Nodes',
                'used': used_nodes,
                'limit': user_usage_data.limit_nodes,
                'requested': new_nodes_count
            })

        # Update usage
        if not exceeded_resources:
            used_compute_vms_environments += 1
            used_nodes += new_nodes_count
            user_usage_data.save()

    else:
        log_data = {
            'level': 'ERROR',
            'daiteap_user_id': daiteap_user_id,
            'client_request': payload
        }
        logger.error('Invalid operation type', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid operation type',
            }
        }, status=400)

    if exceeded_resources:
        response_body = {
            'authorized': False,
            'exceededResources': exceeded_resources
        }
        return JsonResponse(response_body, status=400)

    models.Statistics.objects.create(daiteap_user_id=daiteap_user_id, request=json.dumps(operation_data), authorized=True)

    return None

def get_used_quota(daiteap_user_id):
    used_quota = {}

    used_quota['compute_vms_environments'] = len(models.Clusters.objects.filter(daiteap_user_id=daiteap_user_id, type__in=[
        constants.ClusterType.VMS.value, 
        constants.ClusterType.COMPUTE_VMS.value]))
    used_quota['kubernetes_cluster_environments'] = \
        len(models.Clusters.objects.filter(daiteap_user_id=daiteap_user_id, type__in=[
            constants.ClusterType.DLCM.value,
            constants.ClusterType.DLCM_V2.value,
            constants.ClusterType.CAPI.value,
            constants.ClusterType.K3S.value,
            constants.ClusterType.YAOOKCAPI.value])) + \
        len(models.CapiCluster.objects.filter(daiteap_user_id=daiteap_user_id)) + \
        len(models.YaookCapiCluster.objects.filter(daiteap_user_id=daiteap_user_id))

    user_clusters = models.Clusters.objects.filter(daiteap_user_id=daiteap_user_id)
    user_capi_clusters = models.CapiCluster.objects.filter(daiteap_user_id=daiteap_user_id)
    user_yaook_clusters = models.YaookCapiCluster.objects.filter(daiteap_user_id=daiteap_user_id)

    used_quota['nodes'] =  0

    for cluster in user_clusters:
        if cluster.type in [constants.ClusterType.DLCM.value,
                            constants.ClusterType.DLCM_V2.value,
                            constants.ClusterType.CAPI.value,
                            constants.ClusterType.K3S.value,
                            constants.ClusterType.YAOOKCAPI.value]:
            if cluster.resizeconfig and cluster.resizestep > 0:
                config = json.loads(cluster.resizeconfig)
                for provider in config:
                    if provider in environment_providers.supported_providers:
                        used_quota['nodes'] += len(config[provider]['nodes'])
            else:
                config = json.loads(cluster.config)
                for provider in config:
                    if provider in environment_providers.supported_providers:
                        used_quota['nodes'] += len(config[provider]['nodes'])

    for cluster in user_capi_clusters:
        config = json.loads(cluster.capi_config)
        for provider in config:
            if provider in  environment_providers.supported_providers:
                used_quota['nodes'] += len(config[provider]['workerNodes'])
                used_quota['nodes'] += config[provider]['controlPlane']['replicas']

    for cluster in user_yaook_clusters:
        config = json.loads(cluster.yaookcapi_config)
        for provider in config:
            if provider in  environment_providers.supported_providers:
                used_quota['nodes'] += len(config[provider]['workerNodes'])
                used_quota['nodes'] += config[provider]['controlPlane']['replicas']

    used_quota['services'] =  \
        len(models.ClusterService.objects.filter(capi_cluster__in=user_capi_clusters)) + \
        len(models.ClusterService.objects.filter(yaookcapi_cluster__in=user_yaook_clusters)) + \
        len(models.ClusterService.objects.filter(cluster__in=user_clusters))

    return used_quota

def get_quota_limits(daiteap_user_id):
    user_usage_data = models.UserConfiguration.objects.filter(daiteap_user_id=daiteap_user_id)[0]

    user_usage = {
        'account_type': user_usage_data.account_type,
        'limit_kubernetes_cluster_environments': user_usage_data.limit_kubernetes_cluster_environments,
        'limit_compute_vms_environments': user_usage_data.limit_compute_vms_environments,
        'limit_nodes': user_usage_data.limit_nodes,
        'limit_services': user_usage_data.limit_services,
    }

    return user_usage

def set_user_quotas(daiteap_user_id, payload):
    user_quotas = models.UserConfiguration.objects.filter(daiteap_user_id=daiteap_user_id)[0]
    
    user_quotas.limit_nodes = payload['nodes_quota']
    user_quotas.limit_services = payload['services_quota']
    user_quotas.limit_kubernetes_cluster_environments = payload['clusters_quota']
    user_quotas.limit_compute_vms_environments = payload['compute_quota']
    user_quotas.save()

def CountNodes(payload):
    nodes_count = 0
    if 'alicloud' in payload:
        nodes_count += len(payload['alicloud']['nodes'])
    if 'aws' in payload:
        nodes_count += len(payload['aws']['nodes'])
    if 'google' in payload:
        nodes_count += len(payload['google']['nodes'])
    if 'azure' in payload:
        nodes_count += len(payload['azure']['nodes'])
    if 'openstack' in payload:
        nodes_count += len(payload['openstack']['nodes'])
    if 'onpremise' in payload:
        nodes_count += len(payload['onpremise']['machines'])
    if 'iotarm' in payload:
        nodes_count += len(payload['iotarm']['machines'])

    return nodes_count

def CountCapiNodes(payload):
    nodes_count = 0
    if 'alicloud' in payload:
        nodes_count += len(payload['alicloud']['workerNodes'])
        nodes_count += payload['alicloud']['controlPlane']['replicas']
    if 'aws' in payload:
        nodes_count += len(payload['aws']['workerNodes'])
        nodes_count += payload['aws']['controlPlane']['replicas']
    if 'google' in payload:
        nodes_count += len(payload['google']['workerNodes'])
        nodes_count += payload['google']['controlPlane']['replicas']
    if 'azure' in payload:
        nodes_count += len(payload['azure']['workerNodes'])
        nodes_count += payload['azure']['controlPlane']['replicas']
    if 'openstack' in payload:
        nodes_count += len(payload['openstack']['workerNodes'])
        nodes_count += payload['openstack']['controlPlane']['replicas']
    if 'onpremise' in payload:
        nodes_count += len(payload['onpremise']['workerNodes'])
        nodes_count += payload['onpremise']['controlPlane']['replicas']
    if 'iotarm' in payload:
        nodes_count += len(payload['iotarm']['workerNodes'])
        nodes_count += payload['iotarm']['controlPlane']['replicas']

    return nodes_count

def CountYaookCapiNodes(payload):
    nodes_count = 0
    if 'alicloud' in payload:
        nodes_count += len(payload['alicloud']['workerNodes'])
        nodes_count += payload['alicloud']['controlPlane']['replicas']
    if 'aws' in payload:
        nodes_count += len(payload['aws']['workerNodes'])
        nodes_count += payload['aws']['controlPlane']['replicas']
    if 'google' in payload:
        nodes_count += len(payload['google']['workerNodes'])
        nodes_count += payload['google']['controlPlane']['replicas']
    if 'azure' in payload:
        nodes_count += len(payload['azure']['workerNodes'])
        nodes_count += payload['azure']['controlPlane']['replicas']
    if 'openstack' in payload:
        nodes_count += len(payload['openstack']['workerNodes'])
        nodes_count += payload['openstack']['controlPlane']['replicas']
    if 'onpremise' in payload:
        nodes_count += len(payload['onpremise']['workerNodes'])
        nodes_count += payload['onpremise']['controlPlane']['replicas']
    if 'iotarm' in payload:
        nodes_count += len(payload['iotarm']['workerNodes'])
        nodes_count += payload['iotarm']['controlPlane']['replicas']

    return nodes_count
