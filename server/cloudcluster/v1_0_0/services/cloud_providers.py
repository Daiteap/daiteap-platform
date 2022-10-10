import json

from cloudcluster.models import CloudAccount


def validate_cloud_provider_regions_zones_instance_types_custom_nodes(provider_data, user):
    account_id = provider_data['account']
    region = provider_data['region']

    try:
        account = CloudAccount.objects.filter(id=account_id, tenant__daiteapuser__user=user)[0]
    except Exception as e:
        print(e)
        raise AttributeError('Account does not exist')

    provider_region_valid = False
    provider_zone_valid = True
    provider_instance_type_valid = True

    for region_option in json.loads(account.regions):
        if region == region_option['name']:
            provider_region_valid = True
            for node in provider_data['nodes']:
                if 'zone' in node:
                    available_zone_names = [option['name'] for option in region_option['zones']]
                    zone = node['zone']
                    if zone not in available_zone_names:
                        provider_zone_valid = False
                        break

                    available_zones = [option for option in region_option['zones']]
                    available_instances = []
                    for available_zone in available_zones:
                        if zone == available_zone['name']:
                            available_instances = [instance['name'] for instance in available_zone['instances']]
                            break

                    instanceType = node['instanceType']
                    if instanceType not in available_instances:
                        provider_instance_type_valid = False
                        break
            break

    if not provider_region_valid:
        raise AttributeError('Provider region is not legal')
    if not provider_zone_valid:
        raise AttributeError('Provider zone is not legal')
    if not provider_instance_type_valid:
        raise AttributeError('Provider instanceType is not legal')

def validate_cloud_provider_regions_zones_instance_types(provider_data, user):
    account_id = provider_data['account']
    region = provider_data['region']
    zone = provider_data['zone']
    instanceType = provider_data['instanceType']

    try:
        account = CloudAccount.objects.filter(id=account_id, tenant__daiteapuser__user=user)[0]
    except Exception as e:
        print(e)
        raise AttributeError('Account does not exist')

    provider_region_valid = False
    provider_zone_valid = False
    provider_instance_type_valid = False
    for region_option in json.loads(account.regions):
        if region == region_option['name']:
            provider_region_valid = True
            for zone_option in region_option['zones']:
                if zone == zone_option['name']:
                    provider_zone_valid = True
                    for instance_type_option in zone_option['instances']:
                        if instanceType == instance_type_option['name']:
                            provider_instance_type_valid = True
                            break
                    break
            break

    if not provider_region_valid:
        raise AttributeError('Provider region is not legal')
    if not provider_zone_valid:
        raise AttributeError('Provider zone is not legal')
    if not provider_instance_type_valid:
        raise AttributeError('Provider instanceType is not legal')

def validate_cloud_provider_regions_zones_instance_types_capi(provider_data, user):
    account_id = provider_data['account']
    region = provider_data['region']

    try:
        account = CloudAccount.objects.filter(id=account_id, tenant__daiteapuser__user=user)[0]
    except Exception as e:
        print(e)
        raise AttributeError('Account does not exist')

    provider_region_valid = False
    provider_zone_valid = True
    provider_instance_type_valid = True

    for region_option in json.loads(account.regions):
        if region == region_option['name']:
            provider_region_valid = True
            for node in provider_data['workerNodes']:
                if 'zone' in node:
                    available_zone_names = [option['name'] for option in region_option['zones']]
                    zone = node['zone']
                    if zone not in available_zone_names:
                        provider_zone_valid = False
                        break
                    available_zones = [option for option in region_option['zones']]
                    available_instances = []
                    for available_zone in available_zones:
                        if zone == available_zone['name']:
                            available_instances = [instance['name'] for instance in available_zone['instances']]
                            break

                    instanceType = node['instanceType']
                    if instanceType not in available_instances:
                        provider_instance_type_valid = False
                        break

            if 'zone' in provider_data['controlPlane']:
                available_zone_names = [option['name'] for option in region_option['zones']]
                zone = provider_data['controlPlane']['zone']
                if zone not in available_zone_names:
                    provider_zone_valid = False
                    break
                available_zones = [option for option in region_option['zones']]
                available_instances = []
                for available_zone in available_zones:
                    if zone == available_zone['name']:
                        available_instances = [instance['name'] for instance in available_zone['instances']]
                        break

                instanceType = provider_data['controlPlane']['instanceType']
                if instanceType not in available_instances:
                    provider_instance_type_valid = False
                    break
                break

    if not provider_region_valid:
        raise AttributeError('Provider region is not legal')
    if not provider_zone_valid:
        raise AttributeError('Provider zone is not legal')
    if not provider_instance_type_valid:
        raise AttributeError('Provider instanceType is not legal')

def validate_cloud_provider_regions_zones_instance_types_yaookcapi(provider_data, user):
    account_id = provider_data['account']
    region = provider_data['region']

    try:
        account = CloudAccount.objects.filter(id=account_id, tenant__daiteapuser__user=user)[0]
    except Exception as e:
        print(e)
        raise AttributeError('Account does not exist')

    provider_region_valid = False
    provider_zone_valid = True
    provider_instance_type_valid = True

    for region_option in json.loads(account.regions):
        if region == region_option['name']:
            provider_region_valid = True
            for node in provider_data['workerNodes']:
                if 'zone' in node:
                    available_zone_names = [option['name'] for option in region_option['zones']]
                    zone = node['zone']
                    if zone not in available_zone_names:
                        provider_zone_valid = False
                        break
                    available_zones = [option for option in region_option['zones']]
                    available_instances = []
                    for available_zone in available_zones:
                        if zone == available_zone['name']:
                            available_instances = [instance['name'] for instance in available_zone['instances']]
                            break

                    instanceType = node['instanceType']
                    if instanceType not in available_instances:
                        provider_instance_type_valid = False
                        break

            if 'zone' in provider_data['controlPlane']:
                available_zone_names = [option['name'] for option in region_option['zones']]
                zone = provider_data['controlPlane']['zone']
                if zone not in available_zone_names:
                    provider_zone_valid = False
                    break
                available_zones = [option for option in region_option['zones']]
                available_instances = []
                for available_zone in available_zones:
                    if zone == available_zone['name']:
                        available_instances = [instance['name'] for instance in available_zone['instances']]
                        break

                instanceType = provider_data['controlPlane']['instanceType']
                if instanceType not in available_instances:
                    provider_instance_type_valid = False
                    break
                break

    if not provider_region_valid:
        raise AttributeError('Provider region is not legal')
    if not provider_zone_valid:
        raise AttributeError('Provider zone is not legal')
    if not provider_instance_type_valid:
        raise AttributeError('Provider instanceType is not legal')