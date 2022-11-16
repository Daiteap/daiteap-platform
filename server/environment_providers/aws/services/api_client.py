from asyncio.log import logger
import time
import os

import boto3
import botocore

from environment_providers.aws import aws
from cloudcluster import settings

ALLOWED_REGIONS = [
        'eu-central-1',
        'eu-north-1',
        'ap-south-1',
        'eu-west-3',
        'eu-west-2',
        'eu-west-1',
        'us-east-1',
        'us-east-2',
        'us-west-1',
        'us-west-2'
    ]

def get_created_cluster_resources(aws_access_key_id, aws_secret_access_key, region_name, cluster_prefix):
    client = boto3.client('resourcegroupstaggingapi',
                          aws_access_key_id=aws_access_key_id,
                          aws_secret_access_key=aws_secret_access_key,
                          region_name=region_name)
    resources = client.get_resources()

    tag_name = 'daiteap-env-id'

    resources_list = []
    for resource in resources['ResourceTagMappingList']:
        if (any(tag.get('Key') == tag_name and tag.get('Value').replace('-', '').startswith(cluster_prefix) for tag in resource['Tags']) or
           any(tag.get('Key') == 'Name' and tag.get('Value').startswith(cluster_prefix) for tag in resource['Tags'])):

            # check if resource arn is instance
            if resource['ResourceARN'].startswith('arn:aws:ec2:') and resource['ResourceARN'].split(':')[-1].split('/')[0] == 'instance':
                # get instance state
                ec2 = boto3.resource(
                    'ec2',
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key,
                    region_name=region_name
                )

                try:
                    instance = ec2.Instance(resource['ResourceARN'].split(':')[-1].split('/')[-1])
                    if not instance or instance.state['Name'] == 'terminated':
                        continue
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                        continue
                    raise e
                except AttributeError as e:
                    logger.debug(e)
                    continue

            resources_list.append(resource)

    route53 = boto3.client(
        'route53',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name
    )

    route53_zones = route53.list_hosted_zones()
    for zone in route53_zones['HostedZones']:
        if zone['Config']['Comment'].replace('-', '').startswith(cluster_prefix):
            resources_list.append(zone)

    return resources_list

def delete_k8s_volume_resources(aws_access_key_id, aws_secret_access_key, region):
    if not aws_access_key_id:
        raise AttributeError('Invalid input parameter aws_access_key_id')
    if not aws_secret_access_key:
        raise AttributeError('Invalid input parameter aws_secret_access_key')
    if not region:
        raise AttributeError('Invalid input parameter region')

    # create ec2 client
    ec2 = boto3.client(
        'ec2',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region
    )

    volumes_describe = ec2.describe_volumes()
    if 'Volumes' in volumes_describe:
        volumes = volumes_describe['Volumes']
    else:
        return False

    for volume in volumes:
        if 'Tags' in volume and 'VolumeId' in volume:
            for tag in volume['Tags']:
                if 'Key' in tag and 'Value' in tag:
                    if tag['Key'] == 'CSIVolumeName' and 'pv-disk-daiteap-' in tag['Value']:
                        print('Deleting AWS disk', volume['VolumeId'])
                        max_retries = 48
                        wait_seconds = 5
                        for i in range(0, max_retries):
                            time.sleep(wait_seconds)
                            try:
                                ec2.delete_volume(VolumeId=volume['VolumeId'])
                            except Exception as e:
                                if 'is currently attached to' not in str(e):
                                    raise e
                                if i == max_retries - 1:
                                    raise e
                                continue
                            break
    return True


def check_user_permissions(aws_access_key_id, aws_secret_access_key, region, storage_enabled):
    if not aws_access_key_id:
        raise AttributeError('Invalid input parameter aws_access_key_id')
    if not aws_secret_access_key:
        raise AttributeError('Invalid input parameter aws_secret_access_key')
    if not region:
        raise AttributeError('Invalid input parameter region')

    sts_arn = boto3.client(
        'sts',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region).get_caller_identity()['Arn']

    if sts_arn.endswith(':root'):
        return ''
    
    username = __parse_arn(sts_arn)['resource']

    if not username:
        raise Exception('Invalid user credentials')

    # create ec2 client
    client = boto3.client(
        'iam',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region
    )

    list_policies = client.list_attached_user_policies(
        UserName=username
    )

    list_groups = client.list_groups_for_user(
        UserName=username
    )

    user_policies = []

    for group in list_groups['Groups']:
        # user_groups.append(group['GroupName'])
        list_attached_group_policies = client.list_attached_group_policies(GroupName=group['GroupName'])

        for attached_group_policy in list_attached_group_policies['AttachedPolicies']:
            user_policies.append(attached_group_policy['PolicyName'])

    for policy in list_policies['AttachedPolicies']:
        user_policies.append(policy['PolicyName'])

    if 'AmazonEC2FullAccess' not in user_policies:
        return 'Missing AmazonEC2FullAccess permission'

    if 'AmazonRoute53FullAccess' not in user_policies:
        return 'Missing AmazonRoute53FullAccess permission'

    if 'ResourceGroupsandTagEditorReadOnlyAccess' not in user_policies and 'ResourceGroupsandTagEditorFullAccess' not in user_policies:
        return 'Missing ResourceGroupsandTagEditor permission'

    if storage_enabled and 'AmazonS3FullAccess' not in user_policies:
        return 'Missing storage permissions.'

    if 'AWSOrganizationsReadOnlyAccess' not in user_policies:
        return 'Missing AWSOrganizationsReadOnlyAccess permission'

    return ''


def delete_k8s_loadbalancer_resources(aws_access_key_id, aws_secret_access_key, region, vpc_name, user_id, cluster_id):
    if not aws_access_key_id:
        raise AttributeError('Invalid input parameter aws_access_key_id')
    if not aws_secret_access_key:
        raise AttributeError('Invalid input parameter aws_secret_access_key')
    if not region:
        raise AttributeError('Invalid input parameter region')
    if not vpc_name:
        raise AttributeError('Invalid input parameter vpc_name')

    # create ec2 client
    ec2 = boto3.client(
        'ec2',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region
    )

    # get vpc id from vpc name
    vpcs_describe = ec2.describe_vpcs()
    if 'Vpcs' in vpcs_describe:
        vpcs = vpcs_describe['Vpcs']
    else:
        return False

    vpc_id = ''
    for vpc in vpcs:
        if 'Tags' in vpc and 'VpcId' in vpc:
            for tag in vpc['Tags']:
                if 'Key' in tag and 'Value' in tag:
                    if tag['Key'] == 'Name' and tag['Value'] == vpc_name:
                        vpc_id = vpc['VpcId']
                        break
            if vpc_id != '':
                break

    if vpc_id == '':
        print('VPC', vpc_name, 'not found')
        return False

    # create elb client
    elb = boto3.client(
        'elb',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region
    )
    load_balancers_describe = elb.describe_load_balancers()

    # get load balancers that are in the provided vpc
    if 'LoadBalancerDescriptions' in load_balancers_describe:
        load_balancers = load_balancers_describe['LoadBalancerDescriptions']

        load_balancers_for_deletion = []
        for load_balancer in load_balancers:
            if load_balancer['VPCId'] == vpc_id:
                load_balancers_for_deletion.append(
                    load_balancer['LoadBalancerName']
                )

    # stop all instances
    try:
        aws.stop_all_machines(cluster_id)
    except Exception as e:
        print(str(e))
        pass

    # delete load balancers that are in the provided vpc
    for load_balancer_name in load_balancers_for_deletion:
        elb.delete_load_balancer(LoadBalancerName=load_balancer_name)

    # create ec2 resource client
    ec2_resource = boto3.resource(
        'ec2',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region
    )

    security_groups_describe = ec2.describe_security_groups()

    default_sg = {}

    # get security groups that are in the provided vpc
    if 'SecurityGroups' in security_groups_describe:
        security_groups = security_groups_describe['SecurityGroups']

        security_groups_for_deletion = []
        for security_group in security_groups:
            if 'GroupName' in security_group and 'VpcId' in security_group:
                if security_group['GroupName'].endswith('-default') and security_group['VpcId'] == vpc_id:
                    default_sg = ec2_resource.SecurityGroup(security_group['GroupId'])
                if security_group['GroupName'].startswith('k8s-elb') and security_group['VpcId'] == vpc_id:
                    security_groups_for_deletion.append(security_group['GroupId'])

    if default_sg:
        ip_permissions = default_sg.ip_permissions[0]

        # delete UserIdGroupPairs in default sg
        if 'UserIdGroupPairs' in ip_permissions:
            default_sg.revoke_ingress(IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": default_sg.ip_permissions[0]['UserIdGroupPairs']
                }
            ])

    max_retries = 12
    wait_seconds = 5

    # delete security groups that are in the provided vpc
    for security_group_id in security_groups_for_deletion:
        for i in range(0, max_retries):
            time.sleep(wait_seconds)
            try:
                ec2.delete_security_group(GroupId=security_group_id)
                break
            except botocore.exceptions.ClientError as e:
                logger.debug(e)
                if 'NotFound' in str(e):
                    break
                if i == max_retries - 1:
                    raise e

    return True


def get_available_regions_parameters(aws_access_key_id, aws_secret_access_key):
    regions = []
    ec2 = boto3.client(
        'ec2',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name='eu-central-1'
    )
    response = ec2.describe_regions()

    for region in response['Regions']:
        if region['RegionName'] not in ALLOWED_REGIONS:
            continue

        filt = [
            {
                'Name': 'region-name',
                'Values': [region['RegionName']]
            }
        ]
        ec2 = boto3.client(
            'ec2',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region['RegionName']
        )

        response2 = ec2.describe_availability_zones(Filters=filt)
        if len(response2['AvailabilityZones']) > 0:
            region_option = {
                'name': region['RegionName'],
                'zones': []
            }
            filt = [
                {
                    'Name': 'processor-info.supported-architecture',
                    'Values': ['x86_64']
                }
            ]
            response3 = ec2.describe_instance_types(Filters=filt)

            instances = []

            for zone in response2['AvailabilityZones']:
                zone = {
                    'name': zone['ZoneName'],
                    'instances': []
                }
                region_option['zones'].append(zone)

                for instance in response3['InstanceTypes']:
                    if instance['InstanceType'].startswith('inf'):
                        continue

                    instance_option = {
                        'name': instance['InstanceType'],
                        'description': "",
                        'cpu': 0,
                        'ram': 0
                    }

                    instance_data = get_instance_type_parameters(aws_access_key_id, aws_secret_access_key, region['RegionName'], instance_option['name'], response3)

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

            regions.append(region_option)

    return regions

def get_machine_types_list(aws_access_key_id, aws_secret_access_key, region_name):
    ec2 = boto3.client(
        'ec2',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name
    )

    return ec2.describe_instance_types()

def get_instance_type_parameters(aws_access_key_id, aws_secret_access_key, region_name, instance_type, response3 = {}):
    if not response3:
        response3 = get_machine_types_list(aws_access_key_id, aws_secret_access_key, region_name)

    for instance in response3['InstanceTypes']:
        if 'x86_64' in instance['ProcessorInfo']['SupportedArchitectures']:
            if instance_type == instance['InstanceType']:
                return {
                    'cpu': instance['VCpuInfo']['DefaultVCpus'],
                    'ram': instance['MemoryInfo']['SizeInMiB']/1024
                }
    
    raise Exception('Can\'t find instance type.')

def __parse_arn(arn):
    elements = arn.split(':')
    result = {'arn': elements[0],
            'partition': elements[1],
            'service': elements[2],
            'region': elements[3],
            'account': elements[4]
           }
    if len(elements) == 7:
        result['resourcetype'], result['resource'] = elements[5:]
    elif '/' not in elements[5]:
        result['resource'] = elements[5]
        result['resourcetype'] = None
    else:
        result['resourcetype'], result['resource'] = elements[5].split('/')
    return result

def stop_instances(aws_access_key_id, aws_secret_access_key, region, instances):
    if not aws_access_key_id:
        raise AttributeError('Invalid input parameter aws_access_key_id')
    if not aws_secret_access_key:
        raise AttributeError('Invalid input parameter aws_secret_access_key')
    if not region:
        raise AttributeError('Invalid input parameter region')
    if instances == []:
        raise AttributeError('Invalid input parameter instances')

    ec2 = boto3.client(
        'ec2',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region
    )

    try:
        response = ec2.stop_instances(InstanceIds=instances, DryRun=False)
    except botocore.exceptions.ClientError as e:
        raise AttributeError(e)

    max_retries = 24
    wait_seconds = 20
    for i in range(0, max_retries):
        all_ok = True
        time.sleep(wait_seconds)
        try:
            response = ec2.describe_instances(InstanceIds=instances, DryRun=False)
            instances_response = response['Reservations'][0]['Instances']

            for instance in instances_response:
                if instance['State']['Name'] != 'stopped':
                    all_ok = False

            if all_ok:
                break

        except botocore.exceptions.ClientError as e:
            raise AttributeError(e)
        if i == max_retries - 1:
            raise Exception('Timeout while waiting instances to stop')

    return

def start_instances(aws_access_key_id, aws_secret_access_key, region, instances):
    if not aws_access_key_id:
        raise AttributeError('Invalid input parameter aws_access_key_id')
    if not aws_secret_access_key:
        raise AttributeError('Invalid input parameter aws_secret_access_key')
    if not region:
        raise AttributeError('Invalid input parameter region')
    if instances == []:
        raise AttributeError('Invalid input parameter instances')

    ec2 = boto3.client(
        'ec2',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region
    )

    try:
        response = ec2.start_instances(InstanceIds=instances, DryRun=False)
    except botocore.exceptions.ClientError as e:
        raise AttributeError(e)

    max_retries = 24
    wait_seconds = 20
    for i in range(0, max_retries):
        all_ok = True
        time.sleep(wait_seconds)
        try:
            response = ec2.describe_instances(InstanceIds=instances, DryRun=False)
            instances_response = response['Reservations'][0]['Instances']

            for instance in instances_response:
                if instance['State']['Name'] != 'running':
                    all_ok = False

            if all_ok:
                break

        except botocore.exceptions.ClientError as e:
            raise AttributeError(e)
        if i == max_retries - 1:
            raise Exception('Timeout while waiting instances to stop')

    return

def restart_instances(aws_access_key_id, aws_secret_access_key, region, instances):
    if not aws_access_key_id:
        raise AttributeError('Invalid input parameter aws_access_key_id')
    if not aws_secret_access_key:
        raise AttributeError('Invalid input parameter aws_secret_access_key')
    if not region:
        raise AttributeError('Invalid input parameter region')
    if instances == []:
        raise AttributeError('Invalid input parameter instance_id')

    stop_instances(aws_access_key_id, aws_secret_access_key, region, instances)
    start_instances(aws_access_key_id, aws_secret_access_key, region, instances)

    return

def get_all_available_daiteap_os_parameters(aws_access_key_id, aws_secret_access_key, region, image_name):
    all_os_parameters = []

    images = get_available_image_parameters(aws_access_key_id, aws_secret_access_key, region, image_name)

    for image in images:
        os = {
            'value': image['ImageLocation'],
            'os': image['Name']
        }
        all_os_parameters.append(os)

    return all_os_parameters

def get_all_available_os_parameters(aws_access_key_id, aws_secret_access_key, region):
    all_os_parameters = []

    debian_owners = ['136693071363', '379101102735']
    debian_image_families = [
        'debian-stretch-hvm-x86_64',
        # 'debian-10-amd64'
    ]
    ubuntu_owners = ['099720109477']
    ubuntu_image_families = [
        # 'ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server',
        # 'ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server',
        'ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server'
    ]
    # centos_owners = ['']
    # centos_image_families = [
    #     '',
    #     ''
    # ]

    debian_images = get_compute_available_image_parameters(aws_access_key_id, aws_secret_access_key, debian_owners, debian_image_families, region)
    ubuntu_images = get_compute_available_image_parameters(aws_access_key_id, aws_secret_access_key, ubuntu_owners, ubuntu_image_families, region)
    # centos_images = get_available_image_parameters(
    #     aws_access_key_id, aws_secret_access_key, centos_owners, centos_image_families)

    # Look if it could be deleted
    for image in debian_images:
        os = {
            'value': image['ImageLocation'],
            'os': 'Debian 9'
        }
        all_os_parameters.append(os)
    for image in ubuntu_images:
        os = {
            'value': image['ImageLocation'],
            'os': 'Ubuntu 20 LTS'
        }
        all_os_parameters.append(os)
    # for image in centos_images:
    #     os = {
    #         'value': centos_project + '/' + image['name'],
    #         'os': image['description'] 
    #     }
    #     all_os_parameters.append(os)

    return all_os_parameters

def get_available_image_parameters(aws_access_key_id, aws_secret_access_key, region, image_name):
    ec2 = boto3.client(
        'ec2',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region
    )

    response = ec2.describe_images(Filters=[
        {
            'Name': 'architecture',
            'Values': [
                'x86_64',
            ]
        },
        {
            'Name': 'virtualization-type',
            'Values': [
                'hvm',
            ]
        },
        {
            'Name': 'is-public',
            'Values': [
                'true',
            ]
        },
        {
            'Name': 'name',
            'Values': [
                image_name,
            ]
        }
    ])

    images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)

    return images

def get_compute_available_image_parameters(aws_access_key_id, aws_secret_access_key, owners, image_families, region):
    filtered_images = []

    ec2 = boto3.client(
        'ec2',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region
    )

    response = ec2.describe_images(Owners=owners,Filters=[
        {
            'Name': 'architecture',
            'Values': [
                'x86_64',
            ]
        },
        {
            'Name': 'virtualization-type',
            'Values': [
                'hvm',
            ]
        },
        {
            'Name': 'is-public',
            'Values': [
                'true',
            ]
        },
    ])

    images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
    for image in image_families:
        for image_param in images:
            if image in image_param['Name']:
                filtered_images.append(image_param)
                break

    return filtered_images


def check_if_imageid_exists(aws_access_key_id, aws_secret_access_key, region, owner, image_name):

    ec2 = boto3.client(
        'ec2',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region
    )

    try:
        response = ec2.describe_images(
            Filters=[
                {
                    'Name': 'name',
                    'Values': [
                        image_name,
                    ]
                }
            ],
            Owners=[ owner ]
        )
        return len(response) > 0
    except Exception as e:
        print("---- Exception: ", e)
        return False

def get_storage_buckets(credential_id, aws_credentials):
    client = boto3.client(
        's3',
        aws_access_key_id=aws_credentials['aws_access_key_id'],
        aws_secret_access_key=aws_credentials['aws_secret_access_key']
    )

    response = {'buckets': []}

    buckets = client.list_buckets()['Buckets']
    for bucket in buckets:
        bucket_location = client.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint']
        response_bucket = {
            'name': bucket['Name'],
            'storage_class': None,
            'location': bucket_location,
            'location_type': None,
            'time_created': bucket['CreationDate'],
            'provider': "aws",
            'credential_id': credential_id,
            'storage_account_url': None,
        }
        response['buckets'].append(response_bucket)

    return response 

def create_storage_bucket(aws_credentials, bucket_name, bucket_location, request, payload):
    client = boto3.client(
        's3',
        aws_access_key_id=aws_credentials['aws_access_key_id'],
        aws_secret_access_key=aws_credentials['aws_secret_access_key']
    )

    try:
        client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={
                'LocationConstraint': bucket_location,
            },
        )

        client.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={
                'TagSet': [
                    {
                        'Key': 'daiteap-workspace-id',
                        'Value': str(payload['daiteap-workspace-id'])
                    },
                    {
                        'Key': 'daiteap-user-id',
                        'Value': str(payload['daiteap-user-id'])
                    },
                    {
                        'Key': 'daiteap-username',
                        'Value': request.user.username
                    },
                    {
                        'Key': 'daiteap-user-email',
                        'Value': request.user.email
                    },
                    {
                        'Key': 'daiteap-platform-url',
                        'Value': request.headers['Origin']
                    },
                    {
                        'Key': 'daiteap-workspace-name',
                        'Value': payload['daiteap-workspace-name']
                    },
                ]
            },
        )

        response = {'done': True}
    except client.exceptions.BucketAlreadyOwnedByYou:
        response = {'error': 'Bucket name taken.'}
    except client.exceptions.BucketAlreadyExists:
        response = {'error': 'Bucket name taken.'}
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'IllegalLocationConstraintException':
            response = {'error': 'Bucket name taken.'}

    return response

def delete_storage_bucket(aws_credentials, bucket_name):
    client = boto3.client(
        's3',
        aws_access_key_id=aws_credentials['aws_access_key_id'],
        aws_secret_access_key=aws_credentials['aws_secret_access_key']
    )

    files = client.list_objects_v2(Bucket=bucket_name)
    if 'Contents' in files.keys():
        return {'error': 'Bucket is not empty.'}
    
    client.delete_bucket(
        Bucket=bucket_name,
    )
    return {'done': True}

def get_bucket_files(aws_credentials, bucket_name, path):
    client = boto3.client(
        's3',
        aws_access_key_id=aws_credentials['aws_access_key_id'],
        aws_secret_access_key=aws_credentials['aws_secret_access_key']
    )

    response = {'files': []}
    files = client.list_objects_v2(Bucket=bucket_name)
    dirs_in_folder = []

    if 'Contents' in files.keys():
        for bucket_file in files['Contents']:
            split_file_name = bucket_file['Key'].split("/")
            file_name_slash_count = len(split_file_name) - 1

            if path == "/":
                if file_name_slash_count == 0:
                    file_info = client.get_object(Bucket=bucket_name,Key=bucket_file['Key'])
                    response_file = {
                        'path': bucket_file['Key'],
                        'basename': bucket_file['Key'],
                        'type': "file",
                        'content_type': file_info['ContentType'],
                        'size': bucket_file['Size'],
                    }
                    response['files'].append(response_file)
                elif split_file_name[0] not in dirs_in_folder:
                    file_info = client.get_object(Bucket=bucket_name,Key=bucket_file['Key'])
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
                        file_info = client.get_object(Bucket=bucket_name,Key=bucket_file['Key'])
                        response_file = {
                            'path': bucket_file['Key'],
                            'basename': split_file_name[-1],
                            'type': "file",
                            'content_type': file_info['ContentType'],
                            'size': bucket_file['Size'],
                        }
                        response['files'].append(response_file)
                    if file_name_slash_count > path_slash_count and split_file_name[path_slash_count] not in dirs_in_folder:
                        filepath = ""
                        for index in range(len(split_path)):
                            filepath = filepath + "/" + split_file_name[index]
                        filepath = filepath + "/"

                        file_info = client.get_object(Bucket=bucket_name,Key=bucket_file['Key'])
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

def add_bucket_file(aws_credentials, bucket_name, file_name, content_type, contents, temporary_file):
    client = boto3.client(
        's3',
        aws_access_key_id=aws_credentials['aws_access_key_id'],
        aws_secret_access_key=aws_credentials['aws_secret_access_key']
    )

    if content_type == "folder":
        client.put_object(Body="",Bucket=bucket_name,Key=file_name)
    else:
        bytes_from_array = bytes(contents)
        with open(temporary_file, "wb") as binary_file:
            binary_file.write(bytes_from_array)
        uploadArgs = {'ContentType': content_type}
        client.upload_file(temporary_file, bucket_name, file_name, uploadArgs)
        os.remove(temporary_file)

    return {'done': True}

def delete_bucket_file(aws_credentials, bucket_name, file_name):
    client = boto3.client(
        's3',
        aws_access_key_id=aws_credentials['aws_access_key_id'],
        aws_secret_access_key=aws_credentials['aws_secret_access_key']
    )

    client.delete_object(Bucket=bucket_name,Key=file_name)
    return {'done': True}

def download_bucket_file(aws_credentials, bucket_name, file_name):
    client = boto3.client(
        's3',
        aws_access_key_id=aws_credentials['aws_access_key_id'],
        aws_secret_access_key=aws_credentials['aws_secret_access_key']
    )

    bucket_file = client.get_object(Bucket=bucket_name,Key=file_name)
    contents = bucket_file['Body'].read()
    contents_bytearray = list(contents)
    file_info = client.get_object(Bucket=bucket_name,Key=file_name)

    return {'content_type': file_info['ContentType'], 'contents': contents_bytearray}

def delete_bucket_folder(aws_credentials, bucket_name, folder_path):
    client = boto3.client(
        's3',
        aws_access_key_id=aws_credentials['aws_access_key_id'],
        aws_secret_access_key=aws_credentials['aws_secret_access_key']
    )

    if folder_path[0] == "/":
        folder_path = folder_path[1:]

    files = get_bucket_files(aws_credentials, bucket_name, folder_path)['files']
    for bucket_file in files:
        if bucket_file['content_type'] == "folder":
            delete_bucket_folder(aws_credentials, bucket_name, bucket_file['path'])
        else:
            delete_bucket_file(aws_credentials, bucket_name, bucket_file['path'])
    client.delete_object(Bucket=bucket_name,Key=folder_path)

    return {'done': True}

def get_bucket_details(aws_credentials, bucket_name):
    client = boto3.client(
        's3',
        aws_access_key_id=aws_credentials['aws_access_key_id'],
        aws_secret_access_key=aws_credentials['aws_secret_access_key']
    )

    response = {'bucket_details': []}

    buckets = client.list_buckets()['Buckets']
    for bucket in buckets:
        if bucket['Name'] == bucket_name:
            bucket_location = client.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint']
            response['bucket_details'].append({
                'location': bucket_location,
            })

    return response

def get_cloud_account_info(aws_credentials):
    iam_client = boto3.client(
        'iam',
        aws_access_key_id=aws_credentials['aws_access_key_id'],
        aws_secret_access_key=aws_credentials['aws_secret_access_key']
    )
    sts_client = boto3.client(
        'sts',
        aws_access_key_id=aws_credentials['aws_access_key_id'],
        aws_secret_access_key=aws_credentials['aws_secret_access_key']
    )
    org_client = boto3.client(
        'organizations',
        aws_access_key_id=aws_credentials['aws_access_key_id'],
        aws_secret_access_key=aws_credentials['aws_secret_access_key']
    )

    user = iam_client.get_user()
    identity = sts_client.get_caller_identity()
    account = org_client.describe_account(AccountId=identity['Account'])
    organization = org_client.describe_organization()

    cloud_data = dict()
    cloud_data['user'] = user['User']['UserName']
    cloud_data['account'] = account['Account']['Name']
    cloud_data['account_email'] = account['Account']['Email']
    cloud_data['organization_id'] = organization['Organization']['Id']
    cloud_data['organization_master_account_email'] = organization['Organization']['MasterAccountEmail']

    return(cloud_data)