import base64
import copy
import datetime
import traceback

from cloudcluster.serializers.profile_serializer import ProfileSerializer
from cloudcluster.serializers.user_serializer import UserSerializer
from cloudcluster.serializers.project_serializer import ProjectSerializer
from cloudcluster.serializers.cloud_account_serializer import CloudAccountSerializer
from cloudcluster.serializers.bucket_serializer import BucketSerializer
from environment_providers.azure.services.oauth import AzureAuthClient
import ipaddress
import json
import logging
import pathlib
import re
import time
import uuid
import os

from rest_framework import status
import environment_providers.environment_providers as environment_providers
import ipconflict
import pytz
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import yaml
#from python_wireguard import Key
from rest_framework.response import Response
from _datetime import timedelta
from celery.result import AsyncResult
from cloudcluster import models
from cloudcluster.settings import (API_GIT_COMMIT_INFO,
                                   AZURE_CLIENT_ADMINCONSENT_URI,
                                   AZURE_CLIENT_AUTHORIZE_URI,
                                   AZURE_CLIENT_CREATE_APP_URI,
                                   SUPPORTED_K3S_NETWORK_PLUGINS,
                                   SUPPORTED_K3S_VERSIONS,
                                   SUPPORTED_KUBEADM_NETWORK_PLUGINS,
                                   SUPPORTED_KUBEADM_VERSIONS,
                                   SUPPORTED_KUBERNETES_NETWORK_PLUGINS,
                                   SUPPORTED_KUBERNETES_VERSIONS,
                                   SUPPORTED_CAPI_KUBERNETES_VERSIONS,
                                   SUPPORTED_YAOOKCAPI_KUBERNETES_VERSIONS,
                                   KEYCLOAK_CONFIG)
from django.conf import settings
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.http import HttpResponse, JsonResponse, HttpResponseRedirect
from django.utils import timezone
from django.views.decorators.cache import cache_page
from environment_providers.google.services.oauth import GoogleAuthClient
from jsonschema import ValidationError, validate
from netaddr import IPAddress, IPNetwork
from .mailgun.mailgun_client import MailgunClient
from PIL import Image
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated

from .services import authorization_service, constants, vault_service
from .keycloak.keycloak import KeycloakConnect
from .services.random_string import (get_random_alphanumeric_string,
                                     get_random_lowercase_hex_letters)
from . import tasks

from .helpers import xstr
from django.contrib.auth.decorators import user_passes_test
from django.db.models.fields import Field
from . import custom_permissions

logger = logging.getLogger(__name__)


FILE_BASE_DIR = str(pathlib.Path(__file__).parent.absolute())
VERSION = pathlib.Path(__file__).parent.absolute().name.replace('v', '').replace('_', '.')

def get_request_body(request):
    if 'CONTENT_TYPE' not in request.META:
        return None, HttpResponse('Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n', status=400)
    if 'application/json' not in request.META['CONTENT_TYPE']:
        return None, HttpResponse('Your POST request must have the header \"Content-type: application/json\" as well as a valid JSON payload\n', status=400)

    try:
        payload = json.loads(request.body.decode('utf-8'))
    except:
        return None, HttpResponse('Your POST request must have a valid JSON payload\n', status=400)
    if not payload:
        return None, HttpResponse('Your POST request must have a valid JSON payload\n', status=400)

    return payload, None


def check_if_body_parameters_exist(body, parameters):
    for parameter in parameters:
        if parameter not in body:
            return JsonResponse({
                'error': {
                    'message': 'Missing or invalid parameter ' + parameter
                }
            }, status=400)
        if type(body[parameter]) is not bool and not body[parameter]:
            return JsonResponse({
                'error': {
                    'message': 'Missing or invalid parameter ' + parameter
                }
            }, status=400)
    return None

def check_if_name_is_occupied_by_other_environment(payload, user_id):
    env_with_same_name = models.Clusters.objects.filter(project__tenant__daiteapuser__user=user_id, title=payload['clusterName'].strip()).count()
    capi_env_with_same_name = models.CapiCluster.objects.filter(project__tenant__daiteapuser__user=user_id, title=payload['clusterName'].strip()).count()
    yaookcapi_env_with_same_name = models.YaookCapiCluster.objects.filter(project__tenant__daiteapuser__user=user_id, title=payload['clusterName'].strip()).count()
    if env_with_same_name != 0 or capi_env_with_same_name != 0 or yaookcapi_env_with_same_name != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(user_id),
            'client_request': payload,
        }
        logger.error('Environment with that name already exists.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Environment with that name already exists.'
            }
        }, status=400)

def check_if_compute_name_is_occupied_by_other_environment(payload, user_id):
    env_with_same_name = models.Clusters.objects.filter(type=constants.ClusterType.COMPUTE_VMS.value, project__tenant__daiteapuser__user=user_id, title=payload['clusterName'].strip()).count()
    if env_with_same_name != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(user_id),
            'client_request': payload,
        }
        logger.error('Environment with that name already exists.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Environment with that name already exists.'
            }
        }, status=400)

def check_if_dlcmv2_name_is_occupied_by_other_environment(payload, user_id):
    env_with_same_name = models.Clusters.objects.filter(type=constants.ClusterType.DLCM_V2.value, project__tenant__daiteapuser__user=user_id, title=payload['clusterName'].strip()).count()
    if env_with_same_name != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(user_id),
            'client_request': payload,
        }
        logger.error('Environment with that name already exists.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Environment with that name already exists.'
            }
        }, status=400)

def check_if_project_name_is_occupied_by_other_project(payload, tenant_id):
    project_with_same_name = models.Project.objects.filter(tenant__id=tenant_id, name=payload['name'].strip()).count()
    if project_with_same_name != 0:
        log_data = {
            'level': 'ERROR',
            'tenant_id': str(tenant_id),
            'client_request': payload,
        }
        logger.error('Environment with that name already exists.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Environment with that name already exists.'
            }
        }, status=400)

def is_private_network(network):
    ip_network = IPNetwork(network)

    if ip_network in IPNetwork("10.0.0.0/8") or \
    ip_network in IPNetwork("172.16.0.0/12") or \
    ip_network in IPNetwork("192.168.0.0/16"):
        return True
    else:
        return False

def get_kubernetes_upgrade_versions(config):
    upgrade_versions = []

    for kubernetes_version in SUPPORTED_KUBERNETES_VERSIONS:
        split_new_kubernetes_version = [int(x) for x in kubernetes_version.replace('v', '').split('.')]
        split_current_kubernetes_version = [int(x) for x in config['kubernetesConfiguration']['version'].replace('v', '').split('.')]

        if split_current_kubernetes_version[0] == split_new_kubernetes_version[0] and \
            (split_new_kubernetes_version[1] - split_current_kubernetes_version[1] == 1 or
            (split_current_kubernetes_version[1] == split_new_kubernetes_version[1] and
                split_current_kubernetes_version[2] < split_new_kubernetes_version[2])):
            upgrade_versions.append(kubernetes_version)
    return upgrade_versions

def get_k3s_upgrade_versions(config):
    upgrade_versions = []

    for kubernetes_version in SUPPORTED_K3S_VERSIONS:
        version = kubernetes_version.replace('+k3s1', '')
        split_new_kubernetes_version = [int(x) for x in version.replace('v', '').split('.')]
        split_current_kubernetes_version = [int(x) for x in config['kubernetesConfiguration']['version'].replace('+k3s1', '').replace('v', '').split('.')]

        if split_current_kubernetes_version[0] >= split_new_kubernetes_version[0] and \
            (split_new_kubernetes_version[1] - split_current_kubernetes_version[1] >= 1 or
            (split_current_kubernetes_version[1] == split_new_kubernetes_version[1] and
                split_current_kubernetes_version[2] < split_new_kubernetes_version[2])):
            upgrade_versions.append(kubernetes_version)
    return upgrade_versions

def check_ip_in_network(network, ip):
    try:
        if ip.endswith('.0') or ip.endswith('.00') or ip.endswith('.000') or ip.endswith('.255'):
            return False

        # Check if ip is valid
        ipaddress.ip_address(ip)

        # Check if ip is in network
        if IPAddress(ip) in IPNetwork(network):
            return True
        else:
            return False
    except Exception as e:
        return False

def check_ip_addresses(networks):
    for net in networks:
        # Check if network is valid
        try:
            ipaddress.IPv4Network(net)
        except ValueError as e:
            return JsonResponse({
                'error': {
                    'message': str(e)
                }
            }, status=400)

        # Check if network is private
        try:
            is_private = is_private_network(net)

            if not is_private:
                return JsonResponse({
                    'error': {
                        'message': 'Network addresses must be private'
                    }
                }, status=400)

        except ValueError as e:
            return JsonResponse({
                'error': {
                    'message': str(e)
                }
            }, status=400)

        # Check if network is in ranges
        not_in_range = True
        for i in range(8, 25):
            if net.endswith('/' + str(i)):
                not_in_range = False

        if not_in_range:
            return JsonResponse({
                'error': {
                    'message': 'Network leading bits must be between 8 and 24'
                }
            }, status=400)

    # Check for ip conflicts
    try:
        ip_conflicts = ipconflict.check_conflicts(networks, True)
    except Exception as e:
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    if ip_conflicts:
        return JsonResponse({
            'error': {
                'message': 'Networks must not conflict'
            }
        }, status=400)

    return None

@api_view(['GET'])
@permission_classes([AllowAny])
def is_alive(request):
    return JsonResponse({
        'status': True
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_version(request):
    return JsonResponse({
        'version': VERSION,
        'gitsha': API_GIT_COMMIT_INFO.split('|')[0],
        'date': API_GIT_COMMIT_INFO.split('|')[1],
        'time': API_GIT_COMMIT_INFO.split('|')[2]
    })

@swagger_auto_schema(method='get',
    responses={200: openapi.Response('', ProfileSerializer)},
    operation_description="Get user profile.",
    operation_summary="Get user profile.")
@swagger_auto_schema(method='put',
    request_body=ProfileSerializer,
    responses={200: openapi.Response('', ProfileSerializer)},
    operation_description="Update user profile.",
    operation_summary="Update user profile.")
@permission_classes([IsAuthenticated])
@api_view(['GET', 'PUT'])
def profile(request):
    if request.method == 'GET':
        serializer = ProfileSerializer(request.user.profile, context={'request': request})
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = ProfileSerializer(request.user.profile, data=request.data, context={'request': request})
        current_ssh_key = request.user.profile.sshpubkey
        new_ssh_key = request.data.get('sshpubkey')
        if serializer.is_valid():
            serializer.save()
            # check if sshpubkey is changed
            if current_ssh_key != new_ssh_key:
                request.user.profile.ssh_synchronized_machines.clear()
                request.user.profile.save()

            sync_users()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(method='get',
    responses={200: openapi.Response('', UserSerializer)},
    operation_description="Get user.",
    operation_summary="Get user.")
@swagger_auto_schema(method='put',
    request_body=UserSerializer,
    responses={200: openapi.Response('', UserSerializer)},
    operation_description="Update user.",
    operation_summary="Update user.")
@permission_classes([IsAuthenticated])
@api_view(['GET', 'PUT'])
def user(request):
    user = request.user

    if request.method == 'GET':
        serializer = UserSerializer(user)
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(method='get',
        operation_description="Get projects.",
        operation_summary="Get projects.",
        responses={200: openapi.Response('', ProjectSerializer(many=True))})
@swagger_auto_schema(method='post',
        request_body= ProjectSerializer,
        responses={200: openapi.Response('', ProjectSerializer)},
        operation_description="Create project.",
        operation_summary="Create project.")
@permission_classes([IsAuthenticated])
@api_view(['GET', 'POST'])
def project_list(request, tenant_id):
    if request.method == 'GET':
        projects = models.Project.objects.filter(tenant=tenant_id).all()

        user_projects = []
        for project in projects:
            if project.checkUserAccess(request.daiteap_user):
                user_projects.append(project)

        serializer = ProjectSerializer(user_projects, many=True)

        return Response(serializer.data)

    if request.method == 'POST':
        request.data['contact'] = request.user.email
        serializer = ProjectSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save(tenant=request.daiteap_user.tenant, user=request.user)

            project = models.Project.objects.get(id=serializer.data['id'])
            daiteapuser = models.DaiteapUser.objects.filter(user__username=request.user.username,tenant_id=project.tenant_id)[0]
            daiteapuser.projects.add(project)
            daiteapuser.save()
            sync_users()

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(method='get',
        responses={200: openapi.Response('', ProjectSerializer)},
        operation_description="Get project.",
        operation_summary="Get project.")
@swagger_auto_schema(method='put',
        request_body= ProjectSerializer,
        responses={200: openapi.Response('', ProjectSerializer)},
        operation_description="Update project.",
        operation_summary="Update project.")
@swagger_auto_schema(method='delete',
        operation_description="Delete project.",
        operation_summary="Delete project.")
@permission_classes([IsAuthenticated, custom_permissions.ProjectAccessPermission])
@api_view(['GET', 'PUT', 'DELETE'])
def project_detail(request, tenant_id, project_id):
    try:
        project = models.Project.objects.get(id=project_id, tenant_id=tenant_id)
    except models.Project.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = ProjectSerializer(project)
        return Response(serializer.data)
    if request.method == 'PUT':
        serializer = ProjectSerializer(project, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)
    if request.method == 'DELETE':
        if project.hasConnectedResources():
            return Response({
                'error': {
                    'message': 'Project has connected resources'
                }
            }, status.HTTP_400_BAD_REQUEST)

        if not project.checkUserAccess(request.daiteap_user):
            return Response({
                'error': {
                    'message': 'You do not have access to this project'
                }
            }, status.HTTP_400_BAD_REQUEST)

        project.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

@swagger_auto_schema(method='get',
        operation_description="Get cloud credentials.",
        operation_summary="Get cloud credentials.",
        responses={200: openapi.Response('', CloudAccountSerializer(many=True))})
@swagger_auto_schema(method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'account_params': openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'description': openapi.Schema(type=openapi.TYPE_STRING),
                        'label': openapi.Schema(type=openapi.TYPE_STRING),
                        'aws_access_key_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'aws_secret_access_key': openapi.Schema(type=openapi.TYPE_STRING),
                        'azure_tenant_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'azure_subscription_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'azure_client_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'azure_client_secret': openapi.Schema(type=openapi.TYPE_STRING),
                        'google_key': openapi.Schema(type=openapi.TYPE_STRING),
                        'application_credential_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'application_credential_secret': openapi.Schema(type=openapi.TYPE_STRING),
                        'region_name': openapi.Schema(type=openapi.TYPE_STRING),
                        'external_network_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'auth_url': openapi.Schema(type=openapi.TYPE_STRING),
                        'provider': openapi.Schema(type=openapi.TYPE_STRING),
                        'sharedCredentials': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    },
                    required=['label', 'description']
                ),
                'provider': openapi.Schema(type=openapi.TYPE_STRING),
                'sharedCredentials': openapi.Schema(type=openapi.TYPE_BOOLEAN),
            },
            required=['account_params', 'provider', 'sharedCredentials']
        ),
        responses={200: openapi.Response('', CloudAccountSerializer)},
        operation_description="Create cloud credentials. Set account account_params on provider.",
        operation_summary="Create cloud credentials.")
@permission_classes([IsAuthenticated])
@api_view(['GET', 'POST'])
def cloud_account_list(request, tenant_id):
    if request.method == 'GET':
        cloudaccounts = models.CloudAccount.objects.filter(tenant=tenant_id).all()

        cloudaccounts_filtered = []

        for account in cloudaccounts:
            try:
                account.owner = account.user.id
            except:
                account.owner = None

            try:
                account.cloud_account_info = environment_providers.get_cloud_account_info(account)
            except:
                account.cloud_account_info = {'error': ''}

            if account.checkUserAccess(request.daiteap_user):
                cloudaccounts_filtered.append(account)

        serializer = CloudAccountSerializer(cloudaccounts_filtered, many=True)

        return Response(serializer.data)

    if request.method == 'POST':
        serializer = CloudAccountSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save(tenant=request.daiteap_user.tenant, user=request.user, context={'request': request})
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(method='get',
        responses={200: openapi.Response('', CloudAccountSerializer)},
        operation_description="Get cloud credential.",
        operation_summary="Get cloud credential.")
@swagger_auto_schema(method='put',
        request_body= CloudAccountSerializer,
        responses={200: openapi.Response('', CloudAccountSerializer)},
        operation_description="Update cloud credential.",
        operation_summary="Update cloud credential.")
@swagger_auto_schema(method='delete',
        operation_description="Delete cloud credential.",
        operation_summary="Delete cloud credential.")
@permission_classes([IsAuthenticated, custom_permissions.CloudAccountAccessPermission])
@api_view(['GET', 'PUT', 'DELETE'])
def cloud_account_detail(request, tenant_id, cloudaccount_id):
    cloudaccount = models.CloudAccount.objects.get(id=cloudaccount_id, tenant_id=tenant_id)

    if request.method == 'GET':
        credentials = vault_service.read_secret(cloudaccount.credentials)
        credentials_data = dict()

        if cloudaccount.provider == 'aws':
            credentials_data['aws_access_key_id'] = credentials['aws_access_key_id']
        elif cloudaccount.provider == 'azure':
            credentials_data['azure_tenant_id'] = credentials['azure_tenant_id']
            credentials_data['azure_subscription_id'] = credentials['azure_subscription_id']
            credentials_data['azure_client_id'] = credentials['azure_client_id']
        elif cloudaccount.provider == 'google':
            if credentials['google_key']:
                creds = json.loads(credentials['google_key'])
                credentials_data['type'] = creds['type']
                credentials_data['project_id'] = creds['project_id']
                credentials_data['private_key_id'] = creds['private_key_id']
        elif cloudaccount.provider == 'openstack':
            credentials_data['region_name'] = credentials['region_name']
            credentials_data['auth_url'] = credentials['auth_url']
            credentials_data['application_credential_id'] = credentials['application_credential_id']
        elif cloudaccount.provider == 'onpremise':
            credentials_data['gw_public_ip'] = credentials['gw_public_ip']
            credentials_data['gw_private_ip'] = credentials['gw_private_ip']
            credentials_data['admin_username'] = credentials['admin_username']
        elif cloudaccount.provider == 'iotarm':
            credentials_data['gw_public_ip'] = credentials['gw_public_ip']
            credentials_data['gw_private_ip'] = credentials['gw_private_ip']
            credentials_data['admin_username'] = credentials['admin_username']
        
        cloudaccount.credential_data = credentials_data

        serializer = CloudAccountSerializer(cloudaccount)
        return Response(serializer.data)

    if request.method == 'PUT':
        serializer = CloudAccountSerializer(cloudaccount, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)

    if request.method == 'DELETE':
        if not cloudaccount.checkUserAccess(request.daiteap_user):
            return Response({
                'error': {
                    'message': 'You do not have access to this cloudaccount'
                }
            }, status.HTTP_400_BAD_REQUEST)

        resources = dict()
        resources['clusters'] = []
        resources['compute'] = []
        resources['buckets'] = []

        # check if account is used in existing resource
        clusters = models.Clusters.objects.filter(project__tenant_id=request.daiteap_user.tenant_id)
        for cluster in clusters:
            config = json.loads(cluster.config)
            if cloudaccount.provider in config and config[cloudaccount.provider]["account"] == cloudaccount.id:
                if cluster.type == constants.ClusterType.COMPUTE_VMS.value or cluster.type == constants.ClusterType.VMS.value:
                    resources['compute'].append(cluster.title)
                else:
                    resources['clusters'].append(cluster.title)

        buckets = models.Bucket.objects.filter(credential_id=cloudaccount.id)
        for bucket in buckets:
            resources['buckets'].append(bucket.name)

        if len(resources['buckets']) > 0 or len(resources['clusters']) > 0 or len(resources['compute']) > 0:
            return Response({
                'error': {
                    'message': 'Cloud credential has associated resources.',
                    'resources': resources
                }
            }, status.HTTP_400_BAD_REQUEST)

        environment_providers.delete_cloud_credentials(cloudaccount)
        vault_service.delete_secret(cloudaccount.credentials)
        cloudaccount.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)

@swagger_auto_schema(method='get',
        operation_description="Get buckets.",
        operation_summary="Get buckets.",
        responses={200: openapi.Response('', BucketSerializer(many=True))})
@swagger_auto_schema(method='post',
        request_body= BucketSerializer,
        responses={200: openapi.Response('', BucketSerializer)},
        operation_description="Create bucket.",
        operation_summary="Create bucket.")
@permission_classes([IsAuthenticated])
@api_view(['GET', 'POST'])
def bucket_list(request, tenant_id):
    if request.method == 'GET':
        buckets = []
        bucket_records = models.Bucket.objects.filter(project__tenant_id=tenant_id)

        for bucket in bucket_records:
            if bucket.checkUserAccess(request.daiteap_user):
                buckets.append(bucket)

        serializer = BucketSerializer(buckets, many=True)

        return Response(serializer.data)

    if request.method == 'POST':
        serializer = BucketSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(method='get',
        responses={200: openapi.Response('', BucketSerializer)},
        operation_description="Get bucket.",
        operation_summary="Get bucket.")
@swagger_auto_schema(method='put',
        request_body= BucketSerializer,
        responses={200: openapi.Response('', BucketSerializer)},
        operation_description="Update bucket.",
        operation_summary="Update bucket.")
@swagger_auto_schema(method='delete',
        operation_description="Delete bucket.",
        operation_summary="Delete bucket.")
@permission_classes([IsAuthenticated, custom_permissions.BucketAccessPermission])
@api_view(['GET', 'PUT', 'DELETE'])
def bucket_detail(request, tenant_id, bucket_id):
    try:
        bucket = models.Bucket.objects.get(id=bucket_id, project__tenant_id=tenant_id)
    except models.Bucket.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if bucket.credential.valid != True:
        return Response({
            'error': {
                'message': 'Credentials are not valid.'
            }
        }, status=400)

    if request.method == 'GET':
        storage_bucket_data = {}

        storage_bucket_data['provider'] = bucket.provider
        storage_bucket_data['credential_id'] = bucket.credential.id
        storage_bucket_data['bucket_name'] = bucket.name
        storage_bucket_data['storage_account_url'] = bucket.storage_account

        response = environment_providers.get_bucket_details(storage_bucket_data, request)
        if 'error' in response.keys():
            return JsonResponse(response, status=400)
        else:
            return JsonResponse(response, status=200)
        
    if request.method == 'PUT':
        serializer = BucketSerializer(bucket, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)
    if request.method == 'DELETE':
        storage_bucket_data = {}

        storage_bucket_data['provider'] = bucket.provider
        storage_bucket_data['credential_id'] = bucket.credential.id
        storage_bucket_data['bucket_name'] = bucket.name
        storage_bucket_data['storage_account_url'] = bucket.storage_account

        response = environment_providers.delete_storage_bucket(storage_bucket_data, request)
        if 'error' in response.keys():
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

        bucket.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.TenantAccessPermission])
def get_specific_user_info(request, tenant_id, username):
    # check if account exists
    try:
        daiteap_user = models.DaiteapUser.objects.get(tenant_id=tenant_id, user__username=username)
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('User doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'User doesn\'t exist.'
            }
        }, status.HTTP_400_BAD_REQUEST)
    
    user = {
        'first_name': daiteap_user.user.first_name,
        'last_name': daiteap_user.user.last_name,
        'email': daiteap_user.user.email,
        'username': daiteap_user.user.username
    }
    return JsonResponse(user)

@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.TenantAccessPermission])
def check_provided_credentials(request, tenant_id):
    response = environment_providers.check_provided_credentials(tenant_id)

    return JsonResponse(response)

@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.CloudAccountAccessPermission])
def check_account_regions_update_status(request, tenant_id, cloudaccount_id):
    # get regions update status
    response = {}
    account = models.CloudAccount.objects.get(id=cloudaccount_id,tenant_id=tenant_id)

    regions_update_status = account.regions_update_status
    response[account.provider] = {
        'status': regions_update_status
    }
    if regions_update_status == -1:  # failed
        response[account.provider]['error'] = account.regions_failed_msg

    return JsonResponse(response)


@api_view(['POST'])
@permission_classes([IsAuthenticated, custom_permissions.TenantAccessPermission])
def validate_credentials(request, tenant_id, cloudaccount_id = None):
    # Validate request
    if cloudaccount_id:
        payload = {}
        payload['tenant_id'] = tenant_id
        payload['account_id'] = cloudaccount_id
    else:
        payload, error = get_request_body(request)
        if error:
            return error
        payload['tenant_id'] = tenant_id

    schema = {
        "type": "object",
        "properties": {
            "account_id": {
                "type": "number",
            },
            "tenant_id": {
                "type": "string",
            },
            "credentials": {
                "type": "object",
                "properties": {}
            }
        },
    }

    schema = environment_providers.add_credentials_validation_schemas(schema, payload)

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)


    storage_enabled = models.TenantSettings.objects.get(tenant__id=payload['tenant_id']).enable_storage

    if 'account_id' in payload:
        if len(models.CloudAccount.objects.filter(id=payload['account_id'])) > 0:
            account = models.CloudAccount.objects.get(id=payload['account_id'], tenant_id=payload['tenant_id'])

            daiteap_user = models.DaiteapUser.objects.get(user=request.user,tenant_id=tenant_id)
            if not account.checkUserAccess(daiteap_user):
                return JsonResponse({
                    'error': {
                        'message': 'Access denied'
                    }
                }, status=403)

            if account.valid == None:
                return JsonResponse({
                    'error': {
                        'message': 'Account validation is not fisnished yet'
                    }
                }, status=403)

            account.valid = None
            account.save()

            try:
                task = environment_providers.validate_credentials(payload, request, storage_enabled)
            except Exception as e:
                account = models.CloudAccount.objects.filter(id=payload['account_id'])[0]
                account.valid = False
                account.save()

                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                }
                logger.error(str(e), extra=log_data)

                return JsonResponse({
                    'error': {
                        'message': str(e)
                    }
                }, status=400)

        else:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Invalid account_id parameter', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'Invalid account_id parameter'
                }
            }, status=400)

    elif 'credentials' in payload:
        try:
            task = environment_providers.validate_credentials(payload, request, storage_enabled)
        except Exception as e:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error(str(e), extra=log_data)
            return JsonResponse({
                'error': {
                    'message': str(e),
                }
            }, status=400)

    else:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid request body', extra=log_data)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })

def __update_user_cloud_credentials(request, payload):
    schema = {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "minLength": 3,
                "maxLength": 9
            },
            "account_params": {
                "type": "object"
            }
        },
        "required": ["provider", "account_params"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    try:
        environment_providers.update_cloud_credentials(payload, request)
    except Exception as e:
        logger.error(str(traceback.format_exc()) + '\n' + str(e))
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    return JsonResponse({
        'submitted': True
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.ClusterAccessPermission])
def get_installation_status(request, tenant_id, cluster_id):
    # Get install step
    try:
        cluster = models.Clusters.objects.get(
            id=cluster_id, project__tenant_id=tenant_id)
    except models.Clusters.DoesNotExist:
        try:
            cluster = models.CapiCluster.objects.get(
                id=cluster_id, project__tenant_id=tenant_id)
        except models.CapiCluster.DoesNotExist:
            cluster = models.YaookCapiCluster.objects.get(
                id=cluster_id, project__tenant_id=tenant_id)

    install_step = cluster.installstep

    response = {
        'installStep': install_step
    }

    try:
        error_msg = json.loads(cluster.error_msg)
    except:
        error_msg = {}

    if 'message' in error_msg:
        message = base64.b64decode(error_msg['message']).decode('utf-8')
        if 'Forbidden.RiskControl' in message:
            message = 'Resource alicloud_instance RunInstances Failed!!!\n'
            message += 'This operation is forbidden by Aliyun RiskControl system.\n'
            message += 'Please contact Alicloud cloud support in order to fix the problem with Aliyun RiskControl system in your account.'

            encoded_error_bytes = base64.b64encode(
                str(message).encode("utf-8"))
            response['errorMsg'] = str(encoded_error_bytes, "utf-8")
        else:
            response['errorMsg'] = error_msg['message']

        if install_step == -1:
            if ('suggested_instance_type' in error_msg and
                error_msg['suggested_instance_type'] != '' and
                'error_instance_type' in error_msg and
                error_msg['error_instance_type'] != ''):
                response['error_instance_type'] = error_msg['error_instance_type']
                response['suggested_instance_type'] = error_msg['suggested_instance_type']

    # return JSON response
    return JsonResponse(response)


@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.ClusterAccessPermission])
def get_resize_status(request, tenant_id, cluster_id):
    # Get resize status
    try:
        cluster = models.Clusters.objects.get(
            id=cluster_id, project__tenant_id=tenant_id)
    except models.Clusters.DoesNotExist:
        try:
            cluster = models.CapiCluster.objects.get(
                id=cluster_id, project__tenant_id=tenant_id)
        except models.CapiCluster.DoesNotExist:
            cluster = models.YaookCapiCluster.objects.get(
                id=cluster_id, project__tenant_id=tenant_id)

    resizestep = cluster.resizestep

    response = {
        'resizeStep': resizestep
    }

    try:
        error_msg = json.loads(cluster.error_msg)
    except:
        error_msg = {}
    if 'message' in error_msg:
        response['errorMsg'] = error_msg['message']

    # return JSON response
    return JsonResponse(response)

@api_view(['GET'])
def oauth_azure_adminconsent(request):
    print('oauth_azure_adminconsent')
    query_params = request.build_absolute_uri().split('?')[1]
    redirect_url = AZURE_CLIENT_ADMINCONSENT_URI + '?' + query_params 

    return HttpResponseRedirect(redirect_url)

@api_view(['GET'])
def oauth_azure_authorize(request):
    print('oauth_azure_authorize')
    query_params = request.build_absolute_uri().split('?')[1]

    query_params = query_params.replace('code=', 'authCode=')
    query_params = query_params.replace('&state=', '&authState=')
    query_params = query_params.replace('&session_state=', '&authSessionState=')

    redirect_url = AZURE_CLIENT_AUTHORIZE_URI + '?' + query_params 


    return HttpResponseRedirect(redirect_url)

@api_view(['GET'])
def oauth_azure_createapp(request):
    print('oauth_azure_createapp')
    query_params = request.build_absolute_uri().split('?')[1]
    query_params = query_params.replace('code=', 'authCode=')
    query_params = query_params.replace('&state=', '&authState=')
    query_params = query_params.replace('&session_state=', '&authSessionState=')

    redirect_url = AZURE_CLIENT_CREATE_APP_URI + '?' + query_params 

    return HttpResponseRedirect(redirect_url)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def oauth_azure_get_auth_url_admin_consent(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "origin": {
                "type": "string"
            }
        },
        "required": ["origin"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    redirect_uri = payload['origin'] + "/server/azureadminconsent"

    auth_url = AzureAuthClient.getAuthUrlAdminConsent(redirect_uri)

    return JsonResponse({'auth_url': auth_url})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def oauth_azure_get_auth_url_authorize(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "origin": {
                "type": "string"
            },
            "tenant": {
                "type": "string"
            }
        },
        "required": ["origin", "tenant"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    redirect_uri = payload['origin'] + "/server/azureauthorize"
    tenant = payload['tenant']

    auth_url = AzureAuthClient.getAuthUrlAuthorize(redirect_uri, tenant)

    return JsonResponse({'auth_url': auth_url})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def oauth_azure_get_auth_url_create_app(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "origin": {
                "type": "string"
            },
            "tenant": {
                "type": "string"
            },
            "subscriptionId": {
                "type": "string"
            }
        },
        "required": ["origin", "tenant", "subscriptionId"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    redirect_uri = payload['origin'] + "/server/azurecreateapp"
    tenant = payload['tenant']
    subscription_id = payload['subscriptionId']

    auth_url = AzureAuthClient.getAuthUrlCreateApp(redirect_uri, tenant, subscription_id)

    return JsonResponse({'auth_url': auth_url})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def oauth_azure_create_app(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    required_parameters = [
        'tenant',
        'subscriptionId',
        'authCode',
        'origin'
    ]

    error = check_if_body_parameters_exist(payload, required_parameters)
    if error:
        return error

    task = tasks.worker_create_azure_oauth_credentials.delay(payload, request.user.id, request.daiteap_user.id)

    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'taskId': celerytask.id
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def oauth_azure_get_subscriptions(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    required_parameters = [
        'tenant',
        'authCode',
        'origin'
    ]

    error = check_if_body_parameters_exist(payload, required_parameters)
    if error:
        return error

    try:
        azure_auth_client = AzureAuthClient(authorize_tenant=payload['tenant'])

        subscriptions_data = azure_auth_client.getSubscriptions(
            auth_code=payload['authCode'], origin=payload['origin'])
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return HttpResponse(str(e), status=500)

    response_subscriptions = {'subscriptions': []}
    for subscription in subscriptions_data:
        response_subscription = {}
        response_subscription['subscriptionId'] = subscription['subscriptionId']
        response_subscription['displayName'] = subscription['displayName']
        response_subscriptions['subscriptions'].append(response_subscription)

    return JsonResponse(response_subscriptions)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def oauth_google_get_auth_url_projects(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "origin": {
                "type": "string"
            }
        },
        "required": ["origin"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    google_auth_client = GoogleAuthClient()

    try:
        auth_url = {'auth_url': google_auth_client.get_auth_url_projects(payload['origin'])}
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return HttpResponse(str(e), status=500)

    return JsonResponse(auth_url)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def oauth_google_create_service_account(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "projectId": {
                "type": "string"
            }
        },
        "required": ["projectId"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    google_auth_client = GoogleAuthClient()
    try:
        sa_key = google_auth_client.create_service_account(
            payload['projectId'],
            request.user
        )
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return HttpResponse(str(e), status=500)

    update_user_cloud_credentials_req_body = {
        "provider": "google",
        "account_params": {
            "old_label": "google-oauth-" + payload['projectId'][0:17],
            "label": "google-oauth-" + payload['projectId'][0:17],
            "google_key": sa_key
        }
    }

    response = __update_user_cloud_credentials(
        request,
        update_user_cloud_credentials_req_body
    )

    return response

@api_view(['GET'])
def oauth_google(request):
    # get current uri
    query_params = request.build_absolute_uri().split('?')[1]
    query_params = query_params.replace('code=', 'authCode=')

    redirect_url = "/#/app/platform/cloudprofile/oauth/google/projects?" + query_params 

    return HttpResponseRedirect(redirect_url)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def oauth_google_get_projects(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "authCode": {
                "type": "string"
            },
            "origin": {
                "type": "string"
            }
        },
        "required": ["authCode", "origin"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    google_auth_client = GoogleAuthClient()

    projects = {'projects': google_auth_client.get_projects(payload['authCode'], request.user, payload['origin'])}


    return JsonResponse(projects)


@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.TenantAccessPermission])
def get_provider_accounts(request, tenant_id, provider):
    payload = {}
    payload['provider'] = provider

    schema = {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "minLength": 3,
                "maxLength": 9
            }
        },
        "required": ["provider"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    if not environment_providers.check_if_at_least_one_provider_is_selected(payload['provider']):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('No provider is selected.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'No provider is selected.'
            }
        }, status=400)

    accounts = environment_providers.get_provider_accounts(payload, request, tenant_id)

    response = {
        'accounts': accounts
    }

    # return JSON response
    return JsonResponse(response)


@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.CloudAccountAccessPermission])
def get_valid_regions(request, tenant_id, cloudaccount_id):
    account = models.CloudAccount.objects.get(id=cloudaccount_id, tenant_id=tenant_id)

    payload = {}
    payload['provider'] = account.provider
    payload['accountId'] = cloudaccount_id

    schema = {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "minLength": 3,
                "maxLength": 9
            },
            "accountId": {
                "type": "number",
            },
        },
        "required": ["provider", "accountId"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # Get provider's regions

    if not environment_providers.check_if_at_least_one_provider_is_selected(payload['provider']):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('No provider is selected.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'No provider is selected.'
            }
        }, status=400)

    try:
        regions = environment_providers.get_valid_regions(payload, request, tenant_id)
    except Exception as e:
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    response = {
        'regions': regions
    }

    # return JSON response
    return JsonResponse(response)


@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.CloudAccountAccessPermission])
def get_valid_zones(request, tenant_id, cloudaccount_id, region):
    account = models.CloudAccount.objects.get(id=cloudaccount_id, tenant_id=tenant_id)

    payload = {}
    payload['provider'] = account.provider
    payload['accountId'] = cloudaccount_id
    payload['region'] = region

    schema = {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "minLength": 3,
                "maxLength": 9
            },
            "accountId": {
                "type": "number",
            },
            "region": {
                "type": "string",
                "minLength": 3,
                "maxLength": 20
            }
        },
        "required": ["provider", "accountId", "region"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # Get region's zones
    if not environment_providers.check_if_at_least_one_provider_is_selected(payload['provider']):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid provider parameter.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid provider parameter.'
            }
        }, status=400)

    try:
        zones = environment_providers.get_valid_zones(payload, request, tenant_id)
    except Exception as e:
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    response = {
        'zones': sorted(zones)
    }

    # return JSON response
    return JsonResponse(response)


@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.CloudAccountAccessPermission])
def get_valid_instances(request, tenant_id, cloudaccount_id, region, zone = None):
    account = models.CloudAccount.objects.get(id=cloudaccount_id, tenant_id=tenant_id)

    payload = {}
    payload['provider'] = account.provider
    payload['accountId'] = cloudaccount_id
    payload['region'] = region
    if zone:
        payload['zone'] = zone

    schema = {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "minLength": 3,
                "maxLength": 9
            },
            "accountId": {
                "type": "number",
            },
            "region": {
                "type": "string",
                "minLength": 3,
                "maxLength": 20
            },
            "zone": {
                "type": "string",
                "minLength": 3,
                "maxLength": 25
            }
        },
        "required": ["provider", "accountId", "region"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # Get zone's instance types
    if not environment_providers.check_if_at_least_one_provider_is_selected(payload['provider']):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid provider parameter.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid provider parameter.'
            }
        }, status=400)

    try:
        instances = environment_providers.get_valid_instances(payload, request, tenant_id)
    except Exception as e:
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    response = {
        'instances': instances
    }

    # return JSON response
    return JsonResponse(response)


@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.CloudAccountAccessPermission])
@cache_page(60 * 15)
def get_valid_operating_systems(request, tenant_id, cloudaccount_id, region, environment_type):
    account = models.CloudAccount.objects.get(id=cloudaccount_id, tenant_id=tenant_id)

    payload = {
        'accountId': cloudaccount_id,
        'provider': account.provider,
        'region': region,
        'environmentType': environment_type,
        'username': request.user
    }

    schema = {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "minLength": 3,
                "maxLength": 9
            },
            "accountLabel": {
                "type": "string",
                "minLength": 3,
                "maxLength": 100
            },
            "region": {
                "type": "string",
                "minLength": 3,
                "maxLength": 20
            },
            "environmentType": {
                "type": "number",
            }
        },
        "required": ["provider", "accountId", "region", "environmentType"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': payload,
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # Get zone's instance types
    if not environment_providers.check_if_provider_is_supported(payload['provider']):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': payload,
        }
        logger.error('Invalid provider parameter.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid provider parameter.'
            }
        }, status=400)

    operating_systems = []

    try:
        operating_systems = environment_providers.get_valid_operating_systems(payload, payload['environmentType'], request.user.id)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': payload,
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Account does not exist.'
            }
        }, status=500)

    response = {
        'operatingSystems': sorted(operating_systems, key=lambda i: i['os'])
    }

    # return JSON response
    return JsonResponse(response)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_service_list(request):
    service_list = []

    # Get services
    services = models.Service.objects.all()

    for service in services.filter(visible=True):
        categories = []
        for category in service.categories.all():
            categories.append(category.name)

        service_list.append(
            {
                "name": service.name,
                "logo_url": service.logo_url,
                "description": service.description,
                "categories": categories,
                "implemented": service.implemented
            }
        )

    response = {
        'serviceList': service_list
    }

    # return JSON response
    return JsonResponse(response)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_service_values(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "service": {
                "type": "string",
                "minLength": 5,
                "maxLength": 30
            }
        },
        "required": ["service"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # Get service
    try:
        service = models.Service.objects.filter(name=payload['service'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter service.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter service.'
            }
        }, status=500)

    service_options = json.loads(service.options)

    if service_options['yamlConfig'] == False:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Service does not support yamlConfig.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Service does not support yamlConfig.'
            }
        }, status=500)

    response = {
        'values': service.values_file
    }

    # return JSON response
    return JsonResponse(response)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_service_connection_info(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "minLength": 3,
                "maxLength": 30
            },
            "namespace": {
                "type": "string",
                "minLength": 3,
                "maxLength": 30
            },
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["name", "clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user
    is_capi = False
    is_yaookcapi = False

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(
            id=payload['clusterID'], project__tenant__daiteapuser__user=username)
        if len(cluster) == 0:
            cluster = models.CapiCluster.objects.filter(
                id=payload['clusterID'], project__tenant__daiteapuser__user=username)
            if len(cluster) == 0:
                cluster = models.YaookCapiCluster.objects.filter(
                    id=payload['clusterID'], project__tenant__daiteapuser__user=username)[0]
                is_yaookcapi = True
            else:
                cluster = cluster[0]
                is_capi = True
        else:
            cluster = cluster[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    # Get service
    try:
        if 'namespace' in payload:
            if is_capi:
                service = models.ClusterService.objects.filter(
                    capi_cluster_id=payload['clusterID'],
                    name=payload['name'],
                    namespace=payload['namespace'])[0]
            elif is_yaookcapi:
                service = models.ClusterService.objects.filter(
                    yaookcapi_cluster_id=payload['clusterID'],
                    name=payload['name'],
                    namespace=payload['namespace'])[0]
            else:
                service = models.ClusterService.objects.filter(
                    cluster_id=payload['clusterID'],
                    name=payload['name'],
                    namespace=payload['namespace'])[0]
        else:
            if is_capi:
                service = models.ClusterService.objects.filter(
                    capi_cluster_id=payload['clusterID'],
                    name=payload['name'])[0]
            elif is_yaookcapi:
                service = models.ClusterService.objects.filter(
                    yaookcapi_cluster_id=payload['clusterID'],
                    name=payload['name'])[0]
            else:
                service = models.ClusterService.objects.filter(
                    cluster_id=payload['clusterID'],
                    name=payload['name'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Service does not exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Service does not exist.'
            }
        }, status=500)

    response = {
        'connection_info': json.loads(service.connection_info)
    }

    # return JSON response
    return JsonResponse(response)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_cluster_service_default_name(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "service": {
                "type": "string",
                "minLength": 5,
                "maxLength": 30
            },
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["service", "clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user
    is_capi = False
    is_yaookcapi = False

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(
            id=payload['clusterID'], project__tenant__daiteapuser__user=username)
        if len(cluster) == 0:
            cluster = models.CapiCluster.objects.filter(
                id=payload['clusterID'], project__tenant__daiteapuser__user=username)
            if len(cluster) == 0:
                cluster = models.YaookCapiCluster.objects.filter(
                    id=payload['clusterID'], project__tenant__daiteapuser__user=username)[0]
                is_yaookcapi = True
            else:
                cluster = cluster[0]
                is_capi = True
        else:
            cluster = cluster[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID.'
            }
        }, status=500)

    # Get service
    try:
        service = models.Service.objects.filter(
            name=payload['service'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter service.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter service.'
            }
        }, status=500)

    # Get cluster's services
    if is_capi:
        cluster_services = models.ClusterService.objects.filter(
            capi_cluster=cluster).filter(service=service).count()
    elif is_yaookcapi:
        cluster_services = models.ClusterService.objects.filter(
            yaookcapi_cluster=cluster).filter(service=service).count()
    else:
        cluster_services = models.ClusterService.objects.filter(
            cluster=cluster).filter(service=service).count()

    defaultName = payload['service'] + '-' + str(cluster_services)

    response = {
        'defaultName': defaultName
    }

    # return JSON response
    return JsonResponse(response)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_cluster_list(request):

    # Get user's clusters
    try:
        daiteapuser = request.daiteap_user
        if daiteapuser.role == "Admin":
            user_projects = models.Project.objects.filter(tenant=daiteapuser.tenant).all()

        else:
            user_projects = daiteapuser.projects.all()

        cluster_list_db = list(models.Clusters.objects.filter(project__in=user_projects).values('id',
                                                                                    'title',
                                                                                    'project',
                                                                                    'description',
                                                                                    'contact',
                                                                                    'installstep',
                                                                                    'canceled',
                                                                                    'resizestep',
                                                                                    'type',
                                                                                    'status',
                                                                                    'error_msg_delete',
                                                                                    'error_msg',
                                                                                    'providers',
                                                                                    'created_at'
                                                                                    ))

        capi_cluster_list_db = list(models.CapiCluster.objects.filter(project__in=user_projects).values('id',
                                                                                    'title',
                                                                                    'project',
                                                                                    'description',
                                                                                    'contact',
                                                                                    'installstep',
                                                                                    'resizestep',
                                                                                    'providers',
                                                                                    'created_at',
                                                                                    'type'
                                                                                    ))


        yaookcapi_cluster_list_db = list(models.YaookCapiCluster.objects.filter(project__in=user_projects).values('id',
                                                                                    'title',
                                                                                    'project',
                                                                                    'description',
                                                                                    'contact',
                                                                                    'installstep',
                                                                                    'resizestep',
                                                                                    'providers',
                                                                                    'created_at',
                                                                                    'type'
                                                                                    ))

    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Internal Server Error: ' + str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Internal Server Error.'
            }
        }, status=500)

    cluster_list = []

    for cluster in cluster_list_db:
        cluster_users = len(models.ClusterUser.objects.filter(cluster=cluster['id']))
        cluster_services = len(models.ClusterService.objects.filter(cluster=cluster['id']))
        cluster_machines = len(models.Machine.objects.filter(cluster=cluster['id']))

        project_name = models.Project.objects.filter(id=cluster['project'])[0].name

        cluster_list.append({'id': cluster['id'],
                             'name': cluster['title'],
                             'project_name': project_name,
                             'project_id': cluster['project'],
                             'description': cluster['description'],
                             'canceled': cluster['canceled'],
                             'contact': cluster['contact'],
                             'installstep': cluster['installstep'],
                             'resizestep': cluster['resizestep'],
                             'type': cluster['type'],
                             'status': cluster['status'],
                             'error_msg_delete': cluster['error_msg_delete'],
                             'error_msg': cluster['error_msg'],
                             'providers': cluster['providers'],
                             'created_at': cluster['created_at'],
                             'machines_count': cluster_machines,
                             'users_count': cluster_users,
                             'services_count': cluster_services
        })

    for capi_cluster in capi_cluster_list_db:
        cluster_services = len(models.ClusterService.objects.filter(capi_cluster=capi_cluster['id']))

        project_name = models.Project.objects.filter(id=capi_cluster['project'])[0].name

        cluster_list.append({'id': capi_cluster['id'],
                             'name': capi_cluster['title'],
                             'project_name': project_name,
                             'project_id': capi_cluster['project'],
                             'description': capi_cluster['description'],
                             'contact': capi_cluster['contact'],
                             'installstep': capi_cluster['installstep'],
                             'resizestep': capi_cluster['resizestep'],
                             'type': capi_cluster['type'],
                             'status': 0,
                             'error_msg_delete': "",
                             'providers': capi_cluster['providers'],
                             'created_at': capi_cluster['created_at'],
                             'machines_count': [],
                             'users_count': [],
                             'services_count': cluster_services
        })

    for yaookcapi_cluster in yaookcapi_cluster_list_db:
        cluster_services = len(models.ClusterService.objects.filter(yaookcapi_cluster=yaookcapi_cluster['id']))

        project_name = models.Project.objects.filter(id=yaookcapi_cluster['project'])[0].name

        cluster_list.append({'id': yaookcapi_cluster['id'],
                             'name': yaookcapi_cluster['title'],
                             'project_name': project_name,
                             'project_id': yaookcapi_cluster['project'],
                             'description': yaookcapi_cluster['description'],
                             'contact': yaookcapi_cluster['contact'],
                             'installstep': yaookcapi_cluster['installstep'],
                             'resizestep': yaookcapi_cluster['resizestep'],
                             'type': yaookcapi_cluster['type'],
                             'status': 0,
                             'error_msg_delete': "",
                             'providers': yaookcapi_cluster['providers'],
                             'created_at': yaookcapi_cluster['created_at'],
                             'machines_count': [],
                             'users_count': [],
                             'services_count': cluster_services
        })

    # return JSON response
    return JsonResponse(cluster_list, safe=False)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def is_cluster_name_free(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterName": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1024
            }
        },
        "required": ["clusterName"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # check if name is occupied by other environment
    env_with_same_name = models.Clusters.objects.filter(project__tenant_id=request.daiteap_user.tenant_id, title=payload['clusterName'].strip()).count()
    if env_with_same_name != 0:
        return JsonResponse({
            'free': False
        })

    env_with_same_name = models.CapiCluster.objects.filter(project__tenant_id=request.daiteap_user.tenant_id, title=payload['clusterName'].strip()).count()
    if env_with_same_name != 0:
        return JsonResponse({
            'free': False
        })

    env_with_same_name = models.YaookCapiCluster.objects.filter(project__tenant_id=request.daiteap_user.tenant_id, title=payload['clusterName'].strip()).count()
    if env_with_same_name != 0:
        return JsonResponse({
            'free': False
        })

    return JsonResponse({
        'free': True
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def is_compute_name_free(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterName": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1024
            }
        },
        "required": ["clusterName"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # check if name is occupied by other environment
    env_with_same_name = models.Clusters.objects.filter(type=constants.ClusterType.COMPUTE_VMS.value, project__tenant_id=request.daiteap_user.tenant_id, title=payload['clusterName'].strip()).count()
    if env_with_same_name != 0:
        return JsonResponse({
            'free': False
        })

    return JsonResponse({
        'free': True
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def is_dlcmv2_name_free(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterName": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1024
            }
        },
        "required": ["clusterName"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # check if name is occupied by other environment
    env_with_same_name = models.Clusters.objects.filter(type=constants.ClusterType.DLCM_V2.value, project__tenant_id=request.daiteap_user.tenant_id, title=payload['clusterName'].strip()).count()
    if env_with_same_name != 0:
        return JsonResponse({
            'free': False
        })

    return JsonResponse({
        'free': True
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def is_project_name_free(request, tenant_id, name):
    if len(name) < 1 or len(name) > 1024:
        return JsonResponse({
            'free': False
        })

    # check if name is occupied by other environment
    projects_for_tenant = models.Project.objects.filter(tenant_id=tenant_id, name=name.strip()).count()
    if projects_for_tenant != 0:
        return JsonResponse({
            'free': False
        })

    return JsonResponse({
        'free': True
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_service_options(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "service": {
                "type": "string",
                "minLength": 5,
                "maxLength": 30
            }
        },
        "required": ["service"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # Get service
    try:
        service = models.Service.objects.filter(
            name=payload['service'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter service.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter service.'
            }
        }, status=500)

    response = {
        'options': json.loads(service.options)
    }

    # return JSON response
    return JsonResponse(response)


@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.ClusterAccessPermission])
def get_cluster_details(request, tenant_id, cluster_id):
    is_capi = False
    is_yaookcapi = False

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.get(
            id=cluster_id, project__tenant_id=tenant_id)
    except models.Clusters.DoesNotExist:
        try:
            cluster = models.CapiCluster.objects.get(
                id=cluster_id, project__tenant_id=tenant_id)
            is_capi = True
        except models.CapiCluster.DoesNotExist:
            try:
                cluster = models.YaookCapiCluster.objects.get(
                    id=cluster_id, project__tenant_id=tenant_id)
                is_yaookcapi = True
            except models.YaookCapiCluster.DoesNotExist:
                return Response(status=status.HTTP_404_NOT_FOUND)

    if is_capi:
        config = json.loads(cluster.capi_config)
    elif is_yaookcapi:
        config = json.loads(cluster.yaookcapi_config)
    else:
        config = json.loads(cluster.config)

    # Check if cluster has LB integration
    has_LB_integration = False
    if 'load_balancer_integration' in config:
        has_LB_integration = True

    # Get cluster's machines
    if is_capi:
        providers = {provider.lower() + 'Selected': True for provider in environment_providers.get_selected_providers(config)}
        providers.update(config)
        cluster_machines = []
    elif is_yaookcapi:
        providers = {provider.lower() + 'Selected': True for provider in environment_providers.get_selected_providers(config)}
        providers.update(config)
        cluster_machines = []

        for provider in environment_providers.supported_providers:
            if provider in config:
                provider_config = environment_providers.get_user_friendly_params(config[provider], False)

                account = models.CloudAccount.objects.get(id=config[provider.lower()]['account'])
                regions = json.loads(account.regions)

                for node in provider_config['workerNodes']:
                    node_instance_type = ''
                    if 'instanceTypeName' in node:
                        node_instance_type = node['instanceTypeName']
                    else:
                        node_instance_type = node['instanceType']

                    cpu = ''
                    ram = ''
                    storage = ''

                    for region in regions:
                        if region['name'] == provider_config['region']:
                            for zone in region['zones']:
                                for instance in zone['instances']:
                                    if instance['name'] == node_instance_type:
                                        cpu = instance['cpu']
                                        ram = instance['ram']
                                        storage = instance['storage']
                                        break
                                if cpu != '' and ram != '' and storage != '':
                                    break
                        if cpu != '' and ram != '' and storage != '':
                            break

                    cluster_machines.append({
                        'type': node_instance_type,
                        'provider': provider,
                        'region': provider_config['region'],
                        'cpu': cpu,
                        'ram': ram,
                        'hdd': int(storage),
                    })

                node = provider_config['controlPlane']

                node_instance_type = ''
                if 'instanceTypeName' in node:
                    node_instance_type = node['instanceTypeName']
                else:
                    node_instance_type = node['instanceType']

                cpu = ''
                ram = ''
                storage = ''

                for region in regions:
                    if region['name'] == provider_config['region']:
                        for zone in region['zones']:
                            for instance in zone['instances']:
                                if instance['name'] == node_instance_type:
                                    cpu = instance['cpu']
                                    ram = instance['ram']
                                    storage = instance['storage']
                                    break
                            if cpu != '' and ram != '' and storage != '':
                                break
                    if cpu != '' and ram != '' and storage != '':
                        break

                cluster_machines.append({
                    'type': node_instance_type,
                    'provider': provider,
                    'region': provider_config['region'],
                    'kube_master': True,
                    'cpu': cpu,
                    'ram': ram,
                    'hdd': int(storage),
                })
    else:
        if cluster.type in [constants.ClusterType.VMS.value, constants.ClusterType.COMPUTE_VMS.value] and (-3 <= cluster.installstep < 0 or 0 < cluster.installstep <= 3 or cluster.installstep == -100 or cluster.installstep == 100):
            cluster_machines = []

            if cluster.installstep < 0 and cluster.installstep >= -3:
                machine_status = -4
            elif cluster.installstep > 0 and cluster.installstep <= 3:
                machine_status = 4
            elif cluster.installstep == -100:
                machine_status = -100
            elif cluster.installstep == 100:
                machine_status = 100

            config = json.loads(cluster.config)

            node_counter = 1
            domain = 'daiteap.internal'
            node_prefix = cluster_id.replace('-', '')[:10]

            for provider in environment_providers.supported_providers:
                if provider in config:
                    provider_config = environment_providers.get_user_friendly_params(config[provider], False)
                    for node in provider_config['nodes']:
                        node_operating_system = ''
                        if 'operatingSystemName' in node:
                            node_operating_system = node['operatingSystemName']
                        else:
                            node_operating_system = node['operatingSystem']

                        node_instance_type = ''
                        if 'instanceTypeName' in node:
                            node_instance_type = node['instanceTypeName']
                        else:
                            node_instance_type = node['instanceType']

                        cluster_machines.append({
                            'name': node_prefix + '-node-' + f"{node_counter:02d}" + '.' + provider + '.' + domain,
                            'type': node_instance_type,
                            'provider': provider,
                            'region': provider_config['region'],
                            'zone': node['zone'],
                            'operating_system': node_operating_system,
                            'status': machine_status
                        })
                        node_counter += 1
            # Get regions and zones
            cluster_machines = list(cluster_machines)
            providers = {}
        else:
            providers, cluster_machines = environment_providers.get_cluster_machines(cluster, request, {'cluster_id': cluster_id}, config)

    serviceList = []
    cluster_users = []

    if is_capi:
         # Get cluster's service
        serviceList = models.ClusterService.objects.filter(capi_cluster=cluster).order_by('name').values(
            'name',
            'service__name',
            'namespace',
            'providers',
            'connection_info',
            'status',
            'service_type')
    elif is_yaookcapi:
         # Get cluster's service
        serviceList = models.ClusterService.objects.filter(yaookcapi_cluster=cluster).order_by('name').values(
            'name',
            'service__name',
            'namespace',
            'providers',
            'connection_info',
            'status',
            'service_type')
    else:
        # Get cluster's service
        serviceList = models.ClusterService.objects.filter(cluster=cluster).order_by('name').values(
            'name',
            'service__name',
            'service__accessible_from_browser',
            'namespace',
            'providers',
            'connection_info',
            'status',
            'service_type')

        # Get cluster's users
        cluster_users = models.ClusterUser.objects.filter(cluster=cluster).order_by('username').values(
            'username',
            'first_name',
            'last_name',
            'public_ssh_key',
            'type',
            'status')

    if is_capi or is_yaookcapi or not cluster.resources:
        resources = {}
    else:
        resources = json.loads(cluster.resources)

    load_balancer_integration = ''
    if 'load_balancer_integration' in config:
        load_balancer_integration = config['load_balancer_integration']

    if is_capi:
        status = 0
    elif is_yaookcapi:
        status = 0
    else:
        status = cluster.status

    response = {
        'name': cluster.name,
        'title': cluster.title,
        'description': cluster.description,
        'project_name': cluster.project.name,
        'status': status,
        'resizestep': cluster.resizestep,
        'installstep': cluster.installstep,
        'clusterType': cluster.type,
        'loadBalancerIntegration': load_balancer_integration,
        'providers': providers,
        'resources': resources,
        'usersList': list(cluster_users),
        'machinesList': list(cluster_machines),
        'hasLoadBalancerIntegration': has_LB_integration,
        'serviceList': list(serviceList)
    }

    if not is_capi and not is_yaookcapi:
        additional_services = {
            'grafana_admin_password': cluster.grafana_admin_password,
            'grafana_address': cluster.grafana_address,
            'es_admin_password': cluster.es_admin_password,
            'kibana_address': cluster.kibana_address
        }
        response.update(additional_services)

        if cluster.terraform_graph_index:
            response['terraform_graph_index_path'] = cluster.terraform_graph_index

        if cluster.type == constants.ClusterType.DLCM.value or cluster.type == constants.ClusterType.K3S.value:
            response['kubeUpgradeStatus'] = cluster.kube_upgrade_status

        if cluster.kube_upgrade_status == -1:
            try:
                error_msg = json.loads(cluster.error_msg)
            except:
                error_msg = {}
            if 'message' in error_msg:
                response['errorMsg'] = error_msg['message']

    if 'kubernetesConfiguration' in config and cluster.type in [
        constants.ClusterType.DLCM.value,
        constants.ClusterType.K3S.value,
        constants.ClusterType.CAPI.value,
        constants.ClusterType.DLCM_V2.value
        ]:
        response['kubernetesConfiguration'] = {}
        response['kubernetesConfiguration']['version'] = config['kubernetesConfiguration']['version']
        if not is_capi and not is_yaookcapi:
            response['kubernetesConfiguration']['networkPlugin'] = config['kubernetesConfiguration']['networkPlugin']
            response['kubernetesConfiguration']['podsSubnet'] = config['kubernetesConfiguration']['podsSubnet']
            response['kubernetesConfiguration']['serviceAddresses'] = config['kubernetesConfiguration']['serviceAddresses']

    # return JSON response
    return JsonResponse(response)

@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.ClusterAccessPermission])
def get_cluster_storage(request, tenant_id, cluster_id):
    # submit task
    task = tasks.get_longhorn_storage_info.delay(cluster_id=cluster_id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.ClusterAccessPermission])
def get_cluster_config(request, tenant_id, cluster_id):
    username = request.user
    is_capi = False
    is_yaookcapi = False

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.get(
            id=cluster_id, project__tenant_id=tenant_id)
    except models.Clusters.DoesNotExist:
        try:
            cluster = models.CapiCluster.objects.get(
                id=cluster_id, project__tenant_id=tenant_id)
            is_capi = True
        except models.CapiCluster.DoesNotExist:
            cluster = models.YaookCapiCluster.objects.get(
                id=cluster_id, project__tenant_id=tenant_id)
            is_yaookcapi = True

    if is_capi:
        response = {
            'config': json.loads(cluster.capi_config),
            'projectId': cluster.project.id,
            'name': cluster.title,
            'description': cluster.description,
        }
    elif is_yaookcapi:
        response = {
            'config': json.loads(cluster.yaookcapi_config),
            'projectId': cluster.project.id,
            'name': cluster.title,
            'description': cluster.description,
        }
    else:
        response = {
            'config': json.loads(cluster.config),
            'projectId': cluster.project.id,
            'name': cluster.title,
            'description': cluster.description,
        }

        if cluster.gateway_cloud:
            response['gatewayCloud'] = cluster.gateway_cloud
        else:
            response['gatewayCloud'] = None

    # return JSON response
    return JsonResponse(response)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_kubernetes_available_upgrade_versions(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid clusterID parameter.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=username, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    config = json.loads(cluster.config)

    if cluster.type not in [constants.ClusterType.DLCM.value, constants.ClusterType.K3S.value]:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid cluster type', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid cluster type',
            }
        }, status=400)

    upgrade_versions = get_kubernetes_upgrade_versions(config)

    response = {}

    response['upgradeVersions'] = upgrade_versions
    # return JSON response
    return JsonResponse(response)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_k3s_available_upgrade_versions(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid clusterID parameter.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=username, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    config = json.loads(cluster.config)

    if cluster.type not in [constants.ClusterType.DLCM.value, constants.ClusterType.K3S.value]:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid cluster type', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid cluster type',
            }
        }, status=400)

    upgrade_versions = get_k3s_upgrade_versions(config)

    response = {}

    response['upgradeVersions'] = upgrade_versions
    # return JSON response
    return JsonResponse(response)

@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.ClusterAccessPermission])
def get_cluster_kubeconfig(request, tenant_id, cluster_id):
    try:
        cluster = models.Clusters.objects.get(
            id=cluster_id, project__tenant_id=tenant_id)
    except models.Clusters.DoesNotExist:
        try:
            cluster = models.CapiCluster.objects.get(
                id=cluster_id, project__tenant_id=tenant_id)
        except models.CapiCluster.DoesNotExist:
            cluster = models.YaookCapiCluster.objects.get(
                id=cluster_id, project__tenant_id=tenant_id)

    config = cluster.kubeconfig

    return JsonResponse({
        'kubeconfig': config
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.ClusterAccessPermission])
def get_wireguard_config(request, tenant_id, cluster_id):
    cluster = models.YaookCapiCluster.objects.get(id=cluster_id, project__tenant_id=tenant_id)

    wireguard_user_configs = json.loads(cluster.wireguard_user_configs)

    wireguard_user_config = ''

    for wireguard_user_config_item in wireguard_user_configs:
        if str(request.user.id) in wireguard_user_config_item:
            wireguard_user_config = wireguard_user_config_item[str(request.user.id)]

    # return JSON response
    return JsonResponse({
        'wireguardconfig': wireguard_user_config
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.ClusterAccessPermission])
def get_user_kubeconfig(request, tenant_id, cluster_id, username):
    # check if cluster user exists
    try:
        user = models.ClusterUser.objects.get(
            cluster_id=cluster_id, username=username)
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': cluster_id,
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster user doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster user doesn\'t exist.'
            }
        }, status=500)

    config = user.kubeconfig

    # return JSON response
    return JsonResponse({
        'kubeconfig': config
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def rename_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            },
            "clusterName": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1024
            }
        },
        "required": ["clusterID", "clusterName"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # change cluster install step if cluster exists
    try:
        cluster = models.Clusters.objects.filter(
            id=payload['clusterID'], project__tenant__daiteapuser__user=username)[0]
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster doesn\'t exist.'
            }
        }, status=400)

    if cluster.installstep != 0:
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not allow renaming'
            }
        }, status=400)

    cluster.title = payload['clusterName']
    cluster.save()

    return JsonResponse({
        'submitted': True
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # change cluster install step if cluster exists
    try:
        cluster = models.Clusters.objects.filter(id=payload['clusterID'])[0]

        if not cluster.checkUserAccess(request.daiteap_user):
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter clusterID'
                }
            }, status=403)
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster doesn\'t exist.'
            }
        }, status=400)

    if not cluster.installstep <= 0:
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not allow deletion'
            }
        }, status=400)

    cluster.installstep = 100
    cluster.save()

    cluster_machines = models.Machine.objects.filter(cluster_id=payload['clusterID'])

    if cluster.type == constants.ClusterType.COMPUTE_VMS.value:
        for machine in cluster_machines:
            machine.status = 100
            machine.save()

    # submit deletion
    task = tasks.worker_delete_cluster.delay(payload['clusterID'], request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def remove_compute_node(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "nodeID": {
                "type": "number",
            },
        },
        "required": ["nodeID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # Check if node exists
    try:
        node = models.Machine.objects.filter(id=payload['nodeID'])[0]

        if not node.checkUserAccess(request.daiteap_user):
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter nodeID'
                }
            }, status=400)

        cluster = node.cluster
    except models.Clusters.DoesNotExist:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster does not exist', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster does not exist',
            }
        }, status=400)

    cluster_config = json.loads(cluster.config)

    # check if user has access to the cloud accounts which he attempts to use
    for key in cluster_config:
        if key in ["aws", "google", "openstack", "azure", "onpremise", "iotarm"]:
            id = cluster_config.get(key).get("account")
            account = models.CloudAccount.objects.get(id=id)
            if not account.checkUserAccess(request.daiteap_user):
                return JsonResponse({
                    'error': {
                        'message': 'Project access denied.',
                    }
                }, status=403)

    cluster_nodes = models.Machine.objects.filter(cluster_id=cluster.id)

    if len(cluster_nodes) == 1:
        return JsonResponse({
            'error': {
                'message': 'Cannot remove last node.',
            }
        }, status=400)

    if cluster.resizestep != 0:
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not allow removing nodes.',
            }
        }, status=400)

    if node.status != 0:
        return JsonResponse({
            'error': {
                'message': 'Node status does not allow deletion'
            }
        }, status=400)

    node.status = 100
    node.save()

    cluster.resizestep=1
    cluster.save()

    tag_values = dict()
    tag_values['username'] = request.user.username
    tag_values['email'] = request.user.email
    tag_values['url'] = request.headers['Origin']
    tag_values['tenant_name'] = request.daiteap_user.tenant.name

    # submit kubernetes creation
    task = tasks.worker_remove_compute_node.delay(payload['nodeID'], cluster.id, request.user.id, tag_values)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id, cluster=cluster)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'ID': cluster.id,
        'taskId': celerytask.id
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def stop_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # change cluster status if cluster exists
    try:
        cluster = models.Clusters.objects.filter(
            id=payload['clusterID'], project__tenant__daiteapuser__user=username)[0]
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster doesn\'t exist.'
            }
        }, status=400)

    if cluster.installstep != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is not ready.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is not ready.'
            }
        }, status=400)

    if cluster.status in [10,2,3]:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is stopped/stopping.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is stopped/stopping.'
            }
        }, status=400)

    cluster.status = 2
    cluster.save()

    # submit stop
    task = tasks.worker_stop_cluster.delay(payload['clusterID'], request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def start_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # change cluster status if cluster exists
    try:
        cluster = models.Clusters.objects.filter(
            id=payload['clusterID'], project__tenant__daiteapuser__user=username)[0]
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster doesn\'t exist.'
            }
        }, status=400)
    
    if cluster.installstep != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is not ready.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is not ready.'
            }
        }, status=400)

    if cluster.status in [0,1,3]:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is running/starting.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is running/starting.'
            }
        }, status=400)

    cluster.status = 1
    cluster.save()

    # submit start
    task = tasks.worker_start_cluster.delay(payload['clusterID'], request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def restart_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # change cluster status if cluster exists
    try:
        cluster = models.Clusters.objects.filter(
            id=payload['clusterID'], project__tenant__daiteapuser__user=username)[0]
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster doesn\'t exist.'
            }
        }, status=400)
    
    if cluster.installstep != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is not ready.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is not ready.'
            }
        }, status=400)

    if cluster.status != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is not running.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is not running.'
            }
        }, status=400)

    cluster.status = 3
    cluster.save()

    # submit restart
    task = tasks.worker_restart_cluster.delay(payload['clusterID'], request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def stop_machine(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            },
            "machineName": {
                "type": "string",
                "minLength": 38,
                "maxLength": 150
            },
            "machineProvider": {
                "type": "string",
                "minLength": 3,
                "maxLength": 9
            },
        },
        "required": ["clusterID", "machineName", "machineProvider"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # check if cluster exists
    try:
        cluster = models.Clusters.objects.filter(
            id=payload['clusterID'], project__tenant__daiteapuser__user=username)[0]
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster doesn\'t exist.'
            }
        }, status=400)

    if cluster.installstep != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is not ready.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is not ready.'
            }
        }, status=400)

    # check if machine exists
    try:
        machine = models.Machine.objects.filter(
            cluster_id=payload['clusterID'], name=payload['machineName'], provider=payload['machineProvider'])[0]
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Machine doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Machine doesn\'t exist.'
            }
        }, status=400)

    if machine.status in [10,2,3]:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Machine is stopped/stopping.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Machine is stopped/stopping.'
            }
        }, status=400)

    machine.status = 2
    machine.save()

    # submit stop
    task = tasks.worker_stop_machine.delay(payload['clusterID'], payload['machineName'], payload['machineProvider'], request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def start_machine(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            },
            "machineName": {
                "type": "string",
                "minLength": 38,
                "maxLength": 150
            },
            "machineProvider": {
                "type": "string",
                "minLength": 3,
                "maxLength": 9
            },
        },
        "required": ["clusterID", "machineName", "machineProvider"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # check if cluster exists
    try:
        cluster = models.Clusters.objects.filter(
            id=payload['clusterID'], project__tenant__daiteapuser__user=username)[0]
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster doesn\'t exist.'
            }
        }, status=400)

    if cluster.installstep != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is not ready.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is not ready.'
            }
        }, status=400)

    # check if machine exists
    try:
        machine = models.Machine.objects.filter(
            cluster_id=payload['clusterID'], name=payload['machineName'], provider=payload['machineProvider'])[0]
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Machine doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Machine doesn\'t exist.'
            }
        }, status=400)

    if machine.status in [0,1,3]:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Machine is running/starting.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Machine is running/starting.'
            }
        }, status=400)

    machine.status = 1
    machine.save()

    # submit start
    task = tasks.worker_start_machine.delay(payload['clusterID'], payload['machineName'], payload['machineProvider'], request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def restart_machine(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            },
            "machineName": {
                "type": "string",
                "minLength": 38,
                "maxLength": 150
            },
            "machineProvider": {
                "type": "string",
                "minLength": 3,
                "maxLength": 9
            },
        },
        "required": ["clusterID", "machineName", "machineProvider"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # check if cluster exists
    try:
        cluster = models.Clusters.objects.filter(
            id=payload['clusterID'], project__tenant__daiteapuser__user=username)[0]
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster doesn\'t exist.'
            }
        }, status=400)

    if cluster.installstep != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is not ready.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is not ready.'
            }
        }, status=400)

    # check if machine exists
    try:
        machine = models.Machine.objects.filter(
            cluster_id=payload['clusterID'], name=payload['machineName'], provider=payload['machineProvider'])[0]
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Machine doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Machine doesn\'t exist.'
            }
        }, status=400)

    if machine.status != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Machine is not running.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Machine is not running.'
            }
        }, status=400)

    machine.status = 3
    machine.save()

    # submit restart
    task = tasks.worker_restart_machine.delay(payload['clusterID'], payload['machineName'], payload['machineProvider'], request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_supported_kubernetes_configurations(request):
    response = {'supportedKubernetesVersions': SUPPORTED_KUBERNETES_VERSIONS,
                'supportedKubernetesNetworkPlugins': SUPPORTED_KUBERNETES_NETWORK_PLUGINS}

    return JsonResponse(response)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_supported_kubeadm_configurations(request):
    response = {'supportedKubernetesVersions': SUPPORTED_KUBEADM_VERSIONS,
                'supportedKubernetesNetworkPlugins': SUPPORTED_KUBEADM_NETWORK_PLUGINS}

    return JsonResponse(response)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_supported_capi_kubernetes_configurations(request):
    response = {'supportedKubernetesVersions': SUPPORTED_CAPI_KUBERNETES_VERSIONS}

    return JsonResponse(response)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_supported_yaookcapi_kubernetes_configurations(request):
    response = {'supportedKubernetesVersions': SUPPORTED_YAOOKCAPI_KUBERNETES_VERSIONS}

    return JsonResponse(response)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_supported_k3s_configurations(request):
    response = {'supportedKubernetesVersions': SUPPORTED_K3S_VERSIONS,
                'supportedKubernetesNetworkPlugins': SUPPORTED_K3S_NETWORK_PLUGINS}

    return JsonResponse(response)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_dlcm(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error
    schema = constants.CREATE_KUBERNETES_INPUT_VALIDATION_SCHEMA
    schema = environment_providers.add_input_validation_schemas(schema, payload)
    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    if payload['kubernetesConfiguration']['version'] not in SUPPORTED_KUBERNETES_VERSIONS:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter kubernetes version', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter kubernetes version'
            }
        }, status=400)

    if payload['kubernetesConfiguration']['networkPlugin'] not in SUPPORTED_KUBERNETES_NETWORK_PLUGINS:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter ', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter network plugin'
            }
        }, status=400)

    if not environment_providers.check_if_at_least_one_provider_is_selected(payload):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('No provider is selected.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'No provider is selected.'
            }
        }, status=400)

    if not environment_providers.check_controlplane_nodes(payload):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Illegal control plane node count.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Illegal control plane node count.'
            }
        }, status=400)

    networks = environment_providers.get_providers_networks(payload)
    networks.append(payload['kubernetesConfiguration']['serviceAddresses'])
    networks.append(payload['kubernetesConfiguration']['podsSubnet'])
    error = check_ip_addresses(networks)
    if error:
        return error

    try:
        environment_providers.validate_regions_zones_instance_types(payload, request.user, constants.ClusterType.DLCM.value)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    # authorize request
    error = authorization_service.authorize(payload, 'create_kubernetes_cluster', request.daiteap_user.id, logger)

    if error:
        return error

    # create db record for the cluster
    config = {
        'kubernetesConfiguration': payload['kubernetesConfiguration'],
        'internal_dns_zone': payload['internal_dns_zone'],
    }

    if 'load_balancer_integration' in payload and len(payload['load_balancer_integration']) > 0:
        config['load_balancer_integration'] = payload['load_balancer_integration']

    config.update(environment_providers.get_providers_config_params(payload, request.user))

    error = check_if_name_is_occupied_by_other_environment(payload, request.user.id)

    if error:
        return error

    cluster = models.Clusters()

    projects = models.Project.objects.filter(id=payload['projectId'], tenant_id=request.daiteap_user.tenant_id)
    if len(projects) == 0:
        return JsonResponse({
            'error': {
                'message': 'Not allowed to create resources in requested project',
            }
        }, status=403)
    cluster.project = projects[0]

    cluster.id = uuid.UUID(str(cluster.id)[:0] + get_random_lowercase_hex_letters(1) + str(cluster.id)[1:])
    cluster.name = str(cluster.id).replace('-', '')[0:10]

    cluster.title=payload['clusterName'].strip()
    cluster.installstep=1
    cluster.type=constants.ClusterType.DLCM.value
    cluster.user=request.user
    cluster.daiteap_user=request.daiteap_user
    cluster.providers=json.dumps(environment_providers.get_selected_providers(payload))
    cluster.config=json.dumps(config)

    if 'clusterDescription' in payload and payload['clusterDescription']:
        cluster.description = payload['clusterDescription']

    cluster.contact = request.user.username
    cluster.save()

    tag_values = dict()
    tag_values['username'] = request.user.username
    tag_values['email'] = request.user.email
    tag_values['url'] = request.headers['Origin']
    tag_values['tenant_name'] = request.daiteap_user.tenant.name

    # submit kubernetes creation
    task = tasks.worker_create_dlcm_environment.delay(json.loads(cluster.config), cluster.id, request.user.id, tag_values)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id, cluster=cluster)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'ID': cluster.id,
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_tf_plan(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error
    schema = constants.RESIZE_KUBERNETES_INPUT_VALIDATION_SCHEMA
    schema = environment_providers.add_input_validation_schemas(schema, payload)
    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # Check if cluster exists
    try:
        cluster = models.Clusters.objects.get(id=payload['clusterID'])
    except models.Clusters.DoesNotExist:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster does not exist', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster does not exist',
            }
        }, status=400)

    # get cluster config
    cluster_config = json.loads(cluster.config)

    config = {
        'kubernetesConfiguration': cluster_config['kubernetesConfiguration'],
        'internal_dns_zone': cluster_config['internal_dns_zone'],
    }

    if 'load_balancer_integration' in cluster_config and len(cluster_config['load_balancer_integration']) > 0:
        config['load_balancer_integration'] = cluster_config['load_balancer_integration']

    config.update(environment_providers.get_providers_config_params(payload, request.user))

    tag_values = dict()
    tag_values['username'] = request.user.username
    tag_values['email'] = request.user.email
    tag_values['url'] = request.headers['Origin']
    tag_values['tenant_name'] = request.daiteap_user.tenant.name

    # submit kubernetes creation
    task = tasks.worker_get_tf_plan.delay(config, cluster.id, request.user.id, tag_values)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id, cluster=cluster)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'ID': cluster.id,
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def resize_dlcm_v2(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error
    schema = constants.RESIZE_KUBERNETES_INPUT_VALIDATION_SCHEMA
    schema = environment_providers.add_input_validation_schemas(schema, payload)
    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # Check if cluster exists
    try:
        cluster = models.Clusters.objects.get(id=payload['clusterID'])
    except models.Clusters.DoesNotExist:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster does not exist', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster does not exist',
            }
        }, status=400)

    workspace_settings = models.TenantSettings.objects.get(tenant=cluster.project.tenant)
    if not workspace_settings.enable_cluster_resize:
        return JsonResponse({
            'error': {
                'message': 'Resize is not enabled in the workspace',
            }
        }, status=400)

    # check if user has access to the cloud accounts which he attempts to use
    for key in payload.keys():
        if key in [ "aws", "google", "openstack", "azure", "onpremise", "iotarm"]:
            id = payload.get(key).get("account")
            account = models.CloudAccount.objects.get(id=id)
            if not account.checkUserAccess(request.daiteap_user):
                return JsonResponse({
                    'error': {
                        'message': 'Project access denied.',
                    }
                }, status=403)

    if not environment_providers.check_if_at_least_one_provider_is_selected(payload):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('No provider is selected.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'No provider is selected.'
            }
        }, status=400)

    cluster_config = json.loads(cluster.config)

    networks = environment_providers.get_providers_networks(cluster_config)
    networks.append(cluster_config['kubernetesConfiguration']['serviceAddresses'])
    networks.append(cluster_config['kubernetesConfiguration']['podsSubnet'])
    networks = environment_providers.get_providers_networks(payload)
    error = check_ip_addresses(networks)
    if error:
        return error

    try:
        environment_providers.validate_regions_zones_instance_types(payload, request.user, constants.ClusterType.DLCM_V2.value)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    existing_nodes_count = models.Machine.objects.filter(cluster=cluster).count()

    error = authorization_service.authorize(payload, 'create_kubernetes_cluster', request.daiteap_user.id, logger, existing_nodes_count, True)

    if error:
        return error

    # create db record for the cluster
    config = {
        'kubernetesConfiguration': cluster_config['kubernetesConfiguration'],
        'internal_dns_zone': cluster_config['internal_dns_zone'],
    }

    if 'load_balancer_integration' in cluster_config and len(cluster_config['load_balancer_integration']) > 0:
        config['load_balancer_integration'] = cluster_config['load_balancer_integration']

    config.update(environment_providers.get_providers_config_params(payload, request.user))

    if error:
        return error

    cluster.resizestep=1
    cluster.resizeconfig=json.dumps(config)
    cluster.user = request.user

    cluster.save()

    tag_values = dict()
    tag_values['username'] = request.user.username
    tag_values['email'] = request.user.email
    tag_values['url'] = request.headers['Origin']
    tag_values['tenant_name'] = request.daiteap_user.tenant.name

    # submit kubernetes creation
    task = tasks.worker_resize_dlcm_v2_environment.delay(config, cluster.id, request.user.id, tag_values)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id, cluster=cluster)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'ID': cluster.id,
        'taskId': celerytask.id
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_dlcm_v2(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error
    schema = constants.CREATE_KUBERNETES_INPUT_VALIDATION_SCHEMA
    schema = environment_providers.add_input_validation_schemas(schema, payload)
    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)
    
    # check if user has access to the cloud accounts which he attempts to use
    for key in payload.keys():
        if key in [ "aws", "google", "openstack", "azure", "onpremise", "iotarm"]:
            id = payload.get(key).get("account")
            account = models.CloudAccount.objects.get(id=id)
            if not account.checkUserAccess(request.daiteap_user):
                return JsonResponse({
                    'error': {
                        'message': 'Project access denied.',
                    }
                }, status=403)

    if payload['kubernetesConfiguration']['version'] not in SUPPORTED_KUBEADM_VERSIONS:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter kubernetes version', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter kubernetes version'
            }
        }, status=400)

    if payload['kubernetesConfiguration']['networkPlugin'] not in SUPPORTED_KUBEADM_NETWORK_PLUGINS:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter ', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter network plugin'
            }
        }, status=400)

    if not environment_providers.check_if_at_least_one_provider_is_selected(payload):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('No provider is selected.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'No provider is selected.'
            }
        }, status=400)

    if not environment_providers.check_controlplane_nodes(payload):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Illegal control plane node count.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Illegal control plane node count.'
            }
        }, status=400)

    networks = environment_providers.get_providers_networks(payload)
    networks.append(payload['kubernetesConfiguration']['serviceAddresses'])
    networks.append(payload['kubernetesConfiguration']['podsSubnet'])
    error = check_ip_addresses(networks)
    if error:
        return error

    try:
        environment_providers.validate_regions_zones_instance_types(payload, request.user, constants.ClusterType.DLCM_V2.value)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    # authorize request
    error = authorization_service.authorize(payload, 'create_kubernetes_cluster', request.daiteap_user.id, logger)

    if error:
        return error

    # create db record for the cluster
    config = {
        'kubernetesConfiguration': payload['kubernetesConfiguration'],
        'internal_dns_zone': payload['internal_dns_zone'],
    }

    if 'load_balancer_integration' in payload and len(payload['load_balancer_integration']) > 0:
        config['load_balancer_integration'] = payload['load_balancer_integration']

    config.update(environment_providers.get_providers_config_params(payload, request.user))

    error = check_if_dlcmv2_name_is_occupied_by_other_environment(payload, request.user.id)

    if error:
        return error

    cluster = models.Clusters()

    projects = models.Project.objects.filter(id=payload['projectId'])
    if len(projects) == 0:
        return JsonResponse({
            'error': {
                'message': 'ProjectId not found',
            }
        }, status=403)
    cluster.project = projects[0]

    cluster.id = uuid.UUID(str(cluster.id)[:0] + get_random_lowercase_hex_letters(1) + str(cluster.id)[1:])
    cluster.name = str(cluster.id).replace('-', '')[0:10]

    cluster.title=payload['clusterName'].strip()
    cluster.installstep=1
    cluster.type=constants.ClusterType.DLCM_V2.value
    cluster.user=request.user
    cluster.daiteap_user=request.daiteap_user
    cluster.providers=json.dumps(environment_providers.get_selected_providers(payload))
    cluster.config=json.dumps(config)

    if 'clusterDescription' in payload and payload['clusterDescription']:
        cluster.description = payload['clusterDescription']

    cluster.contact = request.user.username
    cluster.save()

    tag_values = dict()
    tag_values['username'] = request.user.username
    tag_values['email'] = request.user.email
    tag_values['url'] = request.headers['Origin']
    tag_values['tenant_name'] = request.daiteap_user.tenant.name

    try:
        # submit kubernetes creation
        task = tasks.worker_create_dlcm_v2_environment.delay(json.loads(cluster.config), cluster.id, request.user.id, tag_values)
    except Exception as e:
        cluster.delete()
        raise e

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id, cluster=cluster)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'ID': cluster.id,
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_capi_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error
    schema = constants.CREATE_CAPI_INPUT_VALIDATION_SCHEMA
    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    projects = models.Project.objects.filter(id=payload['projectId'])
    if len(projects) == 0:
        return JsonResponse({
            'error': {
                'message': 'ProjectId not found',
            }
        }, status=403)
    project = projects[0]

    if payload['kubernetesConfiguration']['version'] not in SUPPORTED_CAPI_KUBERNETES_VERSIONS:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter kubernetes version', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter kubernetes version'
            }
        }, status=400)

    if not environment_providers.check_if_at_least_one_provider_is_selected(payload):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('No provider is selected.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'No provider is selected.'
            }
        }, status=400)

    if not environment_providers.check_controlplane_nodes(payload):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Illegal control plane node count.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Illegal control plane node count.'
            }
        }, status=400)

    try:
        environment_providers.validate_regions_zones_instance_types(payload, request.user, constants.ClusterType.CAPI.value)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    # authorize request
    error = authorization_service.authorize(payload, 'create_capi_cluster', request.daiteap_user.id, logger)

    if error:
        return error

    # create db record for the cluster
    capi_config = {
        'kubernetesConfiguration': payload['kubernetesConfiguration'],
    }

    capi_config.update(environment_providers.get_providers_capi_config_params(payload, request.user))

    if 'clusterId' in payload and payload['clusterId']:
        cluster = models.CapiCluster.objects.filter(id=payload['clusterId'], project__tenant_id=request.daiteap_user.tenant_id)[0]

        if cluster.installstep:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error("Cluster already created", extra=log_data)
            return JsonResponse({
                'error': {
                    'message': "Cluster already created"
                }
            }, status=400)

    else:
        error = check_if_name_is_occupied_by_other_environment(payload, request.user.id)

        if error:
            return error

        cluster = models.CapiCluster()

        cluster.id = uuid.UUID(str(cluster.id)[:0] + get_random_lowercase_hex_letters(1) + str(cluster.id)[1:])
        cluster.name = str(cluster.id).replace('-', '')[0:10]

    cluster.title=payload['clusterName'].strip()
    cluster.project=project
    cluster.installstep=1
    cluster.type=constants.ClusterType.CAPI.value
    cluster.daiteap_user=request.daiteap_user
    cluster.providers=json.dumps(environment_providers.get_selected_providers(payload))
    cluster.capi_config=json.dumps(capi_config)
    cluster.contact = request.user.username

    if 'clusterDescription' in payload and payload['clusterDescription']:
        cluster.description = payload['clusterDescription']

    cluster.save()

    try:
        # submit capi creation
        task = tasks.worker_create_capi_cluster.delay(json.loads(cluster.capi_config), cluster.id, request.user.id)
    except Exception as e:
        cluster.delete()
        raise e

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'ID': cluster.id,
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def resize_capi_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error
    schema = constants.RESIZE_CAPI_INPUT_VALIDATION_SCHEMA
    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # Get user's cluster
    try:
        cluster = models.CapiCluster.objects.filter(project__tenant_id=request.daiteap_user.tenant_id, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    workspace_settings = models.TenantSettings.objects.get(tenant=cluster.project.tenant)
    if not workspace_settings.enable_cluster_resize:
        return JsonResponse({
            'error': {
                'message': 'Resize is not enabled in the workspace',
            }
        }, status=400)

    if cluster.installstep != 0 or cluster.resizestep != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster status does not permit resize.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not permit resize.'
            }
        }, status=500)

    cluster.resizestep = 1
    cluster.save()

    task = tasks.worker_resize_capi_cluster.delay(payload['openstack']['workerNodes'], cluster.id, request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def retry_create_capi_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # Get user's cluster
    try:
        cluster = models.CapiCluster.objects.filter(project__tenant__daiteapuser__user=username, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    if cluster.installstep >= 0:
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not allow retry'
            }
        }, status=400)

    task = tasks.worker_create_capi_cluster.delay(json.loads(cluster.capi_config), cluster.id, request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id, cluster=cluster)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'taskId': celerytask.id,
        'ID': cluster.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_capi_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)


    # change cluster install step if cluster exists
    try:
        cluster = models.CapiCluster.objects.filter(id=payload['clusterID'])[0]

        if not cluster.checkUserAccess(request.daiteap_user):
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter clusterID'
                }
            }, status=403)
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster doesn\'t exist.'
            }
        }, status=400)

    if not cluster.installstep <= 0:
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not allow deletion'
            }
        }, status=400)

    cluster.installstep = 100
    cluster.save()

    # submit deletion
    task = tasks.worker_delete_capi_cluster.delay(payload['clusterID'], request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
        })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_yaookcapi_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error
    schema = constants.CREATE_YAOOKCAPI_INPUT_VALIDATION_SCHEMA
    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    projects = models.Project.objects.filter(id=payload['projectId'])
    if len(projects) == 0:
        return JsonResponse({
            'error': {
                'message': 'ProjectId not found',
            }
        }, status=403)
    project = projects[0]

    if payload['kubernetesConfiguration']['version'] not in SUPPORTED_YAOOKCAPI_KUBERNETES_VERSIONS:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter kubernetes version', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter kubernetes version'
            }
        }, status=400)

    if not environment_providers.check_if_at_least_one_provider_is_selected(payload):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('No provider is selected.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'No provider is selected.'
            }
        }, status=400)

    if not environment_providers.check_controlplane_nodes(payload):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Illegal control plane node count.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Illegal control plane node count.'
            }
        }, status=400)

    try:
        environment_providers.validate_regions_zones_instance_types(payload, request.user, constants.ClusterType.CAPI.value)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    # authorize request
    error = authorization_service.authorize(payload, 'create_yaookcapi_cluster', request.daiteap_user.id, logger)

    if error:
        return error

    # create db record for the cluster
    yaookcapi_config = {
        'kubernetesConfiguration': payload['kubernetesConfiguration'],
    }

    yaookcapi_config.update(environment_providers.get_providers_yaookcapi_config_params(payload, request.user))

    error = check_if_name_is_occupied_by_other_environment(payload, request.user.id)

    if error:
        return error

    cluster = models.YaookCapiCluster()

    cluster.id = uuid.UUID(str(cluster.id)[:0] + get_random_lowercase_hex_letters(1) + str(cluster.id)[1:])
    cluster.name = str(cluster.id).replace('-', '')[0:10]

    cluster.title=payload['clusterName'].strip()
    cluster.project=project
    cluster.installstep=1
    cluster.type=constants.ClusterType.YAOOKCAPI.value
    cluster.user=request.user
    cluster.daiteap_user=request.daiteap_user
    cluster.providers=json.dumps(environment_providers.get_selected_providers(payload))
    cluster.yaookcapi_config=json.dumps(yaookcapi_config)
    cluster.contact = request.user.username

    wireguard_private, wireguard_public = Key.key_pair()

    cluster.wireguard_public_key = str(wireguard_public)
    cluster.wireguard_private_key = str(wireguard_private)

    cluster.wireguard_indent = '%s' % cluster.id

    if 'clusterDescription' in payload and payload['clusterDescription']:
        cluster.description = payload['clusterDescription']

    cluster.save()

    try:
        # submit yaookcapi creation
        task = tasks.worker_create_yaookcapi_cluster.delay(cluster.id, request.user.id)
    except Exception as e:
        cluster.delete()
        raise e

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'ID': cluster.id,
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def resize_yaookcapi_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error
    schema = constants.RESIZE_YAOOKCAPI_INPUT_VALIDATION_SCHEMA
    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # Get user's cluster
    try:
        cluster = models.YaookCapiCluster.objects.filter(project__tenant_id=request.daiteap_user.tenant_id, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    workspace_settings = models.TenantSettings.objects.get(tenant=cluster.project.tenant)
    if not workspace_settings.enable_cluster_resize:
        return JsonResponse({
            'error': {
                'message': 'Resize is not enabled in the workspace',
            }
        }, status=400)

    if cluster.installstep != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster status does not permit resize.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not permit resize.'
            }
        }, status=500)

    cluster.resizestep = 1
    cluster.save()

    task = tasks.worker_resize_yaookcapi_cluster.delay(payload['openstack']['workerNodes'], cluster.id, request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def retry_create_yaookcapi_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # Get user's cluster
    try:
        cluster = models.YaookCapiCluster.objects.filter(project__tenant__daiteapuser__user=username, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    if cluster.installstep >= 0:
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not allow retry'
            }
        }, status=400)

    task = tasks.worker_create_yaookcapi_cluster.delay(json.loads(cluster.yaookcapi_config), cluster.id, request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id, cluster=cluster)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'taskId': celerytask.id,
        'ID': cluster.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_yaookcapi_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # change cluster install step if cluster exists
    try:
        cluster = models.YaookCapiCluster.objects.filter(id=payload['clusterID'])[0]

        if not cluster.checkUserAccess(request.daiteap_user):
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter clusterID'
                }
            }, status=403)
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster doesn\'t exist.'
            }
        }, status=400)

    if not cluster.installstep <= 0:
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not allow deletion'
            }
        }, status=400)

    cluster.installstep = 100
    cluster.save()

    # submit deletion
    task = tasks.worker_delete_yaookcapi_cluster.delay(payload['clusterID'], request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
        })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_k3s_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = constants.CREATE_K3S_INPUT_VALIDATION_SCHEMA
    schema = environment_providers.add_input_validation_schemas(schema, payload)

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    if payload['kubernetesConfiguration']['version'] not in SUPPORTED_K3S_VERSIONS:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter kubernetes version', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter kubernetes version'
            }
        }, status=400)

    if payload['kubernetesConfiguration']['networkPlugin'] not in SUPPORTED_K3S_NETWORK_PLUGINS:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter ', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter network plugin'
            }
        }, status=400)

    if not environment_providers.check_if_at_least_one_provider_is_selected(payload):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('No provider is selected.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'No provider is selected.'
            }
        }, status=400)

    if not environment_providers.check_controlplane_nodes(payload):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Illegal control plane node count.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Illegal control plane node count.'
            }
        }, status=400)

    networks = environment_providers.get_providers_networks(payload)
    networks.append(payload['kubernetesConfiguration']['serviceAddresses'])
    networks.append(payload['kubernetesConfiguration']['podsSubnet'])

    error = check_ip_addresses(networks)

    if error:
        return error

    try:
        environment_providers.validate_regions_zones_instance_types(payload, request.user, constants.ClusterType.K3S.value)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    # authorize request
    error = authorization_service.authorize(payload, 'create_kubernetes_cluster', request.daiteap_user.id, logger)

    if error:
        return error

    # create db record for the cluster
    config = {
        'kubernetesConfiguration': payload['kubernetesConfiguration'],
        'internal_dns_zone': payload['internal_dns_zone'],
    }

    if 'load_balancer_integration' in payload and len(payload['load_balancer_integration']) > 0:
        config['load_balancer_integration'] = payload['load_balancer_integration']

    config.update(environment_providers.get_providers_config_params(payload, request.user))

    error = check_if_name_is_occupied_by_other_environment(payload, request.user.id)

    if error:
        return error

    cluster = models.Clusters()

    projects = models.Project.objects.filter(id=payload['projectId'])
    if len(projects) == 0:
        return JsonResponse({
            'error': {
                'message': 'ProjectId not found',
            }
        }, status=403)
    cluster.project = projects[0]

    cluster.id = uuid.UUID(str(cluster.id)[:0] + get_random_lowercase_hex_letters(1) + str(cluster.id)[1:])
    cluster.name = str(cluster.id).replace('-', '')[0:10]

    cluster.title=payload['clusterName'].strip()
    cluster.installstep=1
    cluster.type=constants.ClusterType.K3S.value
    cluster.user=request.user
    cluster.daiteap_user=request.daiteap_user
    cluster.providers=json.dumps(environment_providers.get_selected_providers(payload))
    cluster.config=json.dumps(config)

    if 'clusterDescription' in payload and payload['clusterDescription']:
        cluster.description = payload['clusterDescription']

    cluster.contact = request.user.username
    cluster.save()

    tag_values = dict()
    tag_values['username'] = request.user.username
    tag_values['email'] = request.user.email
    tag_values['url'] = request.headers['Origin']
    tag_values['tenant_name'] = request.daiteap_user.tenant.name

    try:
        # submit kubernetes creation
        task = tasks.worker_create_k3s_cluster.delay(json.loads(cluster.config), cluster.id, request.user.id, tag_values)
    except Exception as e:
        cluster.delete()
        raise e

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id, cluster=cluster)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'ID': cluster.id,
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def upgrade_kubernetes_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            },
            "version": {
                "type": "string",
                "minLength": 1,
                "maxLength": 50
            }
        },
        "required": ["clusterID", "version"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=username, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    config = json.loads(cluster.config)

    upgrade_versions = get_kubernetes_upgrade_versions(config)

    if payload['version'] not in upgrade_versions:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid kubernetes upgrade version', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid kubernetes upgrade version',
            }
        }, status=400)

    task = tasks.worker_upgrade_kubernetes_cluster.delay(config, cluster.id, request.user.id, payload['version'])

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'taskId': celerytask.id,
        'ID': cluster.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def upgrade_k3s_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            },
            "version": {
                "type": "string",
                "minLength": 1,
                "maxLength": 50
            }
        },
        "required": ["clusterID", "version"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=username, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    config = json.loads(cluster.config)

    upgrade_versions = get_k3s_upgrade_versions(config)

    if payload['version'] not in upgrade_versions:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid k3s upgrade version', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid k3s upgrade version',
            }
        }, status=400)

    task = tasks.worker_upgrade_k3s_cluster.delay(config, cluster.id, request.user.id, payload['version'])

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'taskId': celerytask.id,
        'ID': cluster.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def retry_create_k3s_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=username, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    if cluster.installstep >= 0:
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not allow retry'
            }
        }, status=400)

    tag_values = dict()
    tag_values['username'] = request.user.username
    tag_values['email'] = request.user.email
    tag_values['url'] = request.headers['Origin']
    tag_values['tenant_name'] = request.daiteap_user.tenant.name

    task = tasks.worker_create_k3s_cluster.delay(json.loads(cluster.config), cluster.id, request.user.id, tag_values)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id, cluster=cluster)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'taskId': celerytask.id,
        'ID': cluster.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def retry_create_dlcm(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            },
            "config": {
                "type": "string",
                "minLength": 1,
                "maxLength": 50
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=username, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    if cluster.installstep >= 0:
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not allow retry'
            }
        }, status=400)

    if ('config' in payload and
        cluster.installstep == -1 and
        'suggested_instance_type' in error_msg and
        error_msg['suggested_instance_type'] != '' and
        'error_instance_type' in error_msg and
        error_msg['error_instance_type'] != ''):
        schema = constants.CREATE_KUBERNETES_INPUT_VALIDATION_SCHEMA
        schema = environment_providers.add_input_validation_schemas(schema, payload['config'])

        try:
            validate(instance=payload['config'], schema=schema)
        except ValidationError as e:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error(str(e), extra=log_data)
            return JsonResponse({
                'error': {
                    'message': str(e),
                }
            }, status=400)
        
        cluster.config = config
        cluster.save()

    tag_values = dict()
    tag_values['username'] = request.user.username
    tag_values['email'] = request.user.email
    tag_values['url'] = request.headers['Origin']
    tag_values['tenant_name'] = request.daiteap_user.tenant.name

    if cluster.type == constants.ClusterType.DLCM_V2.value:
        task = tasks.worker_create_dlcm_v2_environment.delay(json.loads(cluster.config), cluster.id, request.user.id, tag_values)
    else:
        task = tasks.worker_create_dlcm_environment.delay(json.loads(cluster.config), cluster.id, request.user.id, tag_values)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id, cluster=cluster)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'taskId': celerytask.id,
        'ID': cluster.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def retry_resize_dlcm(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=username, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    if cluster.resizestep >= 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not allow retry'
            }
        }, status=500)

    task = tasks.worker_add_machines_to_dlcm.delay(json.loads(cluster.config), cluster.id, request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'taskId': celerytask.id,
        'ID': cluster.id
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def retry_resize_dlcm_v2(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=username, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    workspace_settings = models.TenantSettings.objects.get(tenant=cluster.project.tenant)
    if not workspace_settings.enable_cluster_resize:
        return JsonResponse({
            'error': {
                'message': 'Resize is not enabled in the workspace',
            }
        }, status=400)

    if cluster.resizestep >= 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not allow retry'
            }
        }, status=500)

    task = tasks.worker_add_machines_to_dlcm_v2.delay(json.loads(cluster.config), cluster.id, request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'taskId': celerytask.id,
        'ID': cluster.id
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def retry_resize_vms_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=username, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    if cluster.resizestep >= 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not allow retry'
            }
        }, status=500)

    task = tasks.worker_add_machines_to_vms.delay(json.loads(cluster.config), request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'taskId': celerytask.id,
        'ID': cluster.id
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def retry_create_vms(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(
            project__tenant__daiteapuser__user=username, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    tag_values = dict()
    tag_values['username'] = request.user.username
    tag_values['email'] = request.user.email
    tag_values['url'] = request.headers['Origin']
    tag_values['tenant_name'] = request.daiteap_user.tenant.name

    # submit VMs creation
    task = tasks.worker_create_vms.delay(json.loads(cluster.config), cluster.id, request.user.id, tag_values)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id, cluster=cluster)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'taskId': celerytask.id,
        'ID': cluster.id
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def retry_create_compute_vms(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(
            project__tenant__daiteapuser__user=username, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    tag_values = dict()
    tag_values['username'] = request.user.username
    tag_values['email'] = request.user.email
    tag_values['url'] = request.headers['Origin']
    tag_values['tenant_name'] = request.daiteap_user.tenant.name

    # submit VMs creation
    task = tasks.worker_create_compute_vms.delay(json.loads(cluster.config), cluster.id, request.user.id, tag_values)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id, cluster=cluster)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'taskId': celerytask.id,
        'ID': cluster.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_cluster_creation(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = constants.CANCEL_CLUSTER_CREATION_INPUT_VALIDATION_SCHEMA

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)


    username = request.user

    # change cluster install step if cluster exists
    try:
        cluster = models.Clusters.objects.filter(id=payload['clusterID'], project__tenant__daiteapuser__user=username)[0]
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster doesn\'t exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster doesn\'t exist.'
            }
        }, status=400)

    if cluster.installstep < 1 or cluster.installstep == 100:
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not allow creation cancellation.'
            }
        }, status=400)

    if cluster.canceled:
        return JsonResponse({
            'error': {
                'message': 'Cluster creation is already canceled.'
            }
        }, status=400)

    cluster.canceled = True
    cluster.save()

    task = tasks.worker_cancel_cluster_creation.delay(cluster.id, request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_machines_to_vms(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "minLength": 2,
                "maxLength": 10
            },
            "region": {
                "type": "string",
                "minLength": 3,
                "maxLength": 20
            },
            "zone": {
                "type": "string",
                "minLength": 3,
                "maxLength": 25
            },
            "nodes": {
                "type": "number"
            },
            "instanceType": {
                "type": "string",
                "minLength": 1,
                "maxLength": 50
            },
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["provider", "clusterID", "nodes", "instanceType", "zone", "region"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    user = request.user

    # Validate provider parameter
    if not environment_providers.check_if_at_least_one_provider_is_selected(payload['provider']):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid provider parameter.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid provider parameter.'
            }
        }, status=400)

    # Get user's cluster and check it's status
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=user, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    providers = json.loads(cluster.config)

    try:
        validate_payload = {payload['provider']: {
            'account': providers[payload['provider']]['account'],
            'region': payload['region'],
            'zone': payload['zone'],
            'instanceType': payload['instanceType']
        }}
        environment_providers.validate_regions_zones_instance_types(validate_payload, request.user, 2)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    # Get user's cluster and check it's status
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=user, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    if cluster.status != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is not running.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is not running.'
            }
        }, status=500)

    if cluster.installstep != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster status does not permit adding machines.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not permit adding machines.'
            }
        }, status=500)

    # authorize request
    error = authorization_service.authorize(payload, 'add_machines_to_vms', request.daiteap_user.id, logger)

    if error:
        return error

    cluster.resizestep = 1
    cluster.save()
    task = tasks.worker_add_machines_to_vms.delay(payload, request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_machines_to_k3s(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "minLength": 2,
                "maxLength": 10
            },
            "region": {
                "type": "string",
                "minLength": 3,
                "maxLength": 20
            },
            "zone": {
                "type": "string",
                "minLength": 3,
                "maxLength": 25
            },
            "nodes": {
                "type": "number"
            },
            "instanceType": {
                "type": "string",
                "minLength": 1,
                "maxLength": 50
            },
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            },
        },
        "required": ["provider", "clusterID", "nodes"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    user = request.user

    # Validate provider parameter
    if not environment_providers.check_if_at_least_one_provider_is_selected(payload['provider']):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid provider parameter.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid provider parameter.'
            }
        }, status=400)

    # Get user's cluster and check it's status
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=user, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    providers = json.loads(cluster.config)

    try:
        validate_payload = {payload['provider']: {
            'account': providers[payload['provider']]['account'],
            'region': payload['region'],
            'zone': payload['zone'],
            'instanceType': payload['instanceType']
        }}
        environment_providers.validate_regions_zones_instance_types(validate_payload, request.user, constants.ClusterType.K3S.value)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    # Get user's cluster and check it's status
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=user, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    if cluster.status != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is not running.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is not running.'
            }
        }, status=500)

    if cluster.installstep != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster status does not permit adding machines.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not permit adding machines.'
            }
        }, status=500)


    # authorize request
    error = authorization_service.authorize(payload, 'add_machines_to_kubernetes', request.daiteap_user.id, logger)

    if error:
        return error

    # Submit cluster machine creation
    cluster.resizestep = 1
    cluster.save()
    task = tasks.worker_add_machines_to_k3s.delay(payload, request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_machines_to_dlcm(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "minLength": 2,
                "maxLength": 10
            },
            "region": {
                "type": "string",
                "minLength": 3,
                "maxLength": 20
            },
            "zone": {
                "type": "string",
                "minLength": 3,
                "maxLength": 25
            },
            "nodes": {
                "type": "number"
            },
            "instanceType": {
                "type": "string",
                "minLength": 1,
                "maxLength": 50
            },
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["provider", "clusterID", "nodes", "instanceType", "zone", "region"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    user = request.user

    # Validate provider parameter
    if not environment_providers.check_if_at_least_one_provider_is_selected(payload['provider']):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid provider parameter.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid provider parameter.'
            }
        }, status=400)

    # Get user's cluster and check it's status
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=user, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    providers = json.loads(cluster.config)

    try:
        validate_payload = {payload['provider']: {
            'account': providers[payload['provider']]['account'],
            'region': payload['region'],
            'zone': payload['zone'],
            'instanceType': payload['instanceType']
        }}
        environment_providers.validate_regions_zones_instance_types(validate_payload, request.user, constants.ClusterType.DLCM.value)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    # Get user's cluster and check it's status
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=user, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    if cluster.status != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is not running.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is not running.'
            }
        }, status=500)

    if cluster.installstep != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster status does not permit adding machines.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not permit adding machines.'
            }
        }, status=500)

    # authorize request
    error = authorization_service.authorize(payload, 'add_machines_to_kubernetes', request.daiteap_user.id, logger)

    if error:
        return error

    # Submit cluster machine creation
    cluster.resizestep = 1
    cluster.save()

    task = tasks.worker_add_machines_to_dlcm.delay(payload, request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_machines_to_dlcm_v2(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "minLength": 2,
                "maxLength": 10
            },
            "region": {
                "type": "string",
                "minLength": 3,
                "maxLength": 20
            },
            "zone": {
                "type": "string",
                "minLength": 3,
                "maxLength": 25
            },
            "nodes": {
                "type": "number"
            },
            "instanceType": {
                "type": "string",
                "minLength": 1,
                "maxLength": 50
            },
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["provider", "clusterID", "nodes", "instanceType", "zone", "region"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    user = request.user

    # Validate provider parameter
    if not environment_providers.check_if_at_least_one_provider_is_selected(payload['provider']):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid provider parameter.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid provider parameter.'
            }
        }, status=400)

    # Get user's cluster and check it's status
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=user, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    providers = json.loads(cluster.config)

    try:
        validate_payload = {payload['provider']: {
            'account': providers[payload['provider']]['account'],
            'region': payload['region'],
            'nodes': []
        }}

        for _ in range(payload['nodes']):
            validate_payload[payload['provider']]['nodes'].append({
                'zone': payload['zone'],
                'instanceType': payload['instanceType'],
            })

        environment_providers.validate_regions_zones_instance_types(validate_payload, request.user, constants.ClusterType.DLCM_V2.value)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    # Get user's cluster and check it's status
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=user, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    if cluster.status != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is not running.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is not running.'
            }
        }, status=500)

    if cluster.installstep != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster status does not permit adding machines.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not permit adding machines.'
            }
        }, status=500)

    # authorize request
    error = authorization_service.authorize(payload, 'add_machines_to_kubernetes', request.daiteap_user.id, logger)

    if error:
        return error

    # Submit cluster machine creation
    cluster.resizestep = 1
    cluster.save()

    task = tasks.worker_add_machines_to_dlcm_v2.delay(payload, request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def check_for_ip_conflicts(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "networks": {
                "type": "array"
            },
        },
        "required": ["networks"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    error = check_ip_addresses(payload['networks'])

    if error:
        return JsonResponse({
            'conflicts': True,
            'message': json.loads(error.content.decode('utf-8'))['error']['message']
        })

    # return JSON response
    return JsonResponse({
        'conflicts': False,
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def check_ip_address(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "network": {
                "type": "string"
            },
            "ip": {
                "type": "string"
            },
        },
        "required": ["network", "ip"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    ip_in_network = check_ip_in_network(payload['network'], payload['ip'])

    if not ip_in_network:
        return JsonResponse({
            'error': True
        })

    # return JSON response
    return JsonResponse({
        'error': False,
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_machine_from_vms(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "minLength": 10,
                "maxLength": 62
            },
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["name", "clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    user = request.user

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(
            project__tenant__daiteapuser__user=user, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    if cluster.installstep != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster status does not permit deleting machines.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster status does not permit deleting machines.'
            }
        }, status=500)

    # Validate machine is deletable
    try:
        machine = models.Machine.objects.filter(cluster=cluster, name=payload['name'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Machine does not exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Machine does not exist.'
            }
        }, status=500)

    machines = models.Machine.objects.filter(
        cluster=cluster, provider=machine.provider, region=machine.region).order_by('name')

    if len(machines) < 2 or machine == machines[0]:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Machine couldn\'t be deleted.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Machine couldn\'t be deleted.'
            }
        }, status=500)

    # Submit cluster machine creation
    tasks.worker_delete_machine_from_vms.delay(payload, user.username)

    # return JSON response
    return JsonResponse({
        'submitted': True
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_task_message(request, task_id):
    # get user plan msg
    try:
        celerytask_id = models.CeleryTask.objects.filter(id=task_id, user=request.user).values('task_id')[0]['task_id']
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Internal Server Error.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Internal Server Error.'
            }
        }, status=500)

    res = AsyncResult(celerytask_id)

    response = {
        'status': '',
        'error': False,
        'errorMessage': '',
        'lcmStatuses': []
    }
    response['status'] = res.state

    if (response['status'] == 'SUCCESS'):
        msg = res.get()

        if 'error' in msg:
            response['error'] = True
            response['errorMessage'] = msg['error']
            response['status'] = 'ERROR'

        for key in msg.keys():
            if key != 'error':
                response['lcmStatuses'].append({key: msg[key]})

    elif (response['status'] == 'PENDING'):
        pass

    else:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Internal Server Error.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Internal Server Error.'
            }
        }, status=500)

    return JsonResponse(response)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_VMs(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = constants.CREATE_VMS_INPUT_VALIDATION_SCHEMA
    schema = environment_providers.add_input_validation_schemas(schema, payload)

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    if not environment_providers.check_if_at_least_one_provider_is_selected(payload):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('No provider is selected.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'No provider is selected.'
            }
        }, status=400)

    networks = environment_providers.get_providers_networks(payload)

    error = check_ip_addresses(networks)

    if error:
        return error

    try:
        environment_providers.validate_regions_zones_instance_types(payload, request.user, constants.ClusterType.VMS.value)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    # authorize request
    error = authorization_service.authorize(payload, 'create_VMs', request.daiteap_user.id, logger)

    if error:
        return error

    # create db record for the cluster
    config = {
        'internal_dns_zone': payload['internal_dns_zone']
    }

    config.update(environment_providers.get_providers_config_params(payload, request.user))

    error = check_if_name_is_occupied_by_other_environment(payload, request.user.id)

    if error:
        return error

    cluster = models.Clusters()

    projects = models.Project.objects.filter(id=payload['projectId'])
    if len(projects) == 0:
        return JsonResponse({
            'error': {
                'message': 'ProjectId not found',
            }
        }, status=403)
    cluster.project = projects[0]


    cluster.id = uuid.UUID(str(cluster.id)[:0] + get_random_lowercase_hex_letters(1) + str(cluster.id)[1:])
    cluster.name = str(cluster.id).replace('-', '')[0:10]

    cluster.title=payload['clusterName'].strip()
    cluster.installstep=1
    cluster.type=constants.ClusterType.VMS.value
    cluster.user=request.user
    cluster.daiteap_user=request.daiteap_user
    cluster.providers=json.dumps(environment_providers.get_selected_providers(payload))
    cluster.config=json.dumps(config)

    if payload['clusterDescription']:
        cluster.description = payload['clusterDescription']

    cluster.contact = request.user.email
    cluster.save()

    tag_values = dict()
    tag_values['username'] = request.user.username
    tag_values['email'] = request.user.email
    tag_values['url'] = request.headers['Origin']
    tag_values['tenant_name'] = request.daiteap_user.tenant.name

    # submit VMs creation
    task = tasks.worker_create_vms.delay(json.loads(cluster.config), cluster.id, request.user.id, tag_values)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id, cluster=cluster)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'taskId': celerytask.id,
        'ID': cluster.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_compute_VMs(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error
    
    schema = constants.CREATE_COMPUTE_VMS_INPUT_VALIDATION_SCHEMA
    schema = environment_providers.add_input_validation_schemas(schema, payload)

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # check if user has access to the cloud accounts which he attempts to use
    for key in payload.keys():
        if key in [ "aws", "google", "openstack", "azure", "onpremise", "iotarm"]:
            id = payload.get(key).get("account")
            account = models.CloudAccount.objects.get(id=id)
            if not account.checkUserAccess(request.daiteap_user):
                return JsonResponse({
                    'error': {
                        'message': 'Project access denied.',
                    }
                }, status=403)

    if not environment_providers.check_if_at_least_one_provider_is_selected(payload):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('No provider is selected.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'No provider is selected.'
            }
        }, status=400)

    networks = environment_providers.get_providers_networks(payload)

    error = check_ip_addresses(networks)

    if error:
        return error

    try:
        environment_providers.validate_regions_zones_instance_types(payload, request.user, constants.ClusterType.COMPUTE_VMS.value)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    # authorize request
    error = authorization_service.authorize(payload, 'create_compute_VMs', request.daiteap_user.id, logger)

    if error:
        return error

    # create db record for the cluster
    config = {
        'internal_dns_zone': payload['internal_dns_zone']
    }

    config.update(environment_providers.get_providers_config_params(payload, request.user))

    error = check_if_compute_name_is_occupied_by_other_environment(payload, request.user.id)

    if error:
        return error
    cluster = models.Clusters()

    projects = models.Project.objects.filter(id=payload['projectId'])
    if len(projects) == 0:
        return JsonResponse({
            'error': {
                'message': 'ProjectId not found',
            }
        }, status=403)
    cluster.project = projects[0]

    cluster.id = uuid.UUID(str(cluster.id)[:0] + get_random_lowercase_hex_letters(1) + str(cluster.id)[1:])
    cluster.name = str(cluster.id).replace('-', '')[0:10]

    cluster.title=payload['clusterName'].strip()
    cluster.installstep=1
    cluster.type=constants.ClusterType.COMPUTE_VMS.value
    cluster.user=request.user
    cluster.daiteap_user=request.daiteap_user
    cluster.providers=json.dumps(environment_providers.get_selected_providers(payload))
    cluster.config=json.dumps(config)

    if 'clusterDescription' in payload and payload['clusterDescription']:
        cluster.description = payload['clusterDescription']

    cluster.contact = request.user.username
    cluster.save()

    tag_values = dict()
    tag_values['username'] = request.user.username
    tag_values['email'] = request.user.email
    tag_values['url'] = request.headers['Origin']
    tag_values['tenant_name'] = request.daiteap_user.tenant.name

    try:
        # submit VMs creation
        task = tasks.worker_create_compute_vms.delay(json.loads(cluster.config), cluster.id, request.user.id, tag_values)
    except Exception as e:
        cluster.delete()
        raise e

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id, cluster=cluster)
    celerytask.save()

    # return JSON response
    return JsonResponse({
        'taskId': celerytask.id,
        'ID': cluster.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_service(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "serviceName": {
                "type": "string",
                "minLength": 5,
                "maxLength": 30
            },
            "configurationType": {
                "type": "string",
                "minLength": 10,
                "maxLength": 12
            },
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["serviceName", "configurationType", "clusterID"]
    }

    configTypes = [
        'simpleConfig',
        'yamlConfig'
    ]

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)
    
    if payload['configurationType'] not in configTypes:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('configurationType is invalid.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'configurationType is invalid.'
            }
        }, status=400)

    username = request.user
    is_capi = False
    is_yaookcapi = False

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(id=payload['clusterID'], project__tenant__daiteapuser__user=username)
        if len(cluster) == 0:
            cluster = models.CapiCluster.objects.filter(id=payload['clusterID'], project__tenant__daiteapuser__user=username)
            if len(cluster) == 0:
                cluster = models.YaookCapiCluster.objects.filter(id=payload['clusterID'], project__tenant__daiteapuser__user=username)[0]
                is_yaookcapi = True
            else:
                cluster = cluster[0]
                is_capi = True
        else:
            cluster = cluster[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    # Check if service name already exists
    if is_capi:
        service = models.ClusterService.objects.filter(name=payload['name'], capi_cluster=cluster)
    elif is_yaookcapi:
        service = models.ClusterService.objects.filter(name=payload['name'], yaookcapi_cluster=cluster)
    else:
        service = models.ClusterService.objects.filter(name=payload['name'], cluster=cluster)

    if len(service) > 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Service name already exists', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Service name already exists'
            }
        }, status=400)

    # Check if environment is running
    if not is_capi and not is_yaookcapi and cluster.status != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is not running.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is not running.'
            }
        }, status=500)

    # Get service
    try:
        service = models.Service.objects.filter(name=payload['serviceName'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Service does not exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Service does not exist.'
            }
        }, status=500)

    # Check if service can be installed more than once
    if not service.supports_multiple_installs:
        serviceList = models.ClusterService.objects.filter(cluster=cluster).values('service__name')
        for srvc in serviceList:
            if srvc['service__name'] == service.name:
                return JsonResponse({
                    'error': {
                        'message': 'Service can\'t be installed more than once in a cluster.'
                    }
                }, status=500)

    service_options = json.loads(service.options)

    # Get service configuration
    if payload['configurationType'] == 'yamlConfig':
        if service_options['yamlConfig'] == False:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Service does not support yamlConfig.', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'Service does not support yamlConfig.'
                }
            }, status=500)

        if 'valuesFile' not in payload:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'environment_id': payload['clusterID'],
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('valuesFile is invalid.', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'valuesFile is invalid.'
                }
            }, status=400)

        configuration = payload

    else:
        configuration = {}

        for option in service_options:
            if option == 'yamlConfig':
                continue
            if option not in payload:
                log_data = {
                    'level': 'ERROR',
                    'user_id': str(request.user.id),
                    'environment_id': payload['clusterID'],
                    'client_request': json.loads(request.body.decode('utf-8')),
                }
                logger.error(option + ' parameter is missing.', extra=log_data)
                return JsonResponse({
                    'error': {
                        'message': option + ' parameter is missing.'
                    }
                }, status=400)

            if service_options[option]['choice'] == 'custom':
                if service_options[option]['type'] == 'int':
                    if not isinstance(payload[option], int):
                        log_data = {
                            'level': 'ERROR',
                            'user_id': str(request.user.id),
                            'environment_id': payload['clusterID'],
                            'client_request': json.loads(request.body.decode('utf-8')),
                        }
                        logger.error(option + ' parameter is invalid.', extra=log_data)
                        return JsonResponse({
                            'error': {
                                'message': option + ' parameter is invalid.'
                            }
                        }, status=400)
                    else:
                        configuration[option] = payload[option]

                elif service_options[option]['type'] == 'string':
                    if len(payload[option]) < 1:
                        log_data = {
                            'level': 'ERROR',
                            'user_id': str(request.user.id),
                            'environment_id': payload['clusterID'],
                            'client_request': json.loads(request.body.decode('utf-8')),
                        }
                        logger.error(option + ' parameter is invalid.', extra=log_data)
                        return JsonResponse({
                            'error': {
                                'message': option + ' parameter is invalid.'
                            }
                        }, status=400)
                    else:
                        configuration[option] = payload[option]

            elif service_options[option]['choice'] == 'single':
                if payload[option] not in service_options[option]['values']:
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                        'environment_id': payload['clusterID'],
                        'client_request': json.loads(request.body.decode('utf-8')),
                    }
                    logger.error(option + ' parameter is invalid.', extra=log_data)
                    return JsonResponse({
                        'error': {
                            'message': option + ' parameter is invalid.'
                        }
                    }, status=400)
                else:
                    configuration[option] = payload[option]

            elif service_options[option]['choice'] == 'multiple':
                if not isinstance(payload[option], list):
                    log_data = {
                        'level': 'ERROR',
                        'user_id': str(request.user.id),
                        'environment_id': payload['clusterID'],
                        'client_request': json.loads(request.body.decode('utf-8')),
                    }
                    logger.error(option + ' parameter is invalid.', extra=log_data)
                    return JsonResponse({
                        'error': {
                            'message': option + ' parameter is invalid.'
                        }
                    }, status=400)

                for value in payload[option]:
                    if value not in service_options[option]['values']:
                        log_data = {
                            'level': 'ERROR',
                            'user_id': str(request.user.id),
                            'environment_id': payload['clusterID'],
                            'client_request': json.loads(request.body.decode('utf-8')),
                        }
                        logger.error(option + ' parameter is invalid.', extra=log_data)
                        return JsonResponse({
                            'error': {
                                'message': option + ' parameter is invalid.'
                            }
                        }, status=400)

                configuration[option] = payload[option]

    # authorize request
    error = authorization_service.authorize(payload, 'add_service', request.daiteap_user.id, logger)

    if error:
        return error

    # Submit service
    task = tasks.worker_add_service_kubernetes_cluster.delay(
        payload['serviceName'],
        payload['configurationType'],
        configuration,
        cluster.id
    )

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_service(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "minLength": 3,
                "maxLength": 128
            },
            "namespace": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128
            },
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["name", "clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    is_capi = False
    is_yaookcapi = False

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(id=payload['clusterID'])
        if len(cluster) == 0:
            cluster = models.CapiCluster.objects.filter(id=payload['clusterID'])
            if len(cluster) == 0:
                cluster = models.YaookCapiCluster.objects.filter(id=payload['clusterID'])

                is_yaookcapi = True
            else:
                cluster = cluster[0]
                is_capi = True
        else:
            cluster = cluster[0]

        if not cluster.checkUserAccess(request.daiteap_user):
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter clusterID'
                }
            }, status=403)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    if cluster.type != constants.ClusterType.CAPI.value and cluster.type != constants.ClusterType.YAOOKCAPI.value:
        # Check if environment is running
        if cluster.status != 0:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'environment_id': payload['clusterID'],
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Cluster is not running.', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'Cluster is not running.'
                }
            }, status=500)

    # Get cluster's service
    try:
        namespace = ''
        if 'namespace' in payload:
            namespace = payload['namespace']
            if is_capi:
                service = models.ClusterService.objects.filter(
                    name=payload['name'],
                    capi_cluster_id=payload['clusterID'],
                    namespace=payload['namespace'])[0]
            elif is_yaookcapi:
                service = models.ClusterService.objects.filter(
                    name=payload['name'],
                    yaookcapi_cluster_id=payload['clusterID'],
                    namespace=payload['namespace'])[0]
            else:
                service = models.ClusterService.objects.filter(
                    name=payload['name'],
                    cluster_id=payload['clusterID'],
                    namespace=payload['namespace'])[0]
        else:
            if is_capi:
                service = models.ClusterService.objects.filter(
                    name=payload['name'],
                    cluster_id=payload['clusterID'],)[0]
            elif is_yaookcapi:
                service = models.ClusterService.objects.filter(
                    name=payload['name'],
                    yaookcapi_cluster_id=payload['clusterID'])[0]
            else:
                service = models.ClusterService.objects.filter(
                    name=payload['name'],
                    cluster_id=payload['clusterID'],)[0]

    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Service does not exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Service does not exist.'
            }
        }, status=500)

    # Submit service deletion
    task = tasks.worker_delete_service_kubernetes_cluster.delay(payload['name'], namespace, payload['clusterID'])

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def is_cluster_username_free(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "username": {
                "type": "string",
                "pattern": r'^(?=[a-z0-9_]{3,20}$)(?!.*[_]{2})[^_].*[^_]$',
            },
            "clusterId": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            },
        },
        "required": ["username"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterId'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    pattern = re.compile(r'^(?=[a-z0-9_]{3,20}$)(?!.*[_]{2})[^_].*[^_]$')

    cluster_user = payload

    if not pattern.match(cluster_user['username']):
        return JsonResponse({
            'invalid': True
        })

    username = request.user

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(
            project__tenant__daiteapuser__user=username, id=payload['clusterId'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterId'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)

    # check if username already exists

    users = models.ClusterUser.objects.filter(
        cluster = cluster,
        username = cluster_user['username']
    )
    users_count = len(users)

    if users_count >= 1:
        return JsonResponse({
            'free': False
        })

    return JsonResponse({
        'free': True
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def is_cluster_username_valid(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "username": {
                "type": "string",
                "minLength": 3,
                "maxLength": 20
            },
            "clusterId": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            },
        },
        "required": ["username"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterId'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    pattern = re.compile(r'^(?=[a-z0-9_]{3,20}$)(?!.*[_]{2})[^_].*[^_]$')

    cluster_user = payload

    if not pattern.match(cluster_user['username']):
        return JsonResponse({
            'valid': False
        })

    return JsonResponse({
        'valid': True
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_user_to_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "username": {
                "type": "string",
                "pattern": r'^(?=[a-z0-9_]{3,20}$)(?!.*[_]{2})[^_].*[^_]$'
            },
            "firstName": {
                "type": "string",
                "maxLength": 23
            },
            "lastName": {
                "type": "string",
                "maxLength": 23
            },
            "email": {
                "type": "string",
                "maxLength": 150,
                "pattern": r'^$|(?:[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])'
            },
            "publicSSHKey": {
                "type": "string",
                "minLength": 20,
                "maxLength": 10000,
                "pattern": r'AAAAB3NzaC1yc2E|AAAAC3NzaC1lZDI1NTE5AAAAI',
            },
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            },
            "kubernetesUser": {
                "type": "boolean",
            }
        },
        "required": ["username", "publicSSHKey", "clusterID", "kubernetesUser"],
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        if 'does not match \'AAAAB3NzaC1yc2E|AAAAC3NzaC1lZDI1NTE5AAAAI\'' in str(e):
            e.message = 'Invalid public SSH key format'

        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
                'code': 1000
            }
        }, status=400)

    username = request.user

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(project__tenant__daiteapuser__user=username, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID',
                'code': 1001
            }
        }, status=500)

    # Check if environment is running
    if cluster.status != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is not running.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is not running.'
            }
        }, status=500)

    cluster_user = payload

    # check if username already exists
    users = models.ClusterUser.objects.filter(
        cluster = cluster,
        username = cluster_user['username']
    )
    users_count = len(users)

    if users_count >= 1:
        return JsonResponse({
            'error': {
                'message': 'Username already taken',
                'code': 1002
            }
        }, status=400)

    # authorize request
    error = authorization_service.authorize(payload, 'add_user_to_cluster', request.daiteap_user.id, logger)

    if error:
        return error

    user_password = get_random_alphanumeric_string(30)

    cluster_user['user_password'] = user_password

    userType = 'user, kubernetes user' if cluster_user['kubernetesUser']==1 else 'user'

    # Create cluster user db record
    new_cluster_user = models.ClusterUser(
        cluster=cluster,
        username=cluster_user['username'],
        first_name=cluster_user['firstName'],
        last_name=cluster_user['lastName'],
        type=userType,
        email=cluster_user['email'],
        public_ssh_key=cluster_user['publicSSHKey'],
        kubernetes_user=cluster_user['kubernetesUser'],
        status=1
    )
    new_cluster_user.save()

    if cluster_user['kubernetesUser']:
        config = yaml.safe_load(cluster.kubeconfig)

        kubeconfig = '''apiVersion: v1
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: {0}
  name: cluster.local
contexts:
- context:
    cluster: cluster.local
    user: {1}
  name: kubernetes
current-context: kubernetes
kind: Config
preferences: {{}}
users:
- name: {1}
  user:
    token: {1}:{2}
'''.format(config["clusters"][0]["cluster"]["server"],
           cluster_user['username'],
           user_password)
        
        new_cluster_user.kubeconfig = kubeconfig
        new_cluster_user.save()

    # Submit cluster user creation
    task = tasks.worker_create_cluster_user.delay(cluster_user, cluster.id, request.user.id)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_user_from_cluster(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "username": {
                "type": "string",
                "minLength": 2,
                "maxLength": 50
            },
            "clusterID": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["username", "clusterID"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    username = request.user

    # Get user's cluster
    try:
        cluster = models.Clusters.objects.filter(
            project__tenant__daiteapuser__user=username, id=payload['clusterID'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter clusterID', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter clusterID'
            }
        }, status=500)
    
    # Check if environment is running
    if cluster.status != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Cluster is not running.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Cluster is not running.'
            }
        }, status=500)

    # Get cluster's user
    try:
        cluster_user = models.ClusterUser.objects.filter(
            cluster=cluster,
            username=payload['username'])[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'environment_id': payload['clusterID'],
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('ClusterUser does not exist.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'ClusterUser does not exist.'
            }
        }, status=500)

    # Submit cluster user deletion
    task = tasks.worker_delete_cluster_user.delay(cluster_user.username, cluster.id, request.user.id, payload)

    # Remove user old entries
    old_celerytasks = models.CeleryTask.objects.filter(user=request.user, created_at__lte=(timezone.now()-timedelta(hours=1)))
    old_celerytasks.delete()

    # Create new entry
    celerytask = models.CeleryTask(user=request.user, task_id=task.id)
    celerytask.save()

    return JsonResponse({
        'taskId': celerytask.id
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def can_update_user_password(request):
    keycloak = KeycloakConnect(server_url=KEYCLOAK_CONFIG['KEYCLOAK_SERVER_URL'],
                                realm_name=KEYCLOAK_CONFIG['KEYCLOAK_REALM'],
                                client_id=KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_ID'],
                                client_secret_key=KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_SECRET_KEY'])

    keycloak_user = keycloak.getuser(request.user.username)
    can_update_password = True

    if 'attributes' in keycloak_user and 'social_provider' in keycloak_user['attributes']:
        can_update_password = False

    return JsonResponse({
        'canUpdateUserPassword': can_update_password
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_user_password(request):
    request_body, error = get_request_body(request)
    if error is not None:
        return error

    if request_body == {}:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Missing request data', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Missing request data',
            }
        }, status=400)

    schema = {
        "type": "object",
        "properties": {
            "current_password": {
                "type": "string",
                "minLength": 2,
                "maxLength": 150
            },
            "new_password": {
                "type": "string",
                "minLength": 6,
                "maxLength": 100
            },
            "new_password_confirmation": {
                "type": "string",
                "minLength": 6,
                "maxLength": 100
            }
        }
    }

    try:
        validate(instance=request_body, schema=schema)
    except ValidationError as e:
        if 'is too short' in str(e):
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('New password is too short', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'New password is too short',
                }
            }, status=400)
        else:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('New password is invalid', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'New password is invalid',
                }
            }, status=400)

    current_password = request_body['current_password']
    new_password = request_body['new_password']
    new_password_confirmation = request_body['new_password_confirmation']

    if new_password != new_password_confirmation:
        error_massage = 'Password confirmation doesn\'t match Password'
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(error_massage, extra=log_data)
        return JsonResponse({
            'error': {
                'message': error_massage
            }
        }, status=400)

    keycloak = KeycloakConnect(server_url=KEYCLOAK_CONFIG['KEYCLOAK_SERVER_URL'],
                                realm_name=KEYCLOAK_CONFIG['KEYCLOAK_REALM'],
                                client_id=KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_ID'],
                                client_secret_key=KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_SECRET_KEY'])

    try:
        keycloak.checkUserCredentials(request.user.username, current_password)
    except:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid password', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid password'
            }
        }, status=401)

    keycloak_user = keycloak.getuser(request.user.username)
    if 'attributes' in keycloak_user and 'social_provider' in keycloak_user['attributes']:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Changing password is forbidden.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Changing password is forbidden.',
            }
        }, status=400)
    response = keycloak.resetpassword(keycloak_user['id'], new_password)

    return JsonResponse({
        'submitted': True
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.TenantAccessPermission])
def get_usage(request, tenant_id):
    daiteap_user = models.DaiteapUser.objects.get(user=request.user, tenant_id=tenant_id)

    quota_limits = authorization_service.get_quota_limits(daiteap_user.id)

    used_quota = authorization_service.get_used_quota(daiteap_user.id)

    response_json = quota_limits

    response_json['used_compute_vms_environments'] = used_quota['compute_vms_environments']
    response_json['used_kubernetes_cluster_environments'] = used_quota['kubernetes_cluster_environments']
    response_json['used_nodes'] = used_quota['nodes']
    response_json['used_services'] = used_quota['services']

    return JsonResponse(response_json)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_active_tenants(request):
    daiteap_users = models.DaiteapUser.objects.filter(user=request.user)

    tenants = []

    if len(daiteap_users) > 0:
        for user in daiteap_users:
            if user.tenant is not None:
                tenants.append({
                    'id': user.tenant_id,
                    'name': user.tenant.name,
                    'owner': user.tenant.owner,
                    'email': user.tenant.email,
                    'phone': user.tenant.phone,
                    'company': user.tenant.company,
                    'status': user.tenant.status,
                    'createdAt': user.tenant.created_at,
                    'updatedAt': user.tenant.updated_at,
                    'selected': user.selected
                })

    return JsonResponse({
        "activeTenants": tenants,
        "selectedTenant": request.daiteap_user.tenant_id
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def select_tenant(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "selectedTenant": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": ["selectedTenant"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    daiteap_users = models.DaiteapUser.objects.filter(user=request.user)
    if len(daiteap_users) > 0:
        for user in daiteap_users:
            if user.selected and str(user.tenant_id) != payload['selectedTenant']:
                user.selected = False
                user.save()
            if str(user.tenant_id) == payload['selectedTenant']:
                user.selected = True
                user.save()

    return JsonResponse({'submitted': True})

@api_view(['GET', 'DELETE', 'PUT'])
@permission_classes([IsAuthenticated])
def user_profile_picture(request):
    if request.method == 'GET':
        try:
            profile = request.user.profile

            if not profile.picture:
                return JsonResponse({'location': ''}, status=200)
            return JsonResponse({'location': settings.MEDIA_URL + str(profile.picture)}, status=200)
        except Exception as e:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error(str(e), extra=log_data)
            return JsonResponse({
                'error': {
                    'message': str(e)
                }
            }, status=400)

    if request.method == 'DELETE':
        profile = request.user.profile
        profile.picture.delete()
        profile.save()

        return JsonResponse({
                'done': True
            }, status=200)

    if request.method == 'PUT':
        if 'CONTENT_TYPE' not in request.META:
            return None, HttpResponse('Your POST request must have the header \"Content-type: multipart/form-data\" as well as a valid payload\n', status=400)
        if 'multipart/form-data' not in request.META['CONTENT_TYPE']:
            return None, HttpResponse('Your POST request must have the header \"Content-type: multipart/form-data\" as well as a valid payload\n', status=400)

        if 'picture' not in request.FILES:
            return JsonResponse({'error': {'message': 'Missing form parameter \"picture\"'}}, status=400)

        picture = request.FILES['picture']

        try:
            im = Image.open(picture)
            im.verify()
        except Exception as e:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error(str(e), extra=log_data)
            return JsonResponse({
                'error': {
                    'message': str(e)
                }
            }, status=400)

        profile = request.user.profile
        try:
            current = profile.picture
            if current != picture:
                current.delete(save=False)
        except: pass

        if 'image/' not in picture.content_type:
            return JsonResponse({'error': {'message': 'Invalid image type'}}, status=400)

        profile.picture = picture
        profile.save()

        return JsonResponse({'submitted': True})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def save_environment_template(request):
    request_body, error = get_request_body(request)
    if error is not None:
        return error

    if request_body == {}:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Missing request data', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Missing request data',
            }
        }, status=400)

    schema = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1024
            },
            "environmentId": {
                "type": "string",
                "minLength": 20,
                "maxLength": 60
            }
        },
        "required": ["environmentId", "name"]
    }

    try:
        validate(instance=request_body, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    # check if name is occupied by other environment
    env_template_with_same_name = models.EnvironmentTemplate.objects.filter(
        tenant_id=request.daiteap_user.tenant_id, name=request_body['name'].strip()).count()
    if env_template_with_same_name != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Environment template with that name already exists', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Environment template with that name already exists'
            }
        }, status=400)

    environment_id = request_body['environmentId']

    try:
        cluster = models.Clusters.objects.filter(project__tenant_id=request.daiteap_user.tenant_id, id=environment_id)

        if not cluster:
            cluster = models.CapiCluster.objects.filter(project__tenant_id=request.daiteap_user.tenant_id, id=environment_id)[0]
            if not cluster:
                cluster =models.YaookCapiCluster.objects.filter(project__tenant_id=request.daiteap_user.tenant_id, id=environment_id)[0]
        else:
            cluster = cluster[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('Invalid parameter environmentId', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter environmentId'
            }
        }, status=400)

    daiteap_user=request.daiteap_user
    tenant_id=daiteap_user.tenant_id

    if cluster.type == constants.ClusterType.CAPI.value:
        environment_template = models.EnvironmentTemplate(
            name = request_body['name'],
            config = cluster.capi_config,
            providers = cluster.providers,
            type = cluster.type,
            tenant_id = tenant_id
        )
    if cluster.type == constants.ClusterType.YAOOKCAPI.value:
        environment_template = models.EnvironmentTemplate(
            name = request_body['name'],
            config = cluster.yaookcapi_config,
            providers = cluster.providers,
            type = cluster.type,
            tenant_id = tenant_id
        )
    else:
        environment_template = models.EnvironmentTemplate(
            name = request_body['name'],
            config = cluster.config,
            providers = cluster.providers,
            type = cluster.type,
            tenant_id = tenant_id
        )

    if request_body['description']:
        environment_template.description = request_body['description']

    environment_template.contact = request.user.email
    environment_template.save()

    return HttpResponse(status=201)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_environment_template(request):
    request_body, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1024
            },
            "type": {
                "type": "number",
                "minValue": 1,
                "maxValue": 6
            },
            "description": {
                "type": "string",
                "maxLength": 1024
            },
        },
        "required": ["type", "name"]
    }

    try:
        validate(instance=request_body, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    if request_body['type'] == constants.ClusterType.CAPI.value:
        schema = constants.CREATE_CAPI_INPUT_VALIDATION_SCHEMA
        schema['required'] = ["clusterName", "kubernetesConfiguration"]
    elif request_body['type'] == constants.ClusterType.CAPI.value:
        schema = constants.CREATE_YAOOKCAPI_INPUT_VALIDATION_SCHEMA
        schema['required'] = ["clusterName", "kubernetesConfiguration"]
    elif request_body['type'] == constants.ClusterType.DLCM.value:
        schema = constants.CREATE_KUBERNETES_INPUT_VALIDATION_SCHEMA
        schema['required'] = ["clusterName", "kubernetesConfiguration", "internal_dns_zone"]
    elif request_body['type'] == constants.ClusterType.K3S.value:
        schema = constants.CREATE_K3S_INPUT_VALIDATION_SCHEMA
        schema['required'] = ["clusterName", "kubernetesConfiguration", "internal_dns_zone"]
    elif request_body['type'] == constants.ClusterType.VMS.value or request_body['type'] == constants.ClusterType.COMPUTE_VMS.value:
        schema = constants.CREATE_VMS_INPUT_VALIDATION_SCHEMA
        schema['required'] = ["clusterName", "internal_dns_zone"]

    try:
        validate(instance=request_body, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    if request_body['type'] == constants.ClusterType.CAPI.value:
        if request_body['kubernetesConfiguration']['version'] not in SUPPORTED_CAPI_KUBERNETES_VERSIONS:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Invalid parameter kubernetes version',
                         extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter kubernetes version'
                }
            }, status=400)

    if request_body['type'] == constants.ClusterType.YAOOKCAPI.value:
        if request_body['kubernetesConfiguration']['version'] not in SUPPORTED_YAOOKCAPI_KUBERNETES_VERSIONS:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Invalid parameter kubernetes version',
                         extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter kubernetes version'
                }
            }, status=400)

    if request_body['type'] == constants.ClusterType.K3S.value:
        if request_body['kubernetesConfiguration']['version'] not in SUPPORTED_K3S_VERSIONS:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Invalid parameter kubernetes version', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter kubernetes version'
                }
            }, status=400)

        if request_body['kubernetesConfiguration']['networkPlugin'] not in SUPPORTED_K3S_NETWORK_PLUGINS:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
                'client_request': json.loads(request.body.decode('utf-8')),
            }
            logger.error('Invalid parameter ', extra=log_data)
            return JsonResponse({
                'error': {
                    'message': 'Invalid parameter network plugin'
                }
            }, status=400)

    if request_body['type'] == constants.ClusterType.K3S.value or request_body['type'] == constants.ClusterType.DLCM.value:
        networks = environment_providers.get_providers_networks(request_body)
        networks.append(request_body['kubernetesConfiguration']['serviceAddresses'])
        networks.append(request_body['kubernetesConfiguration']['podsSubnet'])

        error = check_ip_addresses(networks)

        if error:
            return error

    if not environment_providers.check_if_at_least_one_provider_is_selected(request_body):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error('No provider is selected.', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'No provider is selected.'
            }
        }, status=400)

    try:
        environment_providers.validate_regions_zones_instance_types(
            request_body, request.user, request_body['type'])
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e)
            }
        }, status=400)

    if request_body['type'] == constants.ClusterType.CAPI.value:
        cluster_config = {
            'kubernetesConfiguration': request_body['kubernetesConfiguration'],
        }

        cluster_config.update(environment_providers.get_providers_yaookcapi_config_params(
            request_body, request.user))

    elif request_body['type'] in [constants.ClusterType.DLCM.value, constants.ClusterType.K3S.value, constants.ClusterType.DLCM_V2.value]:
        cluster_config = {
            'kubernetesConfiguration': request_body['kubernetesConfiguration'],
            'internal_dns_zone': request_body['internal_dns_zone'],
        }

        if 'load_balancer_integration' in request_body and len(request_body['load_balancer_integration']) > 0:
            cluster_config['load_balancer_integration'] = request_body['load_balancer_integration']

        cluster_config.update(environment_providers.get_providers_config_params(request_body, request.user))

    elif request_body['type'] in [constants.ClusterType.VMS.value, constants.ClusterType.COMPUTE_VMS.value]:
        cluster_config = {
            'internal_dns_zone': request_body['internal_dns_zone']
        }

        cluster_config.update(environment_providers.get_providers_config_params(request_body, request.user))

    env_template_with_same_name = models.EnvironmentTemplate.objects.filter(
        tenant_id=request.daiteap_user.tenant_id, name=request_body['name'].strip()).count()
    if env_template_with_same_name != 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(
            'Environment template with that name already exists', extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Environment template with that name already exists'
            }
        }, status=400)

    daiteap_user = request.daiteap_user
    tenant_id = daiteap_user.tenant_id

    is_capi = False
    is_yaookcapi = False
    if request_body['type'] == constants.ClusterType.CAPI.value:
        is_capi = True
    if request_body['type'] == constants.ClusterType.YAOOKCAPI.value:
        is_yaookcapi = True

    environment_template = models.EnvironmentTemplate(
        name=request_body['name'],
        config=json.dumps(cluster_config),
        providers=json.dumps(environment_providers.get_selected_providers(request_body)),
        type=request_body['type'],
        tenant_id=tenant_id
    )

    if request_body['description']:
        environment_template.description = request_body['description']

    environment_template.daiteap_user = daiteap_user
    environment_template.contact = daiteap_user.user.email

    environment_template.save()

    tasks.worker_set_template_user_friendly_params.delay(environment_template.id)

    return HttpResponse(status=201)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_environment_templates(request):
    try:
        environment_templates = models.EnvironmentTemplate.objects.filter(tenant__daiteapuser=request.daiteap_user)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Internal server error'
            }
        }, status=500)

    response = {'environmentTemplates': []}

    for environment_template in environment_templates:
        if environment_template.checkUserAccess(request.daiteap_user):
            response['environmentTemplates'].append({
                'name': environment_template.name,
                'id': environment_template.id,
                'created_at': environment_template.created_at,
                'type': environment_template.type,
                'providers': environment_template.providers,
                'description': environment_template.description,
                'contact': environment_template.contact,
            })

    return JsonResponse(response, status=200)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_environment_template(request, environmentTemplateId):
    payload = {
        'environmentTemplateId': environmentTemplateId
    }

    schema = {
        "type": "object",
        "properties": {
            "environmentTemplateId": {
                "type": "string",
                "minLength": 20,
                "maxLength": 60
            },
        },
        "required": ["environmentTemplateId"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    environment_template_id = payload['environmentTemplateId']

    try:
        environment_template = models.EnvironmentTemplate.objects.filter(id=environment_template_id)[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter environmentTemplateId'
            }
        }, status=400)

    if not environment_template.checkUserAccess(request.daiteap_user):
        return JsonResponse({
            'error': {
                'message': 'Access denied'
            }
        }, status=403)        

    config = json.loads(environment_template.config)

    response = {
        'name': environment_template.name,
        'id': environment_template.id,
        'created_at': environment_template.created_at,
        'contact': environment_template.contact,
        'description': environment_template.description,
        'type': environment_template.type,
        'providers': environment_template.providers,
        'config': config,
    }

    return JsonResponse(response, status=200)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_environment_template(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "environmentTemplateId": {
                "type": "string",
                "minLength": 20,
                "maxLength": 60
            },
        },
        "required": ["environmentTemplateId"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    environment_template_id = payload['environmentTemplateId']

    try:
        environment_template = models.EnvironmentTemplate.objects.filter(id=environment_template_id)[0]
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Invalid parameter environmentTemplateId'
            }
        }, status=400)

    if not environment_template.checkUserAccess(request.daiteap_user):
        return JsonResponse({
            'error': {
                'message': 'Access denied'
            }
        }, status=403)        

    try:
        environment_template.delete()
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': 'Internal server error'
            }
        }, status=400)

    return JsonResponse({
        'submitted': True
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def is_environment_template_name_free(request):
    # Validate request
    payload, error = get_request_body(request)
    if error:
        return error

    schema = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1024
            }
        },
        "required": ["name"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
            'client_request': json.loads(request.body.decode('utf-8')),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    # check if name is occupied by other environment
    env_template_with_same_name = models.EnvironmentTemplate.objects.filter(
        tenant_id=request.daiteap_user.tenant_id,
        name=payload['name']
        .strip()).count()
    if env_template_with_same_name != 0:
        return JsonResponse({
            'free': False
        })

    return JsonResponse({
        'free': True
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_timezones(_):

    timezones = []

    for tz in pytz.common_timezones:
        tz_info = ({'name': tz, 'offset': datetime.datetime.now(pytz.timezone(tz)).strftime('%z')})
        timezones.append(tz_info)

    response = {'timezones': timezones}

    return JsonResponse(response, status=200)

def _add_user_to_tenant(tenantId, request):
    request_body, error = get_request_body(request)

    try:
        user = models.User.objects.filter(username=request_body['username'])[0]
        news_subscribbed = models.DaiteapUser.objects.all()[0].user.profile.news_subscribbed
    except:
        user=models.User.objects.create_user(request_body['username'])
        user.first_name = request_body['firstname']
        user.last_name = request_body['lastname']
        user.email = request_body['email']
        user.save()

        keycloak = KeycloakConnect(server_url=KEYCLOAK_CONFIG['KEYCLOAK_SERVER_URL'],
                                realm_name=KEYCLOAK_CONFIG['KEYCLOAK_REALM'],
                                client_id=KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_ID'],
                                client_secret_key=KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_SECRET_KEY'])

        keycloak_user = keycloak.getuser(request_body['username'])
        news_subscribbed = True

        if 'attributes' in keycloak_user and 'no_news' in keycloak_user['attributes']:
            news_subscribbed = False

    daiteapuser=models.DaiteapUser.objects.create(user_id=user.id, tenant_id=tenantId)
    daiteapuser.save()
    profile = daiteapuser.user.profile
    if 'company' in request_body:
        profile.company  = request_body['company']
    if 'phone' in request_body:
        profile.phone = request_body['phone']
    profile.sshpubkey = request_body['sshpubkey']
    daiteapuser.role = request_body['userRole']
    daiteapuser.save()
    profile.news_subscribbed = news_subscribbed
    profile.save()

    userconfiguration = models.UserConfiguration.objects.create(daiteap_user=daiteapuser)
    userconfiguration.account_type = daiteapuser.role
    userconfiguration.limit_kubernetes_cluster_environments=20
    userconfiguration.limit_compute_vms_environments=50
    userconfiguration.limit_nodes=200
    userconfiguration.limit_services=50
    userconfiguration.save()

    sync_users()

    return JsonResponse({'user_created': True})

def _delete_user_from_tenant(tenantId, request):
    request_body, error = get_request_body(request)
    username = request_body['username']
    user=models.User.objects.filter(username=username)[0]
    daiteapuser=models.DaiteapUser.objects.filter(user=user, tenant_id=tenantId)[0]

    user_clusters = models.Clusters.objects.filter(daiteap_user_id=daiteapuser)
    user_capi_clusters = models.CapiCluster.objects.filter(daiteap_user_id=daiteapuser)
    user_yaookcapi_clusters = models.YaookCapiCluster.objects.filter(daiteap_user_id=daiteapuser)

    # Check if user has asociated clusters
    if len(user_clusters) > 0 or len(user_capi_clusters) > 0 or len(user_yaookcapi_clusters) > 0:
        return JsonResponse({
            'delete_success': False,
            'message': 'User cannot be deleted because it has clusters associated with it.'
        }, status=400)

    # remove
    for p in daiteapuser.projects.all():
        daiteapuser.projects.remove(p)

    # dereference CloudAccounts (deleting might cause issues with resources)
    for account in models.CloudAccount.objects.filter(user=user, tenant_id=tenantId):
        account.user = None
        account.save()

    daiteapuser.delete()

    if models.DaiteapUser.objects.filter(user=user).count() < 1:
        user.delete()

    sync_users()

    return JsonResponse({'delete_success': True})

@api_view(['POST'])
@permission_classes([IsAuthenticated,custom_permissions.IsAdmin])
def add_newuser(request):
    return _add_user_to_tenant(request.daiteap_user.tenant_id, request)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_userslist(request):
    userslist = []
    daiteapuser = request.daiteap_user
    if not daiteapuser.isAdmin():
        return JsonResponse({'users_list': []})

    tenant=models.Tenant.objects.filter(daiteapuser=daiteapuser)[0]
    users = models.DaiteapUser.objects.filter(tenant_id=tenant.id)
    for daiteap_user in users:
        profile = daiteap_user.user.profile
        userslist.append({
            'username': daiteap_user.user.username,
            'firstname': daiteap_user.user.first_name,
            'lastname': daiteap_user.user.last_name,
            'projects': list(daiteap_user.projects.all().values_list('name', flat=True)),
            'email': daiteap_user.user.email,
            'role': daiteap_user.role,
            'phone': daiteap_user.user.profile.phone,
            'company': profile.company,
            'id': daiteap_user.user.id,
        })

    return JsonResponse({'users_list': userslist})

@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.IsAdmin])
def get_unregistered_users(request, tenant_id):
    keycloak = KeycloakConnect(server_url=KEYCLOAK_CONFIG['KEYCLOAK_SERVER_URL'],
                                realm_name=KEYCLOAK_CONFIG['KEYCLOAK_REALM'],
                                client_id=KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_ID'],
                                client_secret_key=KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_SECRET_KEY'])

    response = keycloak.userslist()
    platform_users = []

    for user in response:
        platform_user = {
            'username': user['username'],
            'email': user['email'],
            'firstName': '',
            'lastName': ''
        }
        if 'firstName' in user:
            platform_user['firstName'] = user['firstName']
        if 'lastName' in user:
            platform_user['lastName'] = user['lastName']
        
        platform_users.append(platform_user)

    all_tenant_users = models.DaiteapUser.objects.filter(tenant_id=tenant_id).values('user__username')
    all_tenant_users = [user['user__username'] for user in all_tenant_users]

    unregisteredUsers = []

    for user in platform_users:
        if user['username'] not in all_tenant_users:
            unregisteredUsers.append(user)

    return JsonResponse({'unregisteredUsers': unregisteredUsers})


@api_view(['GET'])
def is_registered(request):
    if hasattr(request, 'userinfo') and request.userinfo and request.user:
        return JsonResponse({'isRegistered': True})
    else:
        return JsonResponse({'isRegistered': False})


@api_view(['POST'])
@permission_classes([custom_permissions.IsUnregistered])
def register_tenant_user(request):
    # create user
    user=models.User.objects.create_user(request.userinfo['preferred_username'])
    if 'given_name' in request.userinfo:
        user.first_name = request.userinfo['given_name']
    if 'family_name' in request.userinfo:
        user.last_name = request.userinfo['family_name']
    user.email = request.userinfo['email']
    user.save()

    # create a tenant
    tenant=models.Tenant.objects.create()
    tenant.name = request.userinfo['preferred_username']
    tenant.owner = request.userinfo['preferred_username']
    tenant.email = request.userinfo['email']

    tenant.save()
    tenant_settings=models.TenantSettings.objects.create(tenant=tenant)
    tenant_settings.save()

    # create daiteap user
    daiteapuser=models.DaiteapUser.objects.create(user_id=user.id, tenant_id=tenant.id, selected=True)
    profile = daiteapuser.user.profile
    daiteapuser.role = 'RegularUser'
    daiteapuser.save()
    keycloak = KeycloakConnect(server_url=KEYCLOAK_CONFIG['KEYCLOAK_SERVER_URL'],
                                realm_name=KEYCLOAK_CONFIG['KEYCLOAK_REALM'],
                                client_id=KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_ID'],
                                client_secret_key=KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_SECRET_KEY'])

    keycloak_user = keycloak.getuser(request.userinfo['preferred_username'])
    news_subscribbed = True

    if 'attributes' in keycloak_user and 'no_news' in keycloak_user['attributes']:
        news_subscribbed = False
    
    profile.news_subscribbed = news_subscribbed
    profile.save()

    userconfiguration = models.UserConfiguration.objects.create(daiteap_user=daiteapuser)
    userconfiguration.account_type = daiteapuser.role
    userconfiguration.limit_kubernetes_cluster_environments=20
    userconfiguration.limit_compute_vms_environments=50
    userconfiguration.limit_nodes=200
    userconfiguration.limit_services=50
    userconfiguration.save()

    sync_users()

    if not settings.DEBUG:
        email_client = MailgunClient()
        email_client.email_welcome_message(user.id)

    return JsonResponse({'user_created': True})

@api_view(['POST'])
@permission_classes([IsAuthenticated,custom_permissions.IsAdmin])
def delete_user(request):
    return _delete_user_from_tenant(request.daiteap_user.tenant_id, request)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, custom_permissions.ProjectAccessPermission])
def project_users(request, tenant_id, project_id):
    project = models.Project.objects.get(id=project_id)

    if request.method == 'GET':
        userslist = []
        users = models.DaiteapUser.objects.filter(projects__id=project_id)
        project_owner = project.user

        for daiteap_user in users:
            role = ""
            if daiteap_user.user.id == project_owner.id:
                role = "Owner"
            else:
                role = daiteap_user.role

            userslist.append({
                'username': daiteap_user.user.username,
                'firstname': daiteap_user.user.first_name,
                'lastname': daiteap_user.user.last_name,
                'projects': list(daiteap_user.projects.all().values_list('name', flat=True)),
                'email': daiteap_user.user.email,
                'role': role,
                'phone': daiteap_user.user.profile.phone,
            })

        return JsonResponse({'users_list': userslist})

    if request.method == 'POST':
        payload, error = get_request_body(request)
        if error:
            return error

        username = payload['username']
        try:
            daiteapuser = models.DaiteapUser.objects.get(user__username=username,tenant_id=tenant_id)
        except models.DaiteapUser.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        daiteapuser.projects.add(project)
        daiteapuser.save()

        sync_users()

        return JsonResponse({'success': True})

@api_view(['DELETE'])
@permission_classes([IsAuthenticated, custom_permissions.ProjectAccessPermission])
def project_users_detail(request, tenant_id, project_id, username):
    project = models.Project.objects.get(id=project_id, tenant_id=tenant_id)

    try:
        daiteapuser = models.DaiteapUser.objects.get(user__username=username,tenant_id=tenant_id)
    except models.DaiteapUser.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

    daiteapuser.projects.remove(project)
    daiteapuser.save()

    sync_users()

    return JsonResponse({'success': True})

def sync_users(task_delay=True):
    print("Syncing users")

    # find out which users must be assigned to which resources
    for project in models.Project.objects.all():
        # get all DaiteapUser members in the project
        daiteap_users = models.DaiteapUser.objects.filter(projects__id=project.id)

        # get all clusters in the projects
        clusters = models.Clusters.objects.filter(project_id=project.id)

        # get all CAPI clusters in the project
        capiclusters = models.CapiCluster.objects.filter(project_id=project.id)

        # get all YaookCAPI clusters in the project
        yaookcapiclusters = models.YaookCapiCluster.objects.filter(project_id=project.id)

        for daiteap_user in daiteap_users:
            for cluster in clusters:
                gw_address = models.Machine.objects.filter(cluster=cluster).exclude(publicIP=None)[0].publicIP
                synchronized_machines = daiteap_user.user.profile.ssh_synchronized_machines.all()

                if cluster.type in [constants.ClusterType.VMS.value, constants.ClusterType.COMPUTE_VMS.value]:
                    cluster_machines = models.Machine.objects.filter(cluster_id=cluster.id, status=0)

                    for machine in cluster_machines:
                        if machine not in synchronized_machines:
                            if daiteap_user.user.profile.sshpubkey:
                                if task_delay:
                                    tasks.create_vm_user.delay(daiteap_user.id, cluster.id, machine.id, daiteap_user.user.profile.sshpubkey, daiteap_user.user.username, gw_address)
                                else:
                                    tasks.create_vm_user(daiteap_user.id, cluster.id, machine.id, daiteap_user.user.profile.sshpubkey, daiteap_user.user.username, gw_address)
                            else:
                                if task_delay:
                                    tasks.delete_vm_user.delay(daiteap_user.id, cluster.id, machine.id, daiteap_user.user.username, gw_address)
                                else:
                                    tasks.delete_vm_user(daiteap_user.id, cluster.id, machine.id, daiteap_user.user.username, gw_address)

            for cluster in capiclusters:
                u = models.SynchronizedUsers.objects.filter(daiteapuser=daiteap_user, capicluster=cluster)
                if len(u) == 0:
                    if cluster.type == constants.ClusterType.CAPI.value and cluster.installstep == 0:
                        tasks.create_kubernetes_user.delay(daiteap_user.id, cluster.id, daiteap_user.user.username, cluster.kubeconfig, cluster.type)

                        new_sync_user = models.SynchronizedUsers(daiteapuser=daiteap_user, capicluster=cluster)
                        new_sync_user.save()

            for cluster in yaookcapiclusters:
                cluster.resizestep = 1
                cluster.save()
                tasks.worker_update_yaookcapi_cluster_wireguard_peers.delay(cluster.id, cluster.user.id)

                u = models.SynchronizedUsers.objects.filter(daiteapuser=daiteap_user, yaookcluster=cluster)
                if len(u) == 0:
                    if cluster.type == constants.ClusterType.CAPI.value and cluster.installstep == 0:
                        tasks.create_kubernetes_user.delay(daiteap_user.id, cluster.id, daiteap_user.user.username, cluster.kubeconfig, cluster.type)

                        new_sync_user = models.SynchronizedUsers(daiteapuser=daiteap_user, yaookcluster=cluster)
                        new_sync_user.save()

        kubernetes_users_for_deletion = models.SynchronizedUsers.objects.filter(cluster__in=clusters).exclude(daiteapuser__in=daiteap_users)
        capi_users_for_deletion = models.SynchronizedUsers.objects.filter(capicluster__in=capiclusters).exclude(daiteapuser__in=daiteap_users)
        yaookcapi_users_for_deletion = models.SynchronizedUsers.objects.filter(yaookcluster__in=yaookcapiclusters).exclude(daiteapuser__in=daiteap_users)

        for cluster_user in kubernetes_users_for_deletion:
            cluster = cluster_user.cluster
            if cluster.status == 0 and cluster.installstep == 0 and len(models.Machine.objects.filter(cluster=cluster).exclude(status=0)) == 0:
                if cluster.type in [constants.ClusterType.DLCM.value, constants.ClusterType.K3S.value]:
                    tasks.delete_kubernetes_user.delay(daiteap_user.id, cluster.id, cluster_user.daiteapuser.user.username, cluster.kubeconfig, cluster.type)

                elif cluster.type in [constants.ClusterType.VMS.value, constants.ClusterType.COMPUTE_VMS.value] and cluster_user.daiteapuser.user.profile.sshpubkey:
                    gw_address = models.Machine.objects.filter(cluster=cluster).exclude(publicIP=None)[0].publicIP
                    nodes_addresses = [i['privateIP'] for i in models.Machine.objects.filter(cluster=cluster).values("privateIP")]

                    tasks.delete_vm_user.delay(daiteap_user.id, cluster.id, nodes_addresses, cluster_user.daiteapuser.user.username, gw_address)

                cluster_user.delete()

        for cluster_user in capi_users_for_deletion:
            cluster = cluster_user.capicluster

            if cluster.type == constants.ClusterType.CAPI.value and cluster.installstep == 0:
                tasks.delete_kubernetes_user.delay(daiteap_user.id, cluster.id, cluster_user.daiteapuser.user.username, cluster.kubeconfig, cluster.type)

            cluster_user.delete()


        for cluster_user in yaookcapi_users_for_deletion:
            cluster = cluster_user.yaookcluster

            if cluster.type == constants.ClusterType.CAPI.value and cluster.installstep == 0:
                tasks.delete_kubernetes_user.delay(daiteap_user.id, cluster.id, cluster_user.daiteapuser.user.username, cluster.kubeconfig, cluster.type)

            cluster_user.delete()

    return True


@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.TenantAccessPermission])
def account_tenant(request, tenant_id):
    tenant = models.Tenant.objects.filter(id=tenant_id).values('id', 'name', 'company')[0]

    return JsonResponse({'tenant': tenant})


@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.TenantAccessPermission])
def account_get_settings(request, tenant_id):
    tenant = models.Tenant.objects.get(id=tenant_id)

    account = {
        'name': tenant.name,
        'owner': tenant.owner,
        'email': tenant.email,
        'phone': tenant.phone,
        'company': tenant.company,
        'status': tenant.status,
    }

    settings = models.TenantSettings.objects.get(tenant=tenant)
    account_settings = {
        'enable_compute': settings.enable_compute,
        'enable_storage': settings.enable_storage,
        'enable_service_catalog': settings.enable_service_catalog,
        'enable_templates': settings.enable_templates,
        'enable_kubernetes_dlcm': settings.enable_kubernetes_dlcm,
        'enable_kubernetes_k3s': settings.enable_kubernetes_k3s,
        'enable_kubernetes_capi': settings.enable_kubernetes_capi,
        'enable_kubernetes_yaookcapi': settings.enable_kubernetes_yaookcapi,
        'advanced_cluster_configuration': settings.advanced_cluster_configuration,
        'enable_cluster_resize': settings.enable_cluster_resize,
        'providers_enable_gcp': settings.providers_enable_gcp,
        'providers_enable_aws': settings.providers_enable_aws,
        'providers_enable_ali': settings.providers_enable_ali,
        'providers_enable_azure': settings.providers_enable_azure,
        'providers_enable_onprem': settings.providers_enable_onprem,
        'providers_enable_openstack': settings.providers_enable_openstack,
        'providers_enable_arm': settings.providers_enable_arm,
    }

    return JsonResponse({
        'account': account,
        'account_settings': account_settings,
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def suggest_account_params(request, provider):
    autosuggested_params = environment_providers.get_autosuggested_params(provider)

    return JsonResponse(autosuggested_params)

@api_view(['POST'])
@permission_classes([IsAuthenticated,custom_permissions.IsAdmin])
def is_username_free(request, usrname):
    if len(models.User.objects.filter(username=usrname)) > 0:
        return JsonResponse({
            'username_free': False
        }, status=200)
    else:
        return JsonResponse({
            'username_free': True
        }, status=200)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_cluster(request, cluster_id):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1024
            },
            "description": {
                "type": "string",
                "maxLength": 1024
            },
            "isCapi": {
                "type": "boolean"
            },
            "isYaookCapi": {
                "type": "boolean"
            },
        },
        "required": ["name", "description", "isCapi", "isYaookCapi"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    if payload['isCapi']:
        try:
            cluster = models.CapiCluster.objects.filter(id=cluster_id)[0]
        except:
            return JsonResponse({
                'error': {
                    'message': 'Cluster doesn\'t exist.'
                }
            }, status=400)
    elif payload['isYaookCapi']:
        try:
            cluster = models.YaookCapiCluster.objects.filter(id=cluster_id)[0]
        except:
            return JsonResponse({
                'error': {
                    'message': 'Cluster doesn\'t exist.'
                }
            }, status=400)
    else:
        try:
            cluster = models.Clusters.objects.filter(id=cluster_id)[0]
        except:
            return JsonResponse({
                'error': {
                    'message': 'Cluster doesn\'t exist.'
                }
            }, status=400)

    payload['name'] = payload['name'].strip()

    tenant_id = cluster.project.tenant.id

    if payload['name'] != cluster.title:
        if payload['isCapi'] and len(models.CapiCluster.objects.filter(project__tenant_id=tenant_id, title=payload['name'])) > 0:
            return JsonResponse({
                'error': {
                    'message': 'Cluster name already exists.'
                }
            }, status=400)
        if payload['isYaookCapi'] and len(models.YaookCapiCluster.objects.filter(project__tenant_id=tenant_id, title=payload['name'])) > 0:
            return JsonResponse({
                'error': {
                    'message': 'Cluster name already exists.'
                }
            }, status=400)
        elif len(models.Clusters.objects.filter(project__tenant_id=tenant_id, title=payload['name'])) > 0:
            return JsonResponse({
                'error': {
                    'message': 'Cluster name already exists.'
                }
            }, status=400)
        cluster.title = payload['name']
        
    cluster.description = payload['description'].strip()
    cluster.save()

    return JsonResponse({
        'submitted': True
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated,custom_permissions.IsAdmin])
def update_user(request):
    # Validate request
    payload, error = get_request_body(request)
    if error is not None:
        return error

    schema = {
        "type": "object",
        "properties": {
            "user_id": {
                "type": "number"
            },
            "firstname": {
                "type": "string",
                "minLength": 2,
                "maxLength": 100
            },
            "lastname": {
                "type": "string",
                "minLength": 2,
                "maxLength": 100
            },
            "company": {
                "type": "string"
            },
            "phone": {
                "type": "string"
            },
            "password": {
                "type": "string",
                "minLength": 8,
                "maxLength": 100
            }
        },
        "required": ["user_id", "firstname", "lastname", "company", "phone"]
    }

    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }
        logger.error(str(e), extra=log_data)
        return JsonResponse({
            'error': {
                'message': str(e),
            }
        }, status=400)

    try:
        user = models.User.objects.filter(id=payload['user_id'])[0]
    except:
        return JsonResponse({
            'error': {
                'message': 'User doesn\'t exist.'
            }
        }, status=400)

    user.first_name = payload["firstname"].strip()
    user.last_name = payload["lastname"].strip()
    user.save()

    try:
        daiteap_user = (models.DaiteapUser.objects
                                            .filter(user_id=payload['user_id'])
                                            .filter(tenant_id=request.daiteap_user.tenant_id))[0]
    except:
        return JsonResponse({
            'error': {
                'message': 'User doesn\'t exist in this tenant.'
            }
        }, status=400)

    profile = daiteap_user.user.profile
    profile.company = payload["company"].strip()
    profile.phone = payload["phone"].strip()
    profile.save()

    if 'password' in payload:
        password = payload['password']
        user.set_password(password)
        user.save()
    
    return JsonResponse({
        'submitted': True
    })

@api_view(['GET', 'POST', 'DELETE'])
@permission_classes([IsAuthenticated, custom_permissions.BucketAccessPermission])
def bucket_files(request, tenant_id, bucket_id, path):
    bucket = models.Bucket.objects.get(id=bucket_id, project__tenant_id=tenant_id)
    if bucket.credential.valid != True:
        return JsonResponse({
            'error': {
                'message': 'Credentials are not valid.'
            }
        }, status=400)

    if len(path) < 0:
        return JsonResponse({
            'error': {
                'message': 'Invalid path.'
            }
        }, status=400)

    if request.method == 'GET':
        storage_bucket_data = {}
        storage_bucket_data['bucket_id'] = bucket_id
        storage_bucket_data['path'] = path
        storage_bucket_data['provider'] = bucket.provider
        storage_bucket_data['credential_id'] = bucket.credential.id
        storage_bucket_data['bucket_name'] = bucket.name
        storage_bucket_data['storage_account_url'] = bucket.storage_account

        response = environment_providers.get_bucket_files(storage_bucket_data, request)
        if 'error' in response.keys():
            return JsonResponse(response, status=400)
        else:
            return JsonResponse(response, status=200)

    if request.method == 'POST':
        payload, error = get_request_body(request)
        if error is not None:
            return error

        payload['file_name'] = path

        schema = {
            "type": "object",
            "properties": {
                "file_name": {
                    "type": "string",
                    "minLength": 1
                },
                "content_type": {
                    "type": "string",
                    "minLength": 1
                },
                "contents": {},
            },
            "required": ["file_name", "content_type", "contents"]
        }

        try:
            validate(instance=payload, schema=schema)
        except ValidationError as e:
            log_data = {
                'level': 'ERROR',
                'user_id': str(request.user.id),
            }
            logger.error(str(e), extra=log_data)
            return JsonResponse({
                'error': {
                    'message': str(e),
                }
            }, status=400)

        payload['bucket_id'] = bucket_id
        payload['provider'] = bucket.provider
        payload['credential_id'] = bucket.credential.id
        payload['bucket_name'] = bucket.name
        payload['storage_account_url'] = bucket.storage_account

        response = environment_providers.add_bucket_file(payload, request)
        if 'error' in response.keys():
            return JsonResponse(response, status=400)
        else:
            return JsonResponse(response, status=200)

    if request.method == 'DELETE':
        storage_bucket_data = {}
        storage_bucket_data['bucket_id'] = bucket_id
        storage_bucket_data['provider'] = bucket.provider
        storage_bucket_data['credential_id'] = bucket.credential.id
        storage_bucket_data['bucket_name'] = bucket.name
        storage_bucket_data['storage_account_url'] = bucket.storage_account

        if path[len(path) - 1] == "/":
            storage_bucket_data['folder_path'] = path
            response = environment_providers.delete_bucket_folder(payload, request)
        else:
            storage_bucket_data['file_name'] = path
            response = environment_providers.delete_bucket_file(payload, request)

        if 'error' in response.keys():
            return JsonResponse(response, status=400)
        else:
            return JsonResponse(response, status=200)

@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.BucketAccessPermission])
def download_bucket_file(request, tenant_id, bucket_id, path):
    bucket = models.Bucket.objects.get(id=bucket_id, project__tenant_id=tenant_id)
    if bucket.credential.valid != True:
        return JsonResponse({
            'error': {
                'message': 'Credentials are not valid.'
            }
        }, status=400)

    storage_bucket_data = {}
    storage_bucket_data['bucket_id'] = bucket_id
    storage_bucket_data['file_name'] = path
    storage_bucket_data['provider'] = bucket.provider
    storage_bucket_data['credential_id'] = bucket.credential.id
    storage_bucket_data['bucket_name'] = bucket.name
    storage_bucket_data['storage_account_url'] = bucket.storage_account

    response = environment_providers.download_bucket_file(storage_bucket_data, request)
    if 'error' in response.keys():
        return JsonResponse(response, status=400)
    else:
        return JsonResponse(response, status=200)

@api_view(['GET'])
@permission_classes([IsAuthenticated, custom_permissions.CloudAccountAccessPermission])
def get_storage_accounts(request, tenant_id, cloudaccount_id):
    account = models.CloudAccount.objects.get(id=cloudaccount_id, tenant_id=tenant_id)
    if account.valid != True:
        return JsonResponse({
            'error': {
                'message': 'Credentials are not valid.'
            }
        }, status=400)

    response = environment_providers.get_storage_accounts(account.provider, cloudaccount_id)
    if 'error' in response.keys():
        return JsonResponse(response, status=400)
    else:
        return JsonResponse(response, status=200)
