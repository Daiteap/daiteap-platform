from __future__ import absolute_import, unicode_literals

import base64
import copy
import json
import logging
import os
import pathlib
import socket
import tempfile
import time
import traceback
import uuid
from string import Template

import cloudcluster.v1_0_0.views as views
import environment_providers.environment_providers as environment_providers
import requests
import yaml
from celery import shared_task
from celery.result import AsyncResult
from cloudcluster import settings
from django.contrib.auth.models import User
from django.http import HttpRequest
from environment_providers.azure.services.oauth import AzureAuthClient

from ..models import (
    CapiCluster,
    CeleryTask,
    CloudAccount,
    Clusters,
    ClusterService,
    ClusterUser,
    DaiteapUser,
    EnvironmentTemplate,
    Machine,
    Service,
    YaookCapiCluster,
)
from ..settings import (
    CREATE_CAPI_CLUSTER_AUTOMATIC_RETRIES,
    CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES,
    CREATE_VMS_AUTOMATIC_RETRIES,
    CREATE_YAOOKCAPI_CLUSTER_AUTOMATIC_RETRIES,
    DEBUG,
    LDAP_KUBERNETES_USERS_GROUP_NAME,
    MAX_AUTOMATIC_RETRIES,
    SUPPORTED_K3S_VERSIONS,
)
from .ansible.ansible_client import AnsibleClient
from .helm.helm_client import HelmClient
from .helm.values_templates.templates import (
    basic_template,
    basic_template_with_replicas,
    istio_base_template,
    mysql_template,
    mysql_template_with_replicas,
)
from .mailgun.mailgun_client import MailgunClient
from .manifests.templates import EXTERNAL_NAME_MANIFEST, SERVICE_INGRESS_MANIFEST, SERVICE_INGRESS_MANIFEST_WITH_AUTH, SERVICE_SECRET_MANIFEST
from .services import constants, environment_creation_steps, run_shell, vpn_client, user_encrypt
from .services.kubespray_inventory import (
    add_kubernetes_roles_to_nodes,
    add_kubernetes_roles_to_tfstate_resources,
    add_roles_to_k3s_nodes,
)

logger = logging.getLogger(__name__)

GRAFANA_PASSWORD_LENGTH = 16
GRAFANA_PORT = 31000

FILE_BASE_DIR = str(pathlib.Path(__file__).parent.absolute())

def create_service_addresses(credentials_path, service_name, service_namespace, clusterId, kubeconfig_path, service_username='', service_password=''):
    if settings.USE_DNS_FOR_SERVICES:
        domain = str(service_name + '.' + str(clusterId).replace('-','')[:10] + '.' + settings.SERVICES_DNS_DOMAIN)
        command = [
            'kubectl',
            '--kubeconfig',
            credentials_path + 'kubectl_config',
            'get',
            'service',
            '--namespace',
            service_namespace,
            service_name,
            '-o',
            'jsonpath="{.spec.ports[0].port}"',
        ]
        service_port = run_shell.run_shell_with_subprocess_popen(command, workdir='./', return_stdout=True)

        cmd = ['kubectl', '--kubeconfig=' + kubeconfig_path, 'get', 'certificate', '--namespace', 'daiteap-ingress', settings.SAN_CERTIFICATE_NAME, '-o', 'jsonpath="{.spec.dnsNames}"']
        output = run_shell.run_shell_with_subprocess_popen(cmd, workdir='./', return_stdout=True)
        if len(output['stdout']) > 0 and len(output['stdout'][0]) < 5:
            cmd = 'kubectl --kubeconfig=' + kubeconfig_path + ' patch certificate ' + settings.SAN_CERTIFICATE_NAME + ' -n daiteap-ingress --type=merge -p=\'{"spec":{"dnsNames":["' + domain + '"]}}\''
        else:
            cmd = 'kubectl --kubeconfig=' + kubeconfig_path + ' patch certificate ' + settings.SAN_CERTIFICATE_NAME + ' -n daiteap-ingress --type=json -p=\'[{"op": "add", "path": "/spec/dnsNames/-", "value":"' + domain + '"}]\''

        run_shell.run_shell_with_subprocess_popen(cmd, workdir='./', shell=True)

        max_retries = 30
        wait_seconds = 20
        for i in range(0, max_retries):
            time.sleep(wait_seconds)
            cmd = ['kubectl',
                '--kubeconfig=' + kubeconfig_path,
                'get',
                'certificate',
                '--namespace',
                'daiteap-ingress',
                settings.SAN_CERTIFICATE_NAME,
                '-o',
                'jsonpath="{.status.conditions[0].message}"',
            ]

            output = run_shell.run_shell_with_subprocess_popen(cmd, workdir='./', return_stdout=True)
            if output['stdout'] == ['"Certificate is up to date and has not expired"']:
                break

            if i == max_retries - 1:
                raise Exception('Timeout while waiting service certificate to create')

        if service_username and service_password:
            auth = user_encrypt.encrypt(service_username, service_password)

            secret_template = SERVICE_SECRET_MANIFEST
            secret_file = secret_template.substitute(
                name=service_name,
                namespace='daiteap-ingress',
                auth=auth,
            )
            with open(credentials_path + 'secret.yaml', 'a') as text_file:
                text_file.write(secret_file)

            command = [
                'kubectl',
                '--kubeconfig=' + kubeconfig_path,
                'apply',
                '-f',
                credentials_path + 'secret.yaml'
            ]

            run_shell.run_shell_with_subprocess_call(command, workdir='./')

        external_name_template = EXTERNAL_NAME_MANIFEST
        external_name_file = external_name_template.substitute(
            name=service_name + '-external-name',
            namespace='daiteap-ingress',
            externalName=service_name + '.' + service_namespace + '.svc.cluster.local',
            port=service_port['stdout'][0].strip('"'),
        )
        with open(credentials_path + 'external_name.yaml', 'a') as text_file:
            text_file.write(external_name_file)

        command = [
            'kubectl',
            '--kubeconfig=' + kubeconfig_path,
            'apply',
            '-f',
            credentials_path + 'external_name.yaml'
        ]

        run_shell.run_shell_with_subprocess_call(command, workdir='./')

        if service_username and service_password:
            ingress_template = SERVICE_INGRESS_MANIFEST_WITH_AUTH
        else:
            ingress_template = SERVICE_INGRESS_MANIFEST

        ingress_file = ingress_template.substitute(
            name=service_name,
            namespace='daiteap-ingress',
            clusterId=str(clusterId).replace('-','')[:10],
            serviceName=service_name + '-external-name',
            secretName='cert-' + settings.SAN_CERTIFICATE_NAME,
            service_port=service_port['stdout'][0].strip('"'),
            domain=settings.SERVICES_DNS_DOMAIN,
        )

        with open(credentials_path + 'ingress.yaml', 'a') as text_file:
            text_file.write(ingress_file)

        command[4] = credentials_path + 'ingress.yaml'
        run_shell.run_shell_with_subprocess_call(command, workdir='./')

        return [domain]
    else:
        cmd = [
            'kubectl',
            '--kubeconfig',
            credentials_path + 'kubectl_config',
            'patch',
            'service',
            '--namespace',
            service_namespace,
            service_name,
            '-p',
            '{"spec": {"type": "LoadBalancer"}}',
        ]

        run_shell.run_shell_with_subprocess_call(cmd, workdir='./')

        # get port
        cmd = [
            'kubectl',
            '--kubeconfig',
            credentials_path + 'kubectl_config',
            'get',
            'service',
            '--namespace',
            service_namespace,
            service_name,
            '-o',
            'jsonpath="{.spec.ports[0].port}"',
        ]
        service_port = run_shell.run_shell_with_subprocess_popen(cmd, workdir='./', return_stdout=True)

        cmd = [
            'kubectl',
            '--kubeconfig',
            credentials_path + 'kubectl_config',
            'get',
            'service',
            '--namespace',
            service_namespace,
            service_name,
            '-o',
            'jsonpath="{.status.loadBalancer.ingress[0].*}"'
        ]

        max_retries = 30
        wait_seconds = 20
        for i in range(0, max_retries):
            time.sleep(wait_seconds)

            service_ip = run_shell.run_shell_with_subprocess_popen(cmd, workdir='./', return_stdout=True)
            if service_ip['stdout'] != ['""']:
                break

            if i == max_retries - 1:
                raise Exception('Timeout while waiting daiteap ingress controller to create')

        return [service_ip['stdout'][0].strip('"') + ':' + service_port['stdout'][0].strip('"')]

def create_machine_records(cloud_config, tfstate_resources, cluster_id):
    machines = environment_providers.get_machine_records(cloud_config, tfstate_resources, cluster_id)

    Machine.objects.bulk_create(machines)

def delete_cluster_machine_records(cluster_id, nodes_for_deletion):
    machines = Machine.objects.filter(cluster_id=cluster_id, kube_name__in=nodes_for_deletion)
    machines.delete()

def get_gateway_address(resources, clouds, cluster_id, user_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    gateway_address = ''
    gateway_public_ip = ''

    for cloud in clouds:
        for node in clouds[cloud]:
            if not gateway_address and 'public_ip' in node:
                gateway_address = node['user'] + '@' + node['public_ip']
                gateway_public_ip = node['public_ip']

                return gateway_public_ip, gateway_address

    log_data = {
        'client_request': json.dumps(resources),
        'level': 'ERROR',
        'user_id': user_id,
        'environment_id': str(cluster.id),
        'environment_name': cluster.title,
        'task': 'worker_create_dlcm_environment',
    }
    logger.error(str(traceback.format_exc()) + '\n' + 'Cannot get gateway address', extra=log_data)
    raise Exception('Cannot get gateway address')

def get_nodes_private_ips(resources, clouds, cluster_id, user_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    nodes_private_ips = []

    for cloud in clouds:
        for node in clouds[cloud]:
            nodes_private_ips.append(node['private_ip'])

    if nodes_private_ips == []:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_dlcm_environment',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Error getting private ips', extra=log_data)
        return None

    return nodes_private_ips

@shared_task(ignore_result=False, time_limit=5400)
def worker_upgrade_kubernetes_cluster(resources, cluster_id, user_id, kubernetes_version):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    if cluster.kube_upgrade_status == 1:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_upgrade_kubernetes_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Cannot upgrade cluster while another upgrade is in progress', extra=log_data)
        raise Exception('Cannot upgrade cluster while another upgrade is in progress')

    cluster.kube_upgrade_status = 1
    cluster.save()

    clouds = environment_providers.get_tfstate_resources(cluster.tfstate, json.loads(cluster.config))
    _, gateway_address = get_gateway_address(resources, clouds, cluster_id, user_id)
    ansible_client = AnsibleClient()

    resources['kubernetesConfiguration']['version'] = kubernetes_version

    try:
        kubespray_inventory_dir_name = str(uuid.uuid4())

        environment_creation_steps.prepare_kubespray(resources, ansible_client, user_id, cluster_id, kubespray_inventory_dir_name, resources['kubernetesConfiguration'])
        environment_creation_steps.upgrade_kubespray_cluster(ansible_client, user_id, gateway_address, cluster_id, kubespray_inventory_dir_name)
        environment_creation_steps.delete_kubespray_inventory_dir(ansible_client, user_id, cluster_id, kubespray_inventory_dir_name)

        cluster = Clusters.objects.filter(id=cluster_id)[0]
        cluster.kube_upgrade_status = 0
        config = json.loads(cluster.config)
        config['kubernetesConfiguration']['version'] = kubernetes_version
        cluster.config = json.dumps(config)
        cluster.save()

    except Exception as e:
        encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")

        cluster = Clusters.objects.filter(id=cluster_id)[0]
        cluster.kube_upgrade_status = - cluster.kube_upgrade_status
        error_msg = {
            'message': encoded_error
        }
        cluster.error_msg = json.dumps(error_msg)
        cluster.save()

        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_upgrade_kubernetes_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        return

    return

@shared_task(ignore_result=False, time_limit=5400)
def worker_upgrade_k3s_cluster(resources, cluster_id, user_id, kubernetes_version):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    if cluster.kube_upgrade_status == 1:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_upgrade_k3s_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Cannot upgrade cluster while another upgrade is in progress', extra=log_data)
        raise Exception('Cannot upgrade cluster while another upgrade is in progress')

    cluster.kube_upgrade_status = 1
    cluster.save()

    clouds = environment_providers.get_tfstate_resources(cluster.tfstate, json.loads(cluster.config))
    _, gateway_address = get_gateway_address(resources, clouds, cluster_id, user_id)
    ansible_client = AnsibleClient()

    resources['kubernetesConfiguration']['version'] = kubernetes_version

    try:
        nodes_ips, _ = environment_providers.get_nodes_ips(clouds)
        dns_servers_ips = environment_providers.get_dns_servers_ips(nodes_ips)

        environment_creation_steps.k3s_ansible(ansible_client, user_id, gateway_address, cluster_id, dns_servers_ips, resources)

        cluster = Clusters.objects.filter(id=cluster_id)[0]
        cluster.kube_upgrade_status = 0
        config = json.loads(cluster.config)
        config['kubernetesConfiguration']['version'] = kubernetes_version
        cluster.config = json.dumps(config)
        cluster.save()

    except Exception as e:
        encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")

        cluster = Clusters.objects.filter(id=cluster_id)[0]
        cluster.kube_upgrade_status = - cluster.kube_upgrade_status
        error_msg = {
            'message': encoded_error
        }
        cluster.error_msg = json.dumps(error_msg)
        cluster.save()

        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_upgrade_k3s_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        return

    return

@shared_task(ignore_result=False, time_limit=5400)
def worker_create_dlcm_environment(resources, cluster_id, user_id, tag_values):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    cluster.installstep = abs(cluster.installstep)
    cluster.save()

    if type(CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES) != int or CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_dlcm_environment',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    if type(MAX_AUTOMATIC_RETRIES) != int or MAX_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_dlcm_environment',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for MAX_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    last_installstep = None
    current_retries = 0

    for i in range(MAX_AUTOMATIC_RETRIES + 1):
        try:
            if cluster.installstep > 3:
                machines = Machine.objects.filter(cluster_id=cluster_id)

                for machine in machines:
                    worker_restart_machine(cluster_id, machine.name, machine.provider, user_id)

            if cluster.installstep == 1:
                # cluster = Clusters.objects.filter(id=cluster_id)[0]
                # cluster.config=json.dumps(environment_providers.get_user_friendly_params(json.loads(cluster.config), False))
                # cluster.save()

                environment_providers.apply_terraform(resources, user_id, cluster_id, tag_values)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            clouds = environment_providers.get_tfstate_resources(cluster.tfstate, json.loads(cluster.config))
            clouds = add_kubernetes_roles_to_nodes(resources, clouds)

            if cluster.installstep == 2:
                environment_creation_steps.get_used_terraform_environment_resources(resources, user_id, cluster_id)
                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            resources = json.loads(cluster.config)

            if cluster.installstep == 3:
                create_machine_records(resources, clouds, cluster_id)
                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 4
                cluster.save()

            ansible_client = AnsibleClient()

            gateway_public_ip, gateway_address = get_gateway_address(resources, clouds, cluster_id, user_id)

            nodes_privateips = get_nodes_private_ips(resources, clouds, cluster_id, user_id)

            if cluster.installstep == 7:
                environment_creation_steps.prepare_nodes(ansible_client, user_id, nodes_privateips, gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            nodes_ips, all_nodes_private_ips = environment_providers.get_nodes_ips(clouds)

            dns_servers_ips = environment_providers.get_dns_servers_ips(nodes_ips)

            if cluster.installstep == 8:
                environment_creation_steps.dns(resources, user_id, gateway_address, nodes_ips, cluster_id, dns_servers_ips)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 9:
                environment_creation_steps.host_interface_mtu(ansible_client, user_id, gateway_address, all_nodes_private_ips, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 10:
                environment_creation_steps.fix_hostnames(user_id, nodes_ips, gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 11:
                environment_creation_steps.secure_nodes(ansible_client, user_id, nodes_ips, gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 12:
                environment_creation_steps.webhook_service(ansible_client, user_id, nodes_privateips[0], gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 13:
                kubespray_inventory_dir_name = str(uuid.uuid4())

                environment_creation_steps.prepare_kubespray(resources, ansible_client, user_id, cluster_id, kubespray_inventory_dir_name, resources['kubernetesConfiguration'])
                environment_creation_steps.kubespray(ansible_client, user_id, gateway_address, cluster_id, kubespray_inventory_dir_name)
                environment_creation_steps.delete_kubespray_inventory_dir(ansible_client, user_id, cluster_id, kubespray_inventory_dir_name)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 14:
                environment_creation_steps.fix_coredns(ansible_client, user_id, cluster_id, gateway_address, nodes_privateips[0], dns_servers_ips)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 15:
                environment_creation_steps.nodes_labels(resources, user_id, clouds, nodes_privateips[0], gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 4
                cluster.save()

            if cluster.installstep == 19:
                # ansible_client.kubernetes_nfs_storage_integration(resources, user_id, nodes_privateips[0], gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 20:
                environment_creation_steps.download_kubernetes_config(gateway_public_ip, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 3
                cluster.save()

            if cluster.installstep == 23:
                environment_providers.kubernetes_storage_integration(resources, user_id, clouds, nodes_privateips[0], gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 24:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.install_longhorn_storage(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 25:
                environment_providers.kubernetes_loadbalancer_integration(resources, user_id, clouds, nodes_privateips[0], gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 26:
                kubectl_command = "kubectl"
                kubeconfig_path = "/root/.kube/config"
                environment_creation_steps.monitoring(ansible_client, user_id, clouds, gateway_address, nodes_ips, cluster_id, kubectl_command, kubeconfig_path)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            cluster.installstep += 3
            cluster.save()
            # if cluster.installstep == 26:
            #     environment_creation_steps.add_elk_secrets(resources, ansible_client, gateway_address, user_id, nodes_ips, cluster_id)

            #     cluster = Clusters.objects.filter(id=cluster_id)[0]
            #     cluster.installstep += 1
            #     cluster.save()

            # nodes_count = environment_providers.count_nodes(resources)

            # if cluster.installstep == 27:
            #     environment_creation_steps.helm_elasticsearch(resources, nodes_count, cluster_id)

            #     cluster = Clusters.objects.filter(id=cluster_id)[0]
            #     cluster.installstep += 1
            #     cluster.save()

            # if cluster.installstep == 28:
            #     environment_creation_steps.helm_kibana(nodes_count, cluster_id)

            #     cluster = Clusters.objects.filter(id=cluster_id)[0]
            #     cluster.installstep += 1
            #     cluster.save()

            # if cluster.installstep == 29:
            #     environment_creation_steps.helm_fluentd(cluster_id)

            #     cluster = Clusters.objects.filter(id=cluster_id)[0]
            #     cluster.installstep += 1
            #     cluster.save()

            if cluster.installstep == 30:
                try:
                    environment_creation_steps.email_notification(user_id, cluster_id)
                except Exception as e:
                    log_data = {
                        'client_request': json.dumps(resources),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_create_dlcm_environment',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

                    raise Exception('Email notification error.')

                cluster.installstep = 0
                cluster.save()

            break

        except Exception as e:
            if i < MAX_AUTOMATIC_RETRIES:

                if last_installstep != cluster.installstep:
                    last_installstep = cluster.installstep
                    current_retries = 1

                else:
                    current_retries += 1

                if current_retries < CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES:
                    log_data = {
                        'client_request': json.dumps(resources),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_create_dlcm_environment',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e) + '\n retrying... ' + str(current_retries), extra=log_data)

                    time.sleep(10)
                    continue

            error_msg = {
                'message': ''
            }
            providers = json.loads(cluster.providers)
            config = json.loads(cluster.config)
            try:
                # get error instance type 
                error_instance_type = json.loads(e)['error_instance_type']
                encoded_error_bytes = base64.b64encode(str(json.loads(e)['error_msg']).encode("utf-8"))
                error_msg['error_instance_type'] = error_instance_type

                # get specs of error instance type
                instance_size = 0
                error_provider = ''
                error_zone = ''
                for provider in providers:
                    for node in config[provider.lower()]:
                        if node['instanceType'] == error_instance_type:
                            error_provider = provider.lower()
                            account = CloudAccount.objects.filter(id=config[provider.lower()]['account'], provider=provider.lower())[0]
                            regions = account.regions
                            for region in regions:
                                if region['name'] == config[provider.lower()]['region']:
                                    for zone in region['zones']:
                                        if zone['name'] == node['zone']:
                                            error_zone = zone['name']
                                            zone['instances'] = list(sorted(zone['instances'], key=lambda x: x['cpu']))
                                            counter = 0
                                            for instance in zone['instances']:
                                                if instance['name'] == node['instanceType']:
                                                    instance_size = counter
                                                    break
                                                counter += 1
                                            break
                                    break
                            break

                # update regions
                for provider in providers:
                    account_id = CloudAccount.objects.filter(id=config[provider.lower()]['account'],
                                                            provider=provider.lower())[0].id
                    worker_update_provider_regions(provider.lower(), user_id, account_id)

                # get suggested instance type
                account = CloudAccount.objects.filter(id=config[error_provider]['account'], provider=error_provider)[0]
                regions = account.regions
                for region in regions:
                    if region['name'] == config[error_provider]['region']:
                        for zone in region['zones']:
                            if zone['name'] == error_zone:
                                zone['instances'] = list(sorted(zone['instances'], key=lambda x: x['cpu']))
                                suggested_instance_type = zone['instances'][instance_size]
                                break
                        break

                error_msg['suggested_instance_type'] = suggested_instance_type

            except:
                encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))

            encoded_error = str(encoded_error_bytes, "utf-8")
            cluster = Clusters.objects.filter(id=cluster_id)[0]
            cluster.installstep = - cluster.installstep
            error_msg['message'] = encoded_error
            cluster.error_msg = json.dumps(error_msg)
            cluster.save()

            if not DEBUG:
                # Send email notification
                email_client = MailgunClient()
                email_client.email_environment_creation_failed(user_id, cluster.title)

            log_data = {
                'client_request': json.dumps(resources),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_create_dlcm_environment',
            }
            logger.error(str(traceback.format_exc()) + '\n' + encoded_error, extra=log_data)

            return

        return

@shared_task(ignore_result=False, time_limit=600)
def worker_get_tf_plan(resize_config, cluster_id, user_id, tag_values):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    resize_config = add_node_names_to_config(cluster, copy.deepcopy(resize_config))

    tf_plan = environment_providers.get_terraform(resize_config, user_id, cluster_id, tag_values)
    return {'tf_plan': tf_plan}

def worker_resize_dlcm_v2_environment_remove_nodes(resize_config_input, cluster_id, user_id, tag_values):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    current_config = json.loads(cluster.config)

    # Add names to nodes
    resize_config = add_node_names_to_config(cluster, copy.deepcopy(resize_config_input))
    current_config = add_node_names_to_config(cluster, copy.deepcopy(current_config))

    logger.debug('resize_config: ' + str(resize_config))
    logger.debug('current_config: ' + str(current_config))

    # Get nodes for resize
    nodes_for_deletion_names = get_nodes_for_deletion_names(current_config, resize_config)
    kubernetes_node_names_for_deletion = get_kubernetes_node_names_for_deletion(current_config, resize_config, cluster_id)

    if not nodes_for_deletion_names:
        return

    logger.debug('nodes_for_deletion_names: ' + str(nodes_for_deletion_names))
    logger.debug('kubernetes_node_names_for_deletion: ' + str(kubernetes_node_names_for_deletion))

    # Remove nodes from kubernetes
    environment_creation_steps.kubernetes_decomission_nodes(cluster_id, user_id, kubernetes_node_names_for_deletion)

    environment_providers.apply_terraform(resize_config, user_id, cluster_id, tag_values)

    # Parse Terraform output
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    tfstate_resources = environment_providers.get_tfstate_resources(cluster.tfstate, resize_config)
    tfstate_resources = add_kubernetes_roles_to_tfstate_resources(resize_config, tfstate_resources)


    # Delete nodes records from db
    delete_cluster_machine_records(cluster_id, kubernetes_node_names_for_deletion)

@shared_task(ignore_result=False, time_limit=5400)
def worker_resize_dlcm_v2_environment_create_nodes(resize_config_input, cluster_id, user_id, tag_values):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    current_config = json.loads(cluster.config)

    # Add names to nodes
    resize_config = add_node_names_to_config(cluster, copy.deepcopy(resize_config_input))
    current_config = add_node_names_to_config(cluster, copy.deepcopy(current_config))

    logger.debug('resize_config: ' + str(resize_config))
    logger.debug('current_config: ' + str(current_config))

    # Get nodes for creation
    nodes_for_creation = get_nodes_for_creation(current_config, resize_config)

    all_nodes_config = add_nodes_for_creation_in_current_config(current_config, resize_config)

    nodes_for_creation_names = resize_get_nodes_names(nodes_for_creation)

    nodes_for_creation['internal_dns_zone'] = current_config['internal_dns_zone']

    logger.debug('nodes_for_creation: ' + str(nodes_for_creation))
    logger.debug('nodes_for_creation_names: ' + str(nodes_for_creation_names))
    logger.debug('all_nodes_config: ' + str(all_nodes_config))

    # Create nodes with Terraform
    environment_providers.apply_terraform(all_nodes_config, user_id, cluster_id, tag_values)

    # Parse Terraform output
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    tfstate_resources = environment_providers.get_tfstate_resources(cluster.tfstate, all_nodes_config)
    tfstate_resources = add_kubernetes_roles_to_tfstate_resources(all_nodes_config, tfstate_resources)

    # logger.debug('tfstate_resources: ' + str(tfstate_resources))

    # Create nodes records in db
    create_machine_records(nodes_for_creation, tfstate_resources, cluster_id)

    try:
        _, gateway_address = get_gateway_address(all_nodes_config, tfstate_resources, cluster_id, user_id)
        new_nodes = Machine.objects.filter(cluster_id=cluster_id)
        new_nodes = [node for node in new_nodes if node.name.split('.')[0] in nodes_for_creation_names]
        new_nodes_private_ips = [node.privateIP for node in new_nodes]

        logger.debug('gateway_address: ' + str(gateway_address))
        logger.debug('new_nodes_private_ips: ' + str(new_nodes_private_ips))

        nodes_ips, _ = environment_providers.get_nodes_ips(tfstate_resources)
        dns_servers_ips = environment_providers.get_dns_servers_ips(nodes_ips)


        if not nodes_for_creation_names:
            return

        # Run ansible playbooks
        ansible_client = AnsibleClient()

        environment_creation_steps.prepare_nodes(ansible_client, user_id, new_nodes_private_ips, gateway_address, cluster_id, v2=True)

        environment_creation_steps.host_interface_mtu(ansible_client, user_id, gateway_address, new_nodes_private_ips, cluster_id, v2=True)

        skip_nodes = []
        cluster_db_nodes = Machine.objects.filter(cluster_id=cluster_id)

        for cluster_db_node in cluster_db_nodes:
            if cluster_db_node.name.split('.')[0] in nodes_for_creation_names:
                continue
            skip_nodes.append(cluster_db_node.id)

        print("Skip nodes: " + str(skip_nodes))
        environment_creation_steps.prepare_kubeadm_nodes(cluster_id, current_config['kubernetesConfiguration'], skip_nodes)

        master_machine = Machine.objects.filter(cluster=cluster_id, kube_master=True, publicIP__isnull=False)[0]
        master_machine_public_ip = master_machine.publicIP

        join_command = environment_creation_steps.get_kubeadm_join_command(master_machine_public_ip)
        certificate_key = environment_creation_steps.get_kubeadm_certificate_key(master_machine_public_ip)

        environment_providers.remove_nodeselector_from_ccm(all_nodes_config, user_id, master_machine_public_ip, gateway_address, cluster.id)

        for machine in new_nodes:
            if machine.kube_master == True:
                environment_creation_steps.join_kubeadm_node(machine, join_command, True, certificate_key, gateway_address=master_machine_public_ip)
            else:
                environment_creation_steps.join_kubeadm_node(machine, join_command, False, gateway_address=master_machine_public_ip)

        environment_creation_steps.remove_masters_taint(master_machine_public_ip)
        environment_creation_steps.fix_coredns(ansible_client, user_id, cluster_id, gateway_address, master_machine_public_ip, dns_servers_ips)
        environment_creation_steps.nodes_labels(all_nodes_config, user_id, tfstate_resources, master_machine_public_ip, gateway_address, cluster_id)
        environment_providers.add_nodeselector_to_ccm(all_nodes_config, user_id, master_machine_public_ip, gateway_address, cluster.id)
        # environment_providers.kubernetes_storage_integration(all_nodes_config, user_id, tfstate_resources, master_machine_public_ip, gateway_address, cluster.id)
        environment_providers.kubernetes_loadbalancer_integration(all_nodes_config, user_id, tfstate_resources, master_machine_public_ip, gateway_address, cluster.id)
    except Exception as e:
        # Remove created nodes from db
        Machine.objects.filter(cluster_id=cluster_id, kube_name__in=nodes_for_creation_names).delete()
        raise e

@shared_task(ignore_result=False, time_limit=5400)
def worker_resize_dlcm_v2_environment(resize_config, cluster_id, user_id, tag_values):
    try:
        worker_resize_dlcm_v2_environment_create_nodes(resize_config, cluster_id, user_id, tag_values)
        worker_resize_dlcm_v2_environment_remove_nodes(resize_config, cluster_id, user_id, tag_values)

        cluster = Clusters.objects.filter(id=cluster_id)[0]
        cluster.config = json.dumps(resize_config)
        cluster.resizestep = 0
        cluster.save()

    except Exception as e:
        encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")

        error_msg = {
            'message': encoded_error
        }

        cluster = Clusters.objects.filter(id=cluster_id)[0]
        cluster.error_msg = json.dumps(error_msg)
        cluster.resizestep = -1
        cluster.save()

        log_data = {
            'client_request': json.dumps(resize_config),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_resize_dlcm_v2_environment',
        }

        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        raise Exception(e)

@shared_task(ignore_result=False, time_limit=1800)
def worker_remove_compute_node(node_id, cluster_id, user_id, tag_values):
    node = Machine.objects.filter(id=node_id)[0]

    try:
        cluster = Clusters.objects.get(id=cluster_id)
        current_config = json.loads(cluster.config)
        current_config = add_node_names_to_config(cluster, copy.deepcopy(current_config))

        logger.debug('current_config: ' + str(current_config))

        resize_config = copy.deepcopy(current_config)
        node_found = False

        for config_node in current_config[node.provider]['nodes']:
            if node.provider == 'aws':
                if config_node['name'] == node.name.split('.')[0]:
                    resize_config[node.provider]['nodes'].remove(config_node)
                    node_found = True
                    break
            else:
                if config_node['name'] == node.kube_name:
                    resize_config[node.provider]['nodes'].remove(config_node)
                    node_found = True
                    break

        if not node_found:
            raise Exception('Node not found in config')

        # Delete nodes with Terraform
        environment_providers.apply_terraform(resize_config, user_id, cluster_id, tag_values)

        # Parse Terraform output
        cluster = Clusters.objects.filter(id=cluster_id)[0]
        tfstate_resources = environment_providers.get_tfstate_resources(cluster.tfstate, resize_config)
        tfstate_resources = add_kubernetes_roles_to_tfstate_resources(resize_config, tfstate_resources)

        # logger.debug('tfstate_resources: ' + str(tfstate_resources))

        # Delete nodes records from db
        delete_cluster_machine_records(cluster_id, [node.kube_name])

        cluster = Clusters.objects.filter(id=cluster_id)[0]

        other_machines = Machine.objects.filter(cluster_id=cluster_id)
        stopped_cluster = True
        for other_machine in other_machines:
            if other_machine.status != 10:
                stopped_cluster = False
        if stopped_cluster:
            cluster.status = 10

        cluster.config = json.dumps(resize_config)
        cluster.resizestep = 0
        cluster.save()

    except Exception as e:
        encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")

        error_msg = {
            'message': encoded_error
        }

        cluster = Clusters.objects.filter(id=cluster_id)[0]
        cluster.error_msg = json.dumps(error_msg)
        cluster.resizestep = -1
        cluster.save()

        log_data = {
            'client_request': json.dumps(resize_config),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_resize_dlcm_v2_environment',
        }

        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        raise Exception(e)

def add_node_names_to_config(cluster, cluster_config):
    existing_nodes = Machine.objects.filter(cluster_id=cluster.id)
    for existing_node in existing_nodes:
        for provider in cluster_config:
            if provider in environment_providers.supported_providers:
                for provider_node in cluster_config[provider]['nodes']:
                    if provider_node['is_control_plane'] == existing_node.kube_master and \
                       provider_node['instanceType'] == existing_node.type and \
                       provider_node['operatingSystem'] == existing_node.operating_system and \
                       cluster_config[provider]['region'] == existing_node.region and \
                       'name' not in provider_node:
                        provider_node['name'] = existing_node.name.split('.')[0]
                        break

    reserved_kube_names = [node.name.split('.')[0] for node in existing_nodes]

    index = 1
    for provider in cluster_config:
        if provider in environment_providers.supported_providers:
            for provider_node in cluster_config[provider]['nodes']:
                if 'name' not in provider_node:
                    while True:
                        kube_name = cluster.name + '-node-' + str(index).zfill(2)
                        if kube_name not in reserved_kube_names:
                            provider_node['name'] = kube_name
                            reserved_kube_names.append(kube_name)
                            break
                        index += 1

    return cluster_config

def get_kubernetes_node_names_for_deletion(current_config, resize_config, cluster_id):
    nodes_for_deletion = []
    for provider in current_config:
        if provider in environment_providers.supported_providers and \
                provider in resize_config and \
                current_config[provider]['region'] == resize_config[provider]['region']:
            for current_node in current_config[provider]['nodes']:
                found = False
                kube_name = current_node['name']

                for resize_node in resize_config[provider]['nodes']:

                    if resize_node['name'] == kube_name and \
                       resize_node['instanceType'] == current_node['instanceType'] and \
                       resize_node['operatingSystem'] == current_node['operatingSystem'] and \
                       resize_node['is_control_plane'] == current_node['is_control_plane']:
                        found = True
                        break
                if not found:
                    if provider == 'aws':
                        kube_name = Machine.objects.filter(cluster_id=cluster_id, name__startswith=current_node['name'] + '.')[0].kube_name
                    nodes_for_deletion.append(kube_name)

    return nodes_for_deletion

def get_nodes_for_deletion_names(current_config, resize_config):
    nodes_for_deletion = []
    for provider in current_config:
        if provider in environment_providers.supported_providers and \
                provider in resize_config and \
                current_config[provider]['region'] == resize_config[provider]['region']:
            for current_node in current_config[provider]['nodes']:
                found = False
                for resize_node in resize_config[provider]['nodes']:
                    if resize_node['name'] == current_node['name'] and \
                       resize_node['instanceType'] == current_node['instanceType'] and \
                       resize_node['operatingSystem'] == current_node['operatingSystem'] and \
                       resize_node['is_control_plane'] == current_node['is_control_plane']:
                        found = True
                        break
                if not found:
                    nodes_for_deletion.append(current_node['name'])

    return nodes_for_deletion

def get_nodes_for_creation(current_config, resize_config):
    nodes_for_creation = {}
    for provider in resize_config:
        if provider in environment_providers.supported_providers:
            if provider not in current_config or \
                    current_config[provider]['region'] != resize_config[provider]['region']:
                nodes_for_creation[provider] = resize_config[provider]
            else:
                nodes_for_creation[provider] = copy.deepcopy(current_config[provider])
                nodes_for_creation[provider]['nodes'] = []
                for resize_node in resize_config[provider]['nodes']:
                    found = False
                    for current_node in current_config[provider]['nodes']:
                        if resize_node['name'] == current_node['name'] and \
                           resize_node['operatingSystem'] == current_node['operatingSystem'] and \
                           resize_node['instanceType'] == current_node['instanceType'] and \
                           resize_node['is_control_plane'] == current_node['is_control_plane']:
                            found = True
                            break
                    if not found:
                        nodes_for_creation[provider]['nodes'].append(resize_node)

    return nodes_for_creation

def add_nodes_for_creation_in_current_config(current_config, resize_config):
    for provider in resize_config:
        if provider in environment_providers.supported_providers:
            if provider not in current_config or \
                    current_config[provider]['region'] != resize_config[provider]['region']:
                current_config[provider] = resize_config[provider]
            else:
                for resize_node in resize_config[provider]['nodes']:
                    found = False
                    for current_node in current_config[provider]['nodes']:
                        if resize_node['name'] == current_node['name'] and \
                           resize_node['operatingSystem'] == current_node['operatingSystem'] and \
                           resize_node['instanceType'] == current_node['instanceType'] and \
                           resize_node['is_control_plane'] == current_node['is_control_plane']:
                            found = True
                            break
                    if not found:
                        current_config[provider]['nodes'].append(resize_node)

    return current_config

def resize_get_nodes_names(cluster_config):
    nodes_names = []

    for provider in cluster_config:
        if provider in environment_providers.supported_providers:
            for provider_node in cluster_config[provider]['nodes']:
                nodes_names.append(provider_node['name'])

    return nodes_names

@shared_task(ignore_result=False, time_limit=5400)
def worker_create_dlcm_v2_environment(resources, cluster_id, user_id, tag_values):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    cluster.installstep = abs(cluster.installstep)
    cluster.save()

    if type(CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES) != int or CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_dlcm_v2_environment',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    if type(MAX_AUTOMATIC_RETRIES) != int or MAX_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_dlcm_v2_environment',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for MAX_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    last_installstep = None
    current_retries = 0

    for i in range(MAX_AUTOMATIC_RETRIES + 1):
        try:
            if cluster.installstep > 3:
                machines = Machine.objects.filter(cluster_id=cluster_id)

                for machine in machines:
                    worker_restart_machine(cluster_id, machine.name, machine.provider, user_id)

            if cluster.installstep > 20:
                wait_time = 10
                retries = 24
                for i in range(retries):
                    try:
                        logger.debug('Waiting for cluster to be ready...')
                        environment_creation_steps.check_if_kubernetes_cluster_is_reachable(cluster_id)
                        break
                    except Exception as e:
                        if i == retries - 1:
                            raise e
                        logger.debug('Cluster is not ready yet...')
                        time.sleep(wait_time)

            cluster_config = add_node_names_to_config(cluster, copy.deepcopy(json.loads(cluster.config)))

            if cluster.installstep == 1:
                # cluster_config=json.dumps(environment_providers.get_user_friendly_params(json.loads(cluster.config), False))
                # cluster = Clusters.objects.filter(id=cluster_id)[0]
                # cluster.save()

                environment_providers.apply_terraform(cluster_config, user_id, cluster_id, tag_values)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            clouds = environment_providers.get_tfstate_resources(cluster.tfstate, json.loads(cluster.config))
            clouds = add_kubernetes_roles_to_nodes(resources, clouds)

            if cluster.installstep == 2:
                # environment_creation_steps.get_used_terraform_environment_resources(resources, user_id, cluster_id)
                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            resources = json.loads(cluster.config)

            if cluster.installstep == 3:
                create_machine_records(cluster_config, clouds, cluster_id)
                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 4
                cluster.save()

            ansible_client = AnsibleClient()

            _, gateway_address = get_gateway_address(resources, clouds, cluster_id, user_id)

            nodes_privateips = get_nodes_private_ips(resources, clouds, cluster_id, user_id)

            control_plane_node = Machine.objects.filter(cluster_id=cluster_id, kube_master=True, publicIP__isnull=False)[0]
            control_plane_private_ip = control_plane_node.privateIP
            control_plane_public_ip = control_plane_node.publicIP

            cluster.gateway_cloud = control_plane_node.provider
            cluster.save()

            if cluster.installstep == 7:
                environment_creation_steps.prepare_nodes(ansible_client, user_id, nodes_privateips, gateway_address, cluster_id, v2=True)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            nodes_ips, all_nodes_private_ips = environment_providers.get_nodes_ips(clouds)

            dns_servers_ips = environment_providers.get_dns_servers_ips(nodes_ips)

            if cluster.installstep == 8:
                # environment_creation_steps.dns(resources, user_id, gateway_address, nodes_ips, cluster_id, dns_servers_ips, v2=True)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 9:
                environment_creation_steps.host_interface_mtu(ansible_client, user_id, gateway_address, all_nodes_private_ips, cluster_id, v2=True)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 10:
                # environment_creation_steps.fix_hostnames(user_id, nodes_ips, gateway_address, cluster_id, v2=True)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 11:
                # environment_creation_steps.secure_nodes(ansible_client, user_id, nodes_ips, gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 12:
                # environment_creation_steps.webhook_service(ansible_client, user_id, nodes_privateips[0], gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 13:
                environment_creation_steps.prepare_kubeadm_nodes(cluster_id, resources['kubernetesConfiguration'])

                master_machine = Machine.objects.filter(cluster_id=cluster_id, kube_master=True)[0]
                master_machine_public_ip = master_machine.publicIP

                environment_creation_steps.init_kubeadm_primary_master(master_machine, resources['kubernetesConfiguration'])
                join_command = environment_creation_steps.get_kubeadm_join_command(master_machine_public_ip)
                certificate_key = environment_creation_steps.get_kubeadm_certificate_key(master_machine_public_ip)

                machines = Machine.objects.filter(cluster_id=cluster_id)
                for machine in machines:
                    if machine.publicIP != master_machine_public_ip:
                        if machine.kube_master == True:
                            environment_creation_steps.join_kubeadm_node(machine, join_command, True, certificate_key, gateway_address=master_machine_public_ip)
                        else:
                            environment_creation_steps.join_kubeadm_node(machine, join_command, False, gateway_address=master_machine_public_ip)

                environment_creation_steps.remove_masters_taint(master_machine_public_ip)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 14:
                # environment_creation_steps.fix_coredns(ansible_client, user_id, cluster_id, gateway_address, control_plane_private_ip, dns_servers_ips)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 15:
                environment_creation_steps.nodes_labels(resources, user_id, clouds, control_plane_private_ip, gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 4
                cluster.save()

            if cluster.installstep == 19:
                # ansible_client.kubernetes_nfs_storage_integration(resources, user_id, control_plane_private_ip, gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 20:
                environment_creation_steps.download_kubernetes_config(control_plane_public_ip, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 3
                cluster.save()

            if cluster.installstep == 23:
                # environment_providers.kubernetes_storage_integration(resources, user_id, clouds, control_plane_public_ip, gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 24:
                environment_providers.kubernetes_loadbalancer_integration(resources, user_id, clouds, control_plane_private_ip, gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 25:
                if settings.USE_DNS_FOR_SERVICES:
                    ingress_target_list, is_ip = environment_creation_steps.install_ingress_controller(cluster.id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 26:
                if settings.USE_DNS_FOR_SERVICES:
                    environment_creation_steps.create_daiteap_dns_record(cluster.id, ingress_target_list, is_ip)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 27:
                if settings.USE_DNS_FOR_SERVICES:
                    environment_creation_steps.install_cert_manager(cluster.id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 28:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.install_longhorn_storage(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 29:
                kubectl_command = "kubectl"
                kubeconfig_path = "/root/.kube/config"
                environment_creation_steps.monitoring(ansible_client, user_id, control_plane_private_ip, gateway_address, cluster_id, kubectl_command, kubeconfig_path)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            # if cluster.installstep == 26:
            #     environment_creation_steps.add_elk_secrets(resources, ansible_client, gateway_address, user_id, nodes_ips, cluster_id)

            #     cluster = Clusters.objects.filter(id=cluster_id)[0]
            #     cluster.installstep += 1
            #     cluster.save()

            # nodes_count = environment_providers.count_nodes(resources)

            # if cluster.installstep == 27:
            #     environment_creation_steps.helm_elasticsearch(resources, nodes_count, cluster_id)

            #     cluster = Clusters.objects.filter(id=cluster_id)[0]
            #     cluster.installstep += 1
            #     cluster.save()

            # if cluster.installstep == 28:
            #     environment_creation_steps.helm_kibana(nodes_count, cluster_id)

            #     cluster = Clusters.objects.filter(id=cluster_id)[0]
            #     cluster.installstep += 1
            #     cluster.save()

            # if cluster.installstep == 29:
            #     environment_creation_steps.helm_fluentd(cluster_id)

            #     cluster = Clusters.objects.filter(id=cluster_id)[0]
            #     cluster.installstep += 1
            #     cluster.save()

            if cluster.installstep == 30:
                try:
                    environment_creation_steps.email_notification(user_id, cluster_id)
                except Exception as e:
                    log_data = {
                        'client_request': json.dumps(resources),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_create_dlcm_v2_environment',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

                    raise Exception('Email notification error.')

                cluster.installstep = 0
                cluster.save()

            break

        except Exception as e:
            if i < MAX_AUTOMATIC_RETRIES:

                if last_installstep != cluster.installstep:
                    last_installstep = cluster.installstep
                    current_retries = 1

                else:
                    current_retries += 1

                if current_retries < CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES:
                    log_data = {
                        'client_request': json.dumps(resources),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_create_dlcm_v2_environment',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e) + '\n retrying... ' + str(current_retries), extra=log_data)

                    time.sleep(10)
                    continue

            error_msg = {
                'message': ''
            }
            providers = json.loads(cluster.providers)
            config = json.loads(cluster.config)
            try:
                # get error instance type 
                error_instance_type = json.loads(e)['error_instance_type']
                encoded_error_bytes = base64.b64encode(str(json.loads(e)['error_msg']).encode("utf-8"))
                error_msg['error_instance_type'] = error_instance_type

                # get specs of error instance type
                instance_size = 0
                error_provider = ''
                error_zone = ''
                for provider in providers:
                    for node in config[provider.lower()]:
                        if node['instanceType'] == error_instance_type:
                            error_provider = provider.lower()
                            account = CloudAccount.objects.filter(id=config[provider.lower()]['account'], provider=provider.lower())[0]
                            regions = account.regions
                            for region in regions:
                                if region['name'] == config[provider.lower()]['region']:
                                    for zone in region['zones']:
                                        if zone['name'] == node['zone']:
                                            error_zone = zone['name']
                                            zone['instances'] = list(sorted(zone['instances'], key=lambda x: x['cpu']))
                                            counter = 0
                                            for instance in zone['instances']:
                                                if instance['name'] == node['instanceType']:
                                                    instance_size = counter
                                                    break
                                                counter += 1
                                            break
                                    break
                            break

                # update regions
                for provider in providers:
                    account_id = CloudAccount.objects.filter(id=config[provider.lower()]['account'],
                                                            provider=provider.lower())[0].id
                    worker_update_provider_regions(provider.lower(), user_id, account_id)

                # get suggested instance type
                account = CloudAccount.objects.filter(id=config[error_provider]['account'], provider=error_provider)[0]
                regions = account.regions
                for region in regions:
                    if region['name'] == config[error_provider]['region']:
                        for zone in region['zones']:
                            if zone['name'] == error_zone:
                                zone['instances'] = list(sorted(zone['instances'], key=lambda x: x['cpu']))
                                suggested_instance_type = zone['instances'][instance_size]
                                break
                        break

                error_msg['suggested_instance_type'] = suggested_instance_type

            except:
                encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))

            encoded_error = str(encoded_error_bytes, "utf-8")
            cluster = Clusters.objects.filter(id=cluster_id)[0]
            cluster.installstep = - cluster.installstep
            error_msg['message'] = encoded_error
            cluster.error_msg = json.dumps(error_msg)
            cluster.save()

            if not DEBUG:
                # Send email notification
                email_client = MailgunClient()
                email_client.email_environment_creation_failed(user_id, cluster.title)

            log_data = {
                'client_request': json.dumps(resources),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_create_dlcm_v2_environment',
            }
            logger.error(str(traceback.format_exc()) + '\n' + encoded_error, extra=log_data)

            return

        return


@shared_task(ignore_result=False, time_limit=2700)
def worker_create_capi_cluster(resources, cluster_id, user_id):
    cluster = CapiCluster.objects.filter(id=cluster_id)[0]

    cluster.installstep = abs(cluster.installstep)
    cluster.save()

    if type(CREATE_CAPI_CLUSTER_AUTOMATIC_RETRIES) != int or CREATE_CAPI_CLUSTER_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_capi_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for CREATE_CAPI_CLUSTER_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')


    if type(MAX_AUTOMATIC_RETRIES) != int or MAX_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_capi_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for MAX_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    last_installstep = None
    current_retries = 0

    for i in range(MAX_AUTOMATIC_RETRIES + 1):
        try:
            ansible_client = AnsibleClient()

            if cluster.installstep == 1:
                # cluster_config = json.dumps(environment_providers.get_user_friendly_params(json.loads(cluster.capi_config), True))
                # cluster = CapiCluster.objects.filter(id=cluster_id)[0]
                # cluster.save()

                environment_creation_steps.install_capi_cluster(ansible_client, user_id, cluster_id)

                cluster = CapiCluster.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 2:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.download_capi_kubernetes_config(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = CapiCluster.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 3:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.install_capi_cni_plugin(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = CapiCluster.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 4:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.install_openstack_ccm(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = CapiCluster.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 5:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.install_openstack_csi(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = CapiCluster.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 6:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.install_longhorn_storage(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = CapiCluster.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 7:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.add_capi_nodes_labels(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = CapiCluster.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 8:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.remove_master_capi_nodes_taint(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = CapiCluster.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 9:
                try:
                    environment_creation_steps.email_notification(user_id, cluster_id)
                except Exception as e:
                    log_data = {
                        'client_request': json.dumps(resources),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_create_capi_cluster',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

                    raise Exception('Email notification error.')

                cluster.installstep = 0
                cluster.save()

            break

        except Exception as e:
            if i < MAX_AUTOMATIC_RETRIES:

                if last_installstep != cluster.installstep:
                    last_installstep = cluster.installstep
                    current_retries = 1

                else:
                    current_retries += 1

                if current_retries < CREATE_CAPI_CLUSTER_AUTOMATIC_RETRIES:
                    log_data = {
                        'client_request': json.dumps(resources),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_create_capi_cluster',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e) + '\n retrying... ' + str(current_retries), extra=log_data)

                    time.sleep(10)
                    continue


            encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
            encoded_error = str(encoded_error_bytes, "utf-8")

            cluster = CapiCluster.objects.filter(id=cluster_id)[0]
            cluster.installstep = - cluster.installstep
            error_msg = {
                'message': encoded_error
            }
            cluster.error_msg = json.dumps(error_msg)
            cluster.save()

            # if not DEBUG:
            #     # Send email notification
            #     email_client = MailgunClient()
            #     email_client.email_environment_creation_failed(user_id, cluster.title)

            log_data = {
                'client_request': json.dumps(resources),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_create_capi_cluster',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

            return

    return

@shared_task(ignore_result=False, time_limit=2700)
def worker_resize_capi_cluster(nodes, cluster_id, user_id):
    cluster = CapiCluster.objects.filter(id=cluster_id)[0]

    cluster.resizestep = abs(cluster.resizestep)
    cluster.save()

    if type(CREATE_CAPI_CLUSTER_AUTOMATIC_RETRIES) != int or CREATE_CAPI_CLUSTER_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(nodes),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_resize_capi_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for CREATE_CAPI_CLUSTER_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')


    if type(MAX_AUTOMATIC_RETRIES) != int or MAX_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(nodes),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_resize_capi_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for MAX_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    last_resizestep = None
    current_retries = 0

    for i in range(MAX_AUTOMATIC_RETRIES + 1):
        try:
            ansible_client = AnsibleClient()

            if cluster.resizestep == 1:
                environment_creation_steps.resize_capi_cluster(ansible_client, user_id, cluster_id, nodes)

                cluster = CapiCluster.objects.filter(id=cluster_id)[0]
                cluster.resizestep += 1
                cluster.save()

            config = json.loads(cluster.capi_config)
            config['openstack']['workerNodes'] = nodes
            cluster.capi_config = json.dumps(config)
            cluster.save()

            if cluster.resizestep == 2:

                cluster = CapiCluster.objects.filter(id=cluster_id)[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 3:
                # max_retries = 24
                # wait_seconds = 10
                # for i in range(0, max_retries):
                #     time.sleep(wait_seconds)
                #     try:
                #         environment_creation_steps.download_capi_kubernetes_config(cluster_id)
                #     except Exception as e:
                #         if i == max_retries - 1:
                #             raise e
                #         continue
                #     break

                cluster.resizestep = 0
                cluster.save()

            break

        except Exception as e:
            if i < MAX_AUTOMATIC_RETRIES:

                if last_resizestep != cluster.resizestep:
                    last_resizestep = cluster.resizestep
                    current_retries = 1

                else:
                    current_retries += 1

                if current_retries < CREATE_CAPI_CLUSTER_AUTOMATIC_RETRIES:
                    log_data = {
                        'client_request': json.dumps(nodes),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_resize_capi_cluster',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e) + '\n retrying... ' + str(current_retries), extra=log_data)

                    time.sleep(10)
                    continue


            encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
            encoded_error = str(encoded_error_bytes, "utf-8")

            cluster = CapiCluster.objects.filter(id=cluster_id)[0]
            cluster.resizestep = - cluster.resizestep
            error_msg = {
                'message': encoded_error
            }
            cluster.error_msg = json.dumps(error_msg)
            cluster.save()

            # if not DEBUG:
            #     # Send email notification
            #     email_client = MailgunClient()
            #     email_client.email_environment_creation_failed(user_id, cluster.title)

            log_data = {
                'client_request': json.dumps(nodes),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_resize_capi_cluster',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

            return

    return

@shared_task(ignore_result=False, time_limit=2700)
def worker_delete_capi_cluster(cluster_id, user_id):
    cluster = CapiCluster.objects.filter(id=cluster_id)[0]

    try:
        max_retries = 24
        wait_seconds = 10
        not_found_msg = 'Error from server (NotFound): clusters.cluster.x-k8s.io \"' + str(cluster.id) + '\" not found'
        for i in range(0, max_retries):
            time.sleep(wait_seconds)
            try:
                environment_creation_steps.delete_capi_cluster(cluster_id, user_id)
            except Exception as e:
                logger.debug(e)
                if not_found_msg in str(e):
                    logger.debug('Cluster not found in management cluster, deleting from the database')
                    break
                if i == max_retries - 1:
                    raise e
                continue
            break
    except Exception as e:
        encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")

        cluster.installstep = -100
        cluster.error_msg = encoded_error
        cluster.save()

        log_data = {
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_delete_capi_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        return


    cluster.delete()

    return

@shared_task(ignore_result=False, time_limit=2700)
def worker_create_yaookcapi_cluster(cluster_id, user_id):
    cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
    resources = json.loads(cluster.yaookcapi_config)

    cluster.installstep = abs(cluster.installstep)
    cluster.save()

    if type(CREATE_YAOOKCAPI_CLUSTER_AUTOMATIC_RETRIES) != int or CREATE_YAOOKCAPI_CLUSTER_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_yaookcapi_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for CREATE_YAOOKCAPI_CLUSTER_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')


    if type(MAX_AUTOMATIC_RETRIES) != int or MAX_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_yaookcapi_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for MAX_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    last_installstep = None
    current_retries = 0

    for i in range(MAX_AUTOMATIC_RETRIES + 1):
        try:
            if cluster.installstep == 1:

                environment_creation_steps.install_yaookcapi_cluster(user_id, cluster_id)
                environment_creation_steps.wait_for_yaookcapi_cluster(72, 20, cluster_id)

                cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 2:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.download_yaookcapi_kubernetes_config(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 3:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.download_yaookcapi_wireguard_config(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
                cluster.installstep += 4
                cluster.save()

            cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
            vpn_client.connect(cluster.wireguard_config, cluster.id)

            if cluster.installstep == 7:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.add_yaookcapi_nodes_labels(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 8:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.remove_master_yaookcapi_nodes_taint(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 9:
                try:
                    environment_creation_steps.email_notification(user_id, cluster_id)
                except Exception as e:
                    log_data = {
                        'client_request': json.dumps(resources),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_create_yaookcapi_cluster',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

                    raise Exception('Email notification error.')

                cluster.installstep = 0
                cluster.save()

            break

        except Exception as e:
            if i < MAX_AUTOMATIC_RETRIES:

                if last_installstep != cluster.installstep:
                    last_installstep = cluster.installstep
                    current_retries = 1

                else:
                    current_retries += 1

                if current_retries < CREATE_YAOOKCAPI_CLUSTER_AUTOMATIC_RETRIES:
                    log_data = {
                        'client_request': json.dumps(resources),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_create_yaookcapi_cluster',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e) + '\n retrying... ' + str(current_retries), extra=log_data)

                    time.sleep(10)
                    continue


            encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
            encoded_error = str(encoded_error_bytes, "utf-8")

            cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
            cluster.installstep = - cluster.installstep
            error_msg = {
                'message': encoded_error
            }
            cluster.error_msg = json.dumps(error_msg)
            cluster.save()

            log_data = {
                'client_request': json.dumps(resources),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_create_yaookcapi_cluster',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

            return
        finally:
            vpn_client.disconnect(cluster.wireguard_config, cluster.id)

    return

@shared_task(ignore_result=False, time_limit=1800)
def worker_update_yaookcapi_cluster_wireguard_peers(cluster_id, user_id):
    cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]

    cluster.resizestep = abs(cluster.resizestep)
    cluster.save()

    if type(CREATE_YAOOKCAPI_CLUSTER_AUTOMATIC_RETRIES) != int or CREATE_YAOOKCAPI_CLUSTER_AUTOMATIC_RETRIES < 0:
        log_data = {
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_update_yaookcapi_cluster_wireguard_peers',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for CREATE_YAOOKCAPI_CLUSTER_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')


    if type(MAX_AUTOMATIC_RETRIES) != int or MAX_AUTOMATIC_RETRIES < 0:
        log_data = {
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_update_yaookcapi_cluster_wireguard_peers',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for MAX_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    last_resizestep = None
    current_retries = 0

    for i in range(MAX_AUTOMATIC_RETRIES + 1):
        try:
            ansible_client = AnsibleClient()

            if cluster.resizestep == 1:
                environment_creation_steps.resize_yaookcapi_cluster(ansible_client, user_id, cluster_id, None)
                environment_creation_steps.wait_for_yaookcapi_cluster(72, 20, cluster_id)

                cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 2:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.download_yaookcapi_wireguard_config(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
                cluster.resizestep = 0
                cluster.save()

            break

        except Exception as e:
            if i < MAX_AUTOMATIC_RETRIES:

                if last_resizestep != cluster.resizestep:
                    last_resizestep = cluster.resizestep
                    current_retries = 1

                else:
                    current_retries += 1

                if current_retries < CREATE_YAOOKCAPI_CLUSTER_AUTOMATIC_RETRIES:
                    log_data = {
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_update_yaookcapi_cluster_wireguard_peers',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e) + '\n retrying... ' + str(current_retries), extra=log_data)

                    time.sleep(10)
                    continue


            encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
            encoded_error = str(encoded_error_bytes, "utf-8")

            cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
            cluster.resizestep = - cluster.resizestep
            error_msg = {
                'message': encoded_error
            }
            cluster.error_msg = json.dumps(error_msg)
            cluster.save()

            log_data = {
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_update_yaookcapi_cluster_wireguard_peers',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

            return

    return

@shared_task(ignore_result=False, time_limit=2700)
def worker_resize_yaookcapi_cluster(nodes, cluster_id, user_id):
    cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]

    cluster.resizestep = abs(cluster.resizestep)
    cluster.save()

    if type(CREATE_YAOOKCAPI_CLUSTER_AUTOMATIC_RETRIES) != int or CREATE_YAOOKCAPI_CLUSTER_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(nodes),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_resize_yaookcapi_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for CREATE_YAOOKCAPI_CLUSTER_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')


    if type(MAX_AUTOMATIC_RETRIES) != int or MAX_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(nodes),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_resize_yaookcapi_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for MAX_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    last_resizestep = None
    current_retries = 0

    for i in range(MAX_AUTOMATIC_RETRIES + 1):
        try:
            ansible_client = AnsibleClient()

            if cluster.resizestep == 1:
                environment_creation_steps.resize_yaookcapi_cluster(ansible_client, user_id, cluster_id, nodes, True)
                environment_creation_steps.wait_for_yaookcapi_cluster(72, 20, cluster_id)

                cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
                cluster.resizestep += 1
                cluster.save()

            config = json.loads(cluster.yaookcapi_config)
            config['openstack']['workerNodes'] = nodes
            cluster.yaookcapi_config = json.dumps(config)
            cluster.save()

            if cluster.resizestep == 2:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.download_yaookcapi_wireguard_config(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
                cluster.resizestep += 1
                cluster.save()

            cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
            vpn_client.connect(cluster.wireguard_config, cluster.id)

            if cluster.resizestep == 3:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.add_yaookcapi_nodes_labels(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 4:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.remove_master_yaookcapi_nodes_taint(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
                cluster.resizestep = 0
                cluster.save()

            break

        except Exception as e:
            if i < MAX_AUTOMATIC_RETRIES:

                if last_resizestep != cluster.resizestep:
                    last_resizestep = cluster.resizestep
                    current_retries = 1

                else:
                    current_retries += 1

                if current_retries < CREATE_YAOOKCAPI_CLUSTER_AUTOMATIC_RETRIES:
                    log_data = {
                        'client_request': json.dumps(nodes),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_resize_yaookcapi_cluster',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e) + '\n retrying... ' + str(current_retries), extra=log_data)

                    time.sleep(10)
                    continue


            encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
            encoded_error = str(encoded_error_bytes, "utf-8")

            cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
            cluster.resizestep = - cluster.resizestep
            error_msg = {
                'message': encoded_error
            }
            cluster.error_msg = json.dumps(error_msg)
            cluster.save()

            log_data = {
                'client_request': json.dumps(nodes),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_resize_yaookcapi_cluster',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

            return

    return

@shared_task(ignore_result=False, time_limit=1800)
def worker_delete_yaookcapi_cluster(cluster_id, user_id):
    cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]

    try:
        max_retries = 24
        wait_seconds = 10
        for i in range(0, max_retries):
            time.sleep(wait_seconds)
            try:
                environment_creation_steps.delete_yaookcapi_cluster(cluster_id, user_id)
            except Exception as e:
                logger.debug(str(traceback.format_exc()))
                logger.debug(str(e))
                if i == max_retries - 1:
                    raise e
                continue
            break
    except Exception as e:
        encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")

        cluster.installstep = -100
        cluster.error_msg = encoded_error
        cluster.save()

        log_data = {
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_delete_yaookcapi_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        return

    cluster.delete()

    return

@shared_task(ignore_result=False, time_limit=5400)
def worker_create_k3s_cluster(resources, cluster_id, user_id, tag_values):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    cluster.installstep = abs(cluster.installstep)
    cluster.save()

    if type(CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES) != int or CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_dlcm_environment',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')


    if type(MAX_AUTOMATIC_RETRIES) != int or MAX_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_dlcm_environment',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for MAX_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    last_installstep = None
    current_retries = 0

    for i in range(MAX_AUTOMATIC_RETRIES + 1):
        try:
            if cluster.installstep > 3:
                machines = Machine.objects.filter(cluster_id=cluster_id)

                for machine in machines:
                    worker_restart_machine(cluster_id, machine.name, machine.provider, user_id)

            if cluster.installstep == 1:
                # cluster = Clusters.objects.filter(id=cluster_id)[0]
                # cluster.config=json.dumps(environment_providers.get_user_friendly_params(json.loads(cluster.config), False))
                # cluster.save()

                environment_providers.apply_terraform(resources, user_id, cluster_id, tag_values)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            clouds = environment_providers.get_tfstate_resources(cluster.tfstate, json.loads(cluster.config))
            clouds = add_roles_to_k3s_nodes(clouds)

            if cluster.installstep == 2:
                environment_creation_steps.get_used_terraform_environment_resources(resources, user_id, cluster_id)
                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            resources = json.loads(cluster.config)

            if cluster.installstep == 3:
                create_machine_records(resources, clouds, cluster_id)
                cluster.installstep += 4
                cluster.save()

            ansible_client = AnsibleClient()

            gateway_public_ip, gateway_address = get_gateway_address(resources, clouds, cluster_id, user_id)

            nodes_privateips = get_nodes_private_ips(resources, clouds, cluster_id, user_id)

            if cluster.installstep == 7:
                environment_creation_steps.prepare_nodes(ansible_client, user_id, nodes_privateips, gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            nodes_ips, all_nodes_private_ips = environment_providers.get_nodes_ips(clouds)

            dns_servers_ips = environment_providers.get_dns_servers_ips(nodes_ips)

            if cluster.installstep == 8:
                environment_creation_steps.dns(resources, user_id, gateway_address, nodes_ips, cluster_id, dns_servers_ips)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 9:
                environment_creation_steps.host_interface_mtu(ansible_client, user_id, gateway_address, all_nodes_private_ips, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 10:
                environment_creation_steps.fix_hostnames(user_id, nodes_ips, gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 11:
                environment_creation_steps.secure_nodes(ansible_client, user_id, nodes_ips, gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 12:
                environment_creation_steps.webhook_service(ansible_client, user_id, nodes_privateips[0], gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 13:
                environment_creation_steps.k3s_ansible(ansible_client, user_id, gateway_address, cluster_id, dns_servers_ips, resources)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 2
                cluster.save()

            if cluster.installstep == 15:
                environment_creation_steps.nodes_labels(resources, user_id, clouds, nodes_privateips[0], gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 4
                cluster.save()

            if cluster.installstep == 19:
                environment_creation_steps.download_k3s_config(gateway_public_ip, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 4
                cluster.save()

            if cluster.installstep == 23:
                environment_providers.kubernetes_storage_integration(resources, user_id, clouds, nodes_privateips[0], gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 24:
                max_retries = 24
                wait_seconds = 20
                for i in range(0, max_retries):
                    time.sleep(wait_seconds)
                    try:
                        environment_creation_steps.install_longhorn_storage(cluster_id)
                    except Exception as e:
                        logger.debug(str(traceback.format_exc()))
                        logger.debug(str(e))
                        if i == max_retries - 1:
                            raise e
                        continue
                    break

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 25:
                environment_providers.kubernetes_loadbalancer_integration(resources, user_id, clouds, nodes_privateips[0], gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 26:
                kubectl_command = "k3s kubectl"
                kubeconfig_path = "/etc/rancher/k3s/k3s.yaml"
                environment_creation_steps.monitoring(ansible_client, user_id, clouds, gateway_address, nodes_ips, cluster_id, kubectl_command, kubeconfig_path)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            cluster.installstep += 3
            cluster.save()
            # if cluster.installstep == 26:
            #     environment_creation_steps.add_elk_secrets(resources, ansible_client, gateway_address, user_id, nodes_ips, cluster_id)

            #     cluster = Clusters.objects.filter(id=cluster_id)[0]
            #     cluster.installstep += 1
            #     cluster.save()

            # nodes_count = environment_providers.count_nodes(resources)

            # if cluster.installstep == 27:
            #     environment_creation_steps.helm_elasticsearch(resources, nodes_count, cluster_id)

            #     cluster = Clusters.objects.filter(id=cluster_id)[0]
            #     cluster.installstep += 1
            #     cluster.save()

            # if cluster.installstep == 28:
            #     environment_creation_steps.helm_kibana(nodes_count, cluster_id)

            #     cluster = Clusters.objects.filter(id=cluster_id)[0]
            #     cluster.installstep += 1
            #     cluster.save()

            # if cluster.installstep == 29:
            #     environment_creation_steps.helm_fluentd(cluster_id)

            #     cluster = Clusters.objects.filter(id=cluster_id)[0]
            #     cluster.installstep += 1
            #     cluster.save()

            if cluster.installstep == 30:
                try:
                    environment_creation_steps.email_notification(user_id, cluster_id)
                except Exception as e:
                    log_data = {
                        'client_request': json.dumps(resources),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_create_dlcm_environment',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

                    raise Exception('Email notification error.')

                cluster.installstep = 0
                cluster.save()

            break

        except Exception as e:
            if i < MAX_AUTOMATIC_RETRIES:

                if last_installstep != cluster.installstep:
                    last_installstep = cluster.installstep
                    current_retries = 1

                else:
                    current_retries += 1

                if current_retries < CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES:
                    log_data = {
                        'client_request': json.dumps(resources),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_create_dlcm_environment',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e) + '\n retrying... ' + str(current_retries), extra=log_data)

                    time.sleep(10)
                    continue


            encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
            encoded_error = str(encoded_error_bytes, "utf-8")

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            cluster.installstep = - cluster.installstep
            error_msg = {
                'message': encoded_error
            }
            cluster.error_msg = json.dumps(error_msg)
            cluster.save()

            if not DEBUG:
                # Send email notification
                email_client = MailgunClient()
                email_client.email_environment_creation_failed(user_id, cluster.title)

            log_data = {
                'client_request': json.dumps(resources),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_create_dlcm_environment',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

            return

    return

@shared_task(ignore_result=False, time_limit=1200)
def worker_add_service_kubernetes_cluster(serviceName, configurationType, configuration, clusterId):
    if serviceName == 'istio':
        worker_add_istio_service(serviceName, configuration, clusterId)

        return

    elif serviceName == 'kubeflow':
        worker_add_kubeflow_service(serviceName, configuration, clusterId)

        return

    else:
        is_capi = False
        is_yaookcapi = False
        cluster = Clusters.objects.filter(id=clusterId)
        if len(cluster) == 0:
            cluster = CapiCluster.objects.filter(id=clusterId)
            if len(cluster) == 0:
                cluster = YaookCapiCluster.objects.filter(id=clusterId)[0]
                is_yaookcapi = True
            else:
                is_capi = True
        else:
            cluster = cluster[0]

        chart = HelmClient()
        chart.name = configuration['name']
        chart.chart_name = serviceName
        chart.namespace = configuration['namespace']

        service = Service.objects.filter(name=serviceName)[0]
        service_options = json.loads(service.options)
        if service.accessible_from_browser:
            configuration['service_type'] = 'ClusterIP'

        cluster_service = ClusterService(
            name=configuration['name'],
            service=service,
            namespace=configuration['namespace'],
            status=1,
        )
        if is_capi:
            cluster_service.capi_cluster = cluster
        elif is_yaookcapi:
            cluster_service.yaookcapi_cluster = cluster

            vpn_client.connect(cluster.wireguard_config, cluster.id)
        else:
            cluster_service.cluster = cluster

        cluster_service.save()

        values_file = ""

        if configurationType == 'yamlConfig':
            values_file = configuration['valuesFile']
        elif configurationType == 'simpleConfig':
            selectedProviders, providers_string = environment_providers.get_service_selected_providers(service_options, configuration)

            cluster_service.providers = json.dumps(selectedProviders)
            cluster_service.service_type = configuration['service_type']
            cluster_service.save()

            if 'replicas' in service_options:
                is_single = False
            else:
                is_single = True

            if not is_single:
                if serviceName == 'mysql':
                    template = Template(mysql_template_with_replicas)
                    values_file = template.substitute(
                        providers=providers_string,
                        service_type=configuration['service_type'],
                        replicas=configuration['replicas'],
                    )
                else:
                    template = Template(basic_template_with_replicas)
                    values_file = template.substitute(
                        providers=providers_string,
                        service_type=configuration['service_type'],
                        replicas=configuration['replicas']
                    )
            else:
                if serviceName == 'mysql':
                    template = Template(mysql_template)
                    values_file = template.substitute(
                        providers=providers_string,
                        service_type=configuration['service_type'],
                    )
                else:
                    template = Template(basic_template)
                    values_file = template.substitute(
                        providers=providers_string,
                        service_type=configuration['service_type']
                    )
                    if serviceName == 'nextcloud':
                        default_values_path = str(pathlib.Path(__file__).parent.absolute().parent) + '/v1_0_0/helm/charts/nextcloud/'
                        with open(default_values_path + 'values.yaml') as text_file:
                            default_values = text_file.read()
                        values_file += default_values

        with tempfile.TemporaryDirectory() as credentials_path:

            credentials_path = credentials_path + "/"

            with open(credentials_path + 'kubectl_config', 'a') as text_file:
                text_file.write(cluster.kubeconfig)
            os.chmod(credentials_path + 'kubectl_config', 0o700)

            with open(credentials_path + 'values.yaml', 'a') as text_file:
                text_file.write(values_file)

            chart.kubeconfig_path = credentials_path + 'kubectl_config'
            chart.install(credentials_path + 'values.yaml')

            time.sleep(20)

            yaml.safe_load(cluster.kubeconfig)
            connection_info = {}

            if service.accessible_from_browser:
                connection_info['addresses'] = create_service_addresses(credentials_path, configuration['name'], configuration['namespace'], clusterId, chart.kubeconfig_path)
            else:
                server_address = yaml.safe_load(cluster.kubeconfig)['clusters'][0]['cluster']['server'].split('//')[1].split(':')[0]
                connection_info['addresses'] = get_service_addresses(configuration['name'], configuration['namespace'], server_address, credentials_path)

            if serviceName not in configuration['name']:
                configuration['name'] += '-' + serviceName

            connection_info['password'] = get_service_password(configuration['name'], serviceName, configuration['namespace'], credentials_path)
            connection_info['username'] = get_service_username(serviceName)

            check_if_service_online(
                connection_info['addresses'][0],
                clusterId,
                service.accessible_from_browser
            )

            cluster_service.connection_info = json.dumps(connection_info)
            cluster_service.status = 0
            cluster_service.save()

        if is_yaookcapi:
            vpn_client.disconnect(cluster.wireguard_config, cluster.id)
        return

def get_service_addresses(name, namespace, server_address, credentials_path):
    cmd = ['kubectl',
            '--kubeconfig',
            credentials_path + 'kubectl_config',
            'get',
            'service',
            '--namespace',
            namespace,
            name,
            '-o',
            'jsonpath="{.spec.ports}"',
            ]

    output = run_shell.run_shell_with_subprocess_popen(cmd, workdir='./', return_stdout=True)

    ports = json.loads(output['stdout'][0].replace('"[', '[').replace(']"', ']'))

    addresses = []

    for port in ports:
        addresses.append(server_address + ':' + str(port['nodePort']))

    return addresses

def get_service_username(serviceName):
    if serviceName == 'mysql':
        return 'root'
    elif serviceName == 'nextcloud':
        return 'admin'
    elif serviceName == 'tensorflow-notebook':
        return ''
    else:
        return ''

def get_service_password(name, serviceName, namespace, credentials_path):
    if serviceName == 'tensorflow-notebook':
        cmd = [
            'kubectl',
            '--kubeconfig',
            credentials_path + 'kubectl_config',
            'get',
            'secret',
            '--namespace',
            namespace,
            name,
            '-o',
            'jsonpath=\"{.data.password}\"',
            ]

    elif serviceName == 'nextcloud':
        cmd = [
            'kubectl',
            '--kubeconfig',
            credentials_path + 'kubectl_config',
            'get',
            'secret',
            '--namespace',
            namespace,
            name,
            '-o',
            'jsonpath=\"{.data.nextcloud-password}\"',
            ]

    elif serviceName == 'jupyter-notebook':
        cmd = [
            'kubectl',
            '--kubeconfig',
            credentials_path + 'kubectl_config',
            'get',
            'secret',
            '--namespace',
            namespace,
            name,
            '-o',
            'jsonpath=\"{.data.password}\"',
            ]

    elif serviceName == 'mysql':
        cmd = [
            'kubectl',
            '--kubeconfig',
            credentials_path + 'kubectl_config',
            'get',
            'secret',
            '--namespace',
            namespace,
            name,
            '-o',
            'jsonpath=\"{.data.mysql-root-password}'
        ]
    elif serviceName == 'kubeapps':
        cmd = "kubectl --kubeconfig " + credentials_path + 'kubectl_config' + " -n kube-system describe secret $(kubectl --kubeconfig " + credentials_path + 'kubectl_config' + " -n kube-system get secret | awk '/^dashboard-admin-sa-token-/{print $1}') | awk '$1==\"token:\"{print $2}'"
    else:
        return ''

    if serviceName == 'kubeapps':
        password = run_shell.run_shell_with_subprocess_popen(cmd, workdir='./', return_stdout=True, shell=True)['stdout'][0].strip()
    else:
        password = run_shell.run_shell_with_subprocess_popen(cmd, workdir='./', return_stdout=True)['stdout'][0].strip()

    if serviceName == 'mysql':
        password = base64.b64decode(password).decode('utf-8')
    elif serviceName == 'nextcloud':
        password = base64.b64decode(password).decode('utf-8')
    elif serviceName == 'tensorflow-notebook':
        password = base64.b64decode(password).decode('utf-8')
    elif serviceName == 'jupyter-notebook':
        password = base64.b64decode(password).decode('utf-8')

    return password

def check_if_service_online(address, cluster_id, accessible_from_browser):
    cluster = Clusters.objects.filter(id=cluster_id)
    if len(cluster) == 0:
        cluster = CapiCluster.objects.filter(id=cluster_id)
        if len(cluster) == 0:
            cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
            is_yaookcapi = True
        else:
            is_capi = True
    else:
        cluster = cluster[0]

    max_retries = 24
    wait_seconds = 20
    for i in range(0, max_retries):
        all_ok = True
        time.sleep(wait_seconds)
        try:
            if accessible_from_browser:
                response = requests.get('https://' + address + '/', timeout=30)

                if response.status_code != 200:
                    all_ok = False
            else:
                s = socket.socket()
                s.settimeout(30)
                s.connect((address.split(':')[0],int(address.split(':')[1])))
                s.close()
        except Exception as e:
            all_ok = False

        if all_ok:
            break

        if i == max_retries - 1:
            log_data = {
                'level': 'ERROR',
                'user_id': str(cluster.user.id),
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_add_service_kubernetes_cluster',
            }
            logger.error('Timeout waiting for service to get online', extra=log_data)
            raise Exception('Timeout waiting for service to get online')
    
    return

@shared_task(ignore_result=True, time_limit=1800)
def worker_add_istio_service(serviceName, configuration, clusterId):
    chart = HelmClient()
    cluster = Clusters.objects.filter(id=clusterId)[0]
    service = Service.objects.filter(name=serviceName)[0]

    cluster_service = ClusterService(
        cluster=cluster,
        name=configuration['name'],
        service=service,
        namespace=configuration['namespace'],
        status=1,
    )
    cluster_service.save()

    # install istio-base
    chart.Helm_DIR = FILE_BASE_DIR + '/helm/charts/istio/manifests/charts/'
    chart.name = 'istio-base'
    chart.chart_name = 'base'
    chart.namespace = configuration['namespace']

    template = Template(istio_base_template)
    values_file = template.substitute(
        istio_namespace=configuration['namespace']
    )

    with tempfile.TemporaryDirectory() as credentials_path:

        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        with open(credentials_path + 'values.yaml', 'a') as text_file:
            text_file.write(values_file)

        chart.kubeconfig_path = credentials_path + 'kubectl_config'
        result = chart.install(credentials_path + 'values.yaml')

    # install istio-discovery
    chart.Helm_DIR = FILE_BASE_DIR + '/helm/charts/istio/manifests/charts/istio-control/'
    chart.name = 'istiod'
    chart.chart_name = 'istio-discovery'
    chart.namespace = configuration['namespace']

    template = Template(istio_base_template)
    values_file = template.substitute(
        istio_namespace=configuration['namespace']
    )

    with tempfile.TemporaryDirectory() as credentials_path:

        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        with open(credentials_path + 'values.yaml', 'a') as text_file:
            text_file.write(values_file)

        chart.kubeconfig_path = credentials_path + 'kubectl_config'
        result = chart.install(credentials_path + 'values.yaml')
    
    # install istio-ingress
    chart.Helm_DIR = FILE_BASE_DIR + '/helm/charts/istio/manifests/charts/gateways/'
    chart.name = 'istio-ingress'
    chart.chart_name = 'istio-ingress'
    chart.namespace = configuration['namespace']

    template = Template(istio_base_template)
    values_file = template.substitute(
        istio_namespace=configuration['namespace']
    )

    with tempfile.TemporaryDirectory() as credentials_path:

        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        with open(credentials_path + 'values.yaml', 'a') as text_file:
            text_file.write(values_file)

        chart.kubeconfig_path = credentials_path + 'kubectl_config'
        result = chart.install(credentials_path + 'values.yaml')

    # install istio-egress
    chart.Helm_DIR = FILE_BASE_DIR + '/helm/charts/istio/manifests/charts/gateways/'
    chart.name = 'istio-egress'
    chart.chart_name = 'istio-egress'
    chart.namespace = configuration['namespace']

    template = Template(istio_base_template)
    values_file = template.substitute(
        istio_namespace=configuration['namespace']
    )

    with tempfile.TemporaryDirectory() as credentials_path:

        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        with open(credentials_path + 'values.yaml', 'a') as text_file:
            text_file.write(values_file)

        chart.kubeconfig_path = credentials_path + 'kubectl_config'
        result = chart.install(credentials_path + 'values.yaml')

    cluster_service.status = 0
    cluster_service.save()

    return


@shared_task(ignore_result=True, time_limit=1800)
def worker_add_kubeflow_service(serviceName, configuration, clusterId):
    cluster = Clusters.objects.filter(id=clusterId)[0]
    service = Service.objects.filter(name=serviceName)[0]
    user_id = User.objects.filter(username=cluster.user)[0].id

    cluster_service = ClusterService(
        cluster=cluster,
        name=configuration['name'],
        service=service,
        status=1,
    )
    cluster_service.save()

    config = json.loads(cluster.config)
    dc_node = environment_providers.get_dc_node(config, cluster)

    try:
        ansible_client = AnsibleClient()

        ansible_client.run_kubeflow(
            user_id,
            str(cluster.id),
            cluster.title,
            configuration['name'],
            dc_node,
            False
        )

    except Exception as e:
        encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")

        cluster_service.status = -1
        cluster.save()

        log_data = {
            'configuration': json.dumps(configuration),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_add_kubeflow_service',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        return

    cluster_service.connection_info = '''Get the application URL by running these commands:

    NOTE: It may take a few minutes for the LoadBalancer IP to be available.
    You can watch the status of by running 'kubectl get svc -w '
    export SERVICE_IP=$(kubectl -n istio-system get svc istio-ingressgateway --output jsonpath='{.status.loadBalancer.ingress[0].ip}')
    echo kubeflow_url=http://$SERVICE_IP:80'''

    cluster_service.status = 0
    cluster_service.save()

    return



@shared_task(ignore_result=False, time_limit=1800)
def worker_stop_cluster(cluster_id, user_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    try:
        environment_providers.stop_all_machines(cluster_id)
    except Exception as e:
        encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")

        cluster.status = -2
        error_msg = {
            'message': encoded_error
        }
        cluster.error_msg = json.dumps(error_msg)
        cluster.save()

        log_data = {
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_stop_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        return

    cluster.status = 10
    cluster.save()

@shared_task(ignore_result=False, time_limit=1800)
def worker_start_cluster(cluster_id, user_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    try:
        environment_providers.start_all_machines(cluster_id, user_id)
    except Exception as e:
        encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")

        cluster.status = -1
        error_msg = {
            'message': encoded_error
        }
        cluster.error_msg = json.dumps(error_msg)
        cluster.save()

        log_data = {
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_stop_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        return

    cluster.status = 0
    cluster.save()

    views.sync_users()


@shared_task(ignore_result=False, time_limit=5400)
def worker_restart_cluster(cluster_id, user_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    try:
        environment_providers.restart_all_machines(cluster_id, user_id)
    except Exception as e:
        encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")

        cluster.status = -3
        error_msg = {
            'message': encoded_error
        }
        cluster.error_msg = json.dumps(error_msg)
        cluster.save()

        log_data = {
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_restart_cluster',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        return

    cluster.status = 0
    cluster.save()

    views.sync_users()

@shared_task(ignore_result=False, time_limit=1800)
def worker_stop_machine(cluster_id, machine_name, machine_provider, user_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    machine = Machine.objects.filter(cluster_id=cluster_id, name=machine_name, provider=machine_provider)[0]
    stop_cluster = True
    other_machines = Machine.objects.filter(cluster_id=cluster_id).exclude(id=machine.id)

    for other_machine in other_machines:
        if other_machine.status != 10:
            stop_cluster = False

    environment_providers.stop_machine(machine, cluster_id, machine_provider, user_id)

    machine.status = 10
    machine.save()

    if stop_cluster:
        cluster.status = 10
        cluster.save()

    return

@shared_task(ignore_result=False, time_limit=1800)
def worker_start_machine(cluster_id, machine_name, machine_provider, user_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    
    machine = Machine.objects.filter(cluster_id=cluster_id, name=machine_name, provider=machine_provider)[0]
    start_cluster = True

    environment_providers.start_machine(machine, cluster_id, machine_provider, user_id)

    machine.status = 0
    machine.save()

    if start_cluster:
        cluster.status = 0
        cluster.save()

    views.sync_users()

    return

@shared_task(ignore_result=False, time_limit=1800)
def worker_restart_machine(cluster_id, machine_name, machine_provider, user_id):
    cluster = Clusters.objects.filter(id=cluster_id)[0]
    config = json.loads(cluster.config)

    machine = Machine.objects.filter(cluster_id=cluster_id, name=machine_name, provider=machine_provider)[0]

    environment_providers.restart_machine(machine, config, machine_provider, user_id)

    machine.status = 0
    machine.save()

    views.sync_users()

@shared_task(ignore_result=False, time_limit=1200)
def worker_delete_service_kubernetes_cluster(name, namespace, clusterId):
    chart = HelmClient()
    chart.name = name
    chart.namespace = namespace

    is_capi = False
    is_yaookcapi = False

    cluster = Clusters.objects.filter(id=clusterId)
    if len(cluster) == 0:
        cluster = CapiCluster.objects.filter(id=clusterId)
        if len(cluster) == 0:
            cluster = YaookCapiCluster.objects.filter(id=clusterId)[0]
            is_yaookcapi = True

            vpn_client.connect(cluster.wireguard_config, cluster.id)
        else:
            is_capi = True
    else:
        cluster = cluster[0]
        is_capi=False

    if len(namespace) > 0:
        if is_capi:
            service = ClusterService.objects.filter(
                                                name=name,
                                                capi_cluster=clusterId,
                                                namespace=namespace)[0]
        elif is_yaookcapi:
            service = ClusterService.objects.filter(
                                                name=name,
                                                yaookcapi_cluster=clusterId,
                                                namespace=namespace)[0]
        else:
            service = ClusterService.objects.filter(
                                                name=name,
                                                cluster_id=clusterId,
                                                namespace=namespace)[0]
    else:
        if is_capi:
            service = ClusterService.objects.filter(
                                                    name=name,
                                                    capi_cluster=clusterId)[0]
        elif is_yaookcapi:
            service = ClusterService.objects.filter(
                                                    name=name,
                                                    yaookcapi_cluster=clusterId)[0]
        else:
            service = ClusterService.objects.filter(
                                                    name=name,
                                                    cluster_id=clusterId)[0]

    if service.service.name == 'kubeflow':
        worker_delete_kubeflow_service(name, clusterId)

        return
    
    if service.service.name == 'istio':
        worker_delete_istio_service(name, namespace, clusterId)

        return

    service.status = 10
    service.save()

    with tempfile.TemporaryDirectory() as credentials_path:

        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        chart.kubeconfig_path = credentials_path + 'kubectl_config'

        if service.service.name == 'nextcloud':
            chart.uninstall(True, f"data-{service.name}-mariadb-0")
        else:
            chart.uninstall()

    # Delete cluster service db record
    service.delete()

    if is_yaookcapi:
        vpn_client.disconnect(cluster.wireguard_config, cluster.id)

    return


@shared_task(ignore_result=True, time_limit=1200)
def worker_delete_istio_service(name, namespace, clusterId):
    chart = HelmClient()
    cluster = Clusters.objects.filter(id=clusterId)
    if len(cluster) == 0:
        cluster = CapiCluster.objects.filter(id=clusterId)
        if len(cluster) == 0:
            cluster = YaookCapiCluster.objects.filter(id=clusterId)[0]
            is_yaookcapi = True
        else:
            is_capi = True
    else:
        cluster = cluster[0]

    if is_capi:
        service = ClusterService.objects.filter(
                                            name=name,
                                            capi_cluster=clusterId,
                                            namespace=namespace)[0]
    elif is_yaookcapi:
        service = ClusterService.objects.filter(
                                            name=name,
                                            yaookcapi_cluster=clusterId,
                                            namespace=namespace)[0]
    else:
        service = ClusterService.objects.filter(
                                            name=name,
                                            cluster_id=clusterId,
                                            namespace=namespace)[0]

    service.status = 10
    service.save()

    # delete istio-egress
    chart.name = 'istio-egress'
    chart.namespace = namespace

    with tempfile.TemporaryDirectory() as credentials_path:

        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        chart.kubeconfig_path = credentials_path + 'kubectl_config'
        chart.uninstall()

    # delete istio-ingress
    chart.name = 'istio-ingress'
    chart.namespace = namespace

    with tempfile.TemporaryDirectory() as credentials_path:

        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        chart.kubeconfig_path = credentials_path + 'kubectl_config'
        chart.uninstall()

    # delete istio-discovery
    chart.name = 'istiod'
    chart.namespace = namespace

    with tempfile.TemporaryDirectory() as credentials_path:

        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        chart.kubeconfig_path = credentials_path + 'kubectl_config'
        chart.uninstall()

    # delete istio-base
    chart.name = 'istio-base'
    chart.namespace = namespace

    with tempfile.TemporaryDirectory() as credentials_path:

        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        chart.kubeconfig_path = credentials_path + 'kubectl_config'
        chart.uninstall()

    # Delete cluster service db record
    service.delete()

    return


@shared_task(ignore_result=True, time_limit=1200)
def worker_delete_kubeflow_service(name, clusterId):
    cluster = Clusters.objects.filter(id=clusterId)
    if len(cluster) == 0:
        cluster = CapiCluster.objects.filter(id=clusterId)
        if len(cluster) == 0:
            cluster = YaookCapiCluster.objects.filter(id=clusterId)[0]
            is_yaookcapi = True
        else:
            is_capi = True
    else:
        cluster = cluster[0]

    user_id = User.objects.filter(username=cluster.user)[0].id
    service = Service.objects.filter(name='kubeflow')[0]

    if is_capi:
        cluster_service = ClusterService.objects.filter(
            capi_cluster=cluster,
            name=name,
            service=service
        )[0]
    elif is_yaookcapi:
        cluster_service = ClusterService.objects.filter(
            yaookcapi_cluster=cluster,
            name=name,
            service=service
        )[0]
    else:
        cluster_service = ClusterService.objects.filter(
            cluster=cluster,
            name=name,
            service=service
        )[0]

    cluster_service.status = 10
    cluster_service.save()

    config = json.loads(cluster.config)
    dc_node = environment_providers.get_dc_node(config, cluster)

    try:
        ansible_client = AnsibleClient()

        ansible_client.run_kubeflow(
            user_id,
            str(cluster.id),
            cluster.title,
            name,
            dc_node,
            True
        )

    except Exception as e:
        encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
        encoded_error = str(encoded_error_bytes, "utf-8")

        cluster_service.status = -10
        cluster.save()

        log_data = {
            'configuration': json.dumps(configuration),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_delete_kubeflow_service',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        return

    cluster_service.delete()

@shared_task(ignore_result=False, time_limit=1200)
def worker_validate_credentials(credentials, user_id, storage_enabled):
    try:
        result = environment_providers.validate_account_permissions(credentials, user_id, storage_enabled)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
            'user_id': user_id,
            'task': 'worker_validate_credentials',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
        parsed_error = ""
        for line in str(e).splitlines():
            if 'on terraform.tf' not in line and line not in '\n':
                parsed_error += line + "\n"
        result = {"error": parsed_error}
        if 'id' in credentials:
            cloud_account = CloudAccount.objects.get(id=credentials['id'])
            cloud_account.valid = False
            cloud_account.save()
        return result

    return result

@shared_task(ignore_result=False, time_limit=1800)
def worker_update_provider_regions(provider, user_id, account_id):

    environment_providers.update_provider_regions(provider, user_id, account_id)


@shared_task(ignore_result=False, time_limit=300)
def worker_set_template_user_friendly_params(template_id):
    template = EnvironmentTemplate.objects.filter(id=template_id)[0]

    resources = json.loads(template.config)
    is_capi = template.type == constants.ClusterType.CAPI.value
    is_yaookcapi = template.type == constants.ClusterType.YAOOKCAPI.value

    resources = environment_providers.get_user_friendly_params(resources, is_capi, is_yaookcapi)

    template.config = json.dumps(resources)
    template.save()

@shared_task(ignore_result=False, time_limit=5400)
def worker_create_vms(resources, cluster_id, user_id, tag_values):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    cluster.installstep = abs(cluster.installstep)
    cluster.save()

    if type(CREATE_VMS_AUTOMATIC_RETRIES) != int or CREATE_VMS_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_vms',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for CREATE_VMS_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    if type(MAX_AUTOMATIC_RETRIES) != int or MAX_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_vms',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for MAX_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')


    last_installstep = None
    current_retries = 0

    for i in range(MAX_AUTOMATIC_RETRIES + 1):
        try:
            if cluster.installstep == 1:
                # cluster = Clusters.objects.filter(id=cluster_id)[0]
                # cluster.config=json.dumps(environment_providers.get_user_friendly_params(json.loads(cluster.config), False))
                # cluster.save()

                environment_providers.apply_terraform(resources, user_id, cluster_id, tag_values)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            clouds = environment_providers.get_tfstate_resources(cluster.tfstate, json.loads(cluster.config))
            clouds = add_roles_to_k3s_nodes(clouds)

            if cluster.installstep == 2:
                environment_creation_steps.get_used_terraform_environment_resources(resources, user_id, cluster_id)
                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            resources = json.loads(cluster.config)

            if cluster.installstep == 3:
                create_machine_records(resources, clouds, cluster_id)
                cluster.installstep += 4
                cluster.save()

            ansible_client = AnsibleClient()

            _, gateway_address = get_gateway_address(resources, clouds, cluster_id, user_id)

            nodes_privateips = get_nodes_private_ips(resources, clouds, cluster_id, user_id)

            if cluster.installstep == 7:
                environment_creation_steps.prepare_nodes(ansible_client, user_id, nodes_privateips, gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            nodes_ips, all_nodes_private_ips = environment_providers.get_nodes_ips(clouds)

            dns_servers_ips = environment_providers.get_dns_servers_ips(nodes_ips)

            if cluster.installstep == 8:
                environment_creation_steps.dns(resources, user_id, gateway_address, nodes_ips, cluster_id, dns_servers_ips)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 9:
                environment_creation_steps.host_interface_mtu(ansible_client, user_id, gateway_address, all_nodes_private_ips, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 10:
                environment_creation_steps.fix_hostnames(user_id, nodes_ips, gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 11:
                environment_creation_steps.secure_nodes(ansible_client, user_id, nodes_ips, gateway_address, cluster_id)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 12:
                environment_creation_steps.k3s_ansible(ansible_client, user_id, gateway_address, cluster_id, dns_servers_ips, resources)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 13:
                kubectl_command = "k3s kubectl"
                kubeconfig_path = "/etc/rancher/k3s/k3s.yaml"
                environment_creation_steps.monitoring(ansible_client, user_id, clouds, gateway_address, nodes_ips, cluster_id, kubectl_command, kubeconfig_path)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 14:
                try:
                    environment_creation_steps.email_notification(user_id, cluster_id)
                except Exception as e:
                    log_data = {
                        'client_request': json.dumps(resources),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_create_vms',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

                    raise Exception('Email notification error.')

                cluster.installstep = 0
                cluster.save()

            break

        except Exception as e:
            if i < MAX_AUTOMATIC_RETRIES:
                if last_installstep != cluster.installstep:
                    last_installstep = cluster.installstep
                    current_retries = 1

                else:
                    current_retries += 1

                if current_retries < CREATE_VMS_AUTOMATIC_RETRIES:
                    log_data = {
                        'client_request': json.dumps(resources),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_create_vms',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e) + '\n retrying... ' + str(current_retries), extra=log_data)

                    time.sleep(10)
                    continue

            encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
            encoded_error = str(encoded_error_bytes, "utf-8")

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            cluster.installstep = - cluster.installstep
            error_msg = {
                'message': encoded_error
            }
            cluster.error_msg = json.dumps(error_msg)
            cluster.save()

            if not DEBUG:
                # Send email notification
                email_client = MailgunClient()
                email_client.email_environment_creation_failed(user_id, cluster.title)

            log_data = {
                'client_request': json.dumps(resources),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_create_vms',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

            return

@shared_task(ignore_result=False, time_limit=5400)
def worker_create_compute_vms(resources, cluster_id, user_id, tag_values):
    cluster = Clusters.objects.filter(id=cluster_id)[0]

    cluster.installstep = abs(cluster.installstep)
    cluster.save()

    if type(CREATE_VMS_AUTOMATIC_RETRIES) != int or CREATE_VMS_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_compute_vms',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for CREATE_VMS_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    if type(MAX_AUTOMATIC_RETRIES) != int or MAX_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(resources),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_compute_vms',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for MAX_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    resources['internal_dns_zone'] = 'daiteap.internal'
    last_installstep = None
    current_retries = 0

    for i in range(MAX_AUTOMATIC_RETRIES + 1):
        try:
            cluster_config = add_node_names_to_config(cluster, copy.deepcopy(json.loads(cluster.config)))

            if cluster.installstep == 1:
                environment_providers.apply_terraform(cluster_config, user_id, cluster_id, tag_values)

                cluster = Clusters.objects.filter(id=cluster_id)[0]
                cluster.installstep += 1
                cluster.save()

            clouds = environment_providers.get_tfstate_resources(cluster.tfstate, json.loads(cluster.config))
            clouds = add_kubernetes_roles_to_nodes(resources, clouds)

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            resources = json.loads(cluster.config)

            if cluster.installstep == 2:
                create_machine_records(cluster_config, clouds, cluster_id)
                cluster.installstep += 1
                cluster.save()

            if cluster.installstep == 3:
                try:
                    environment_creation_steps.email_notification(user_id, cluster_id)
                except Exception as e:
                    log_data = {
                        'client_request': json.dumps(resources),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_create_compute_vms',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

                    raise Exception('Email notification error.')

                views.sync_users(task_delay=False)

                cluster.installstep = 0
                cluster.save()

            views.sync_users()

            break

        except Exception as e:
            if i < MAX_AUTOMATIC_RETRIES:
                if last_installstep != cluster.installstep:
                    last_installstep = cluster.installstep
                    current_retries = 1

                else:
                    current_retries += 1

                if current_retries < CREATE_VMS_AUTOMATIC_RETRIES:
                    log_data = {
                        'client_request': json.dumps(resources),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_create_compute_vms',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e) + '\n retrying... ' + str(current_retries), extra=log_data)

                    time.sleep(10)
                    continue

            encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
            encoded_error = str(encoded_error_bytes, "utf-8")

            cluster = Clusters.objects.filter(id=cluster_id)[0]
            cluster.installstep = - cluster.installstep
            error_msg = {
                'message': encoded_error
            }
            cluster.error_msg = json.dumps(error_msg)
            cluster.save()

            if not DEBUG:
                # Send email notification
                email_client = MailgunClient()
                email_client.email_environment_creation_failed(user_id, cluster.title)

            log_data = {
                'client_request': json.dumps(resources),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_create_compute_vms',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

            return

@shared_task(ignore_result=False, time_limit=1800)
def worker_add_machines_to_vms(machines, user_id):
    cluster = Clusters.objects.filter(id=machines['clusterID'])[0]

    cluster.resizestep = abs(cluster.resizestep)
    cluster.save()

    ansible_client = AnsibleClient()

    if type(CREATE_VMS_AUTOMATIC_RETRIES) != int or CREATE_VMS_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(machines),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_add_machines_to_vms',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for CREATE_VMS_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')


    if type(MAX_AUTOMATIC_RETRIES) != int or MAX_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(machines),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_add_machines_to_vms',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for MAX_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    last_resizestep = None
    current_retries = 0

    for i in range(MAX_AUTOMATIC_RETRIES + 1):
        try:
            if cluster.resizestep == 1:
                resources = json.loads(cluster.config)

                old_machines = Machine.objects.filter(cluster=cluster)
                new_indices_counter = 0
                gateway_address = ''

                for machine in old_machines:
                    if gateway_address == '' and machine.publicIP:
                        gateway_address = 'clouduser' + '@' + machine.publicIP
                    machine_index = int(machine.name.split('.')[0][-2:])
                    if machine_index > new_indices_counter:
                        new_indices_counter = machine_index

                environment_providers.create_new_machines(resources, user_id, cluster.id, machines, new_indices_counter, old_machines)

                resources = environment_providers.add_new_machines_to_resources(machines, resources)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.config = json.dumps(resources)
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 2:
                clouds = environment_providers.get_tfstate_resources(cluster.tfstate, json.loads(cluster.config))

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 3:
                new_indices_counter = 0
                for machine in old_machines:
                    machine_index = int(machine.name.split('.')[0][-2:])
                    if machine_index > new_indices_counter:
                        new_indices_counter = machine_index

                old_machine_counter = environment_providers.count_provider_machines(machines, resources)

                new_machines = environment_providers.get_provider_machine_records(resources, clouds, cluster.id, machines['provider'], new_indices_counter, old_machine_counter)
                Machine.objects.bulk_create(new_machines)

                new_nodes_privateips = []

                for new_machine in new_machines:
                    new_nodes_privateips.append(new_machine.privateIP)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 4:
                ansible_client.run_prepare_nodes(user_id, str(cluster.id), cluster.title, new_nodes_privateips, gateway_address)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            for machine in clouds[machines['provider']]:
                if 'public_ip' in machine:
                    server_private_ip = machine['private_ip']

            if cluster.resizestep == 5:
                environment_providers.run_add_dns_address(machines, new_nodes_privateips, clouds, user_id, cluster, server_private_ip, gateway_address)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 6:
                ansible_client.run_dns_client(user_id, str(cluster.id), cluster.title, new_nodes_privateips, server_private_ip, machines['provider'], gateway_address)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 7:
                ansible_client.run_host_interface_mtu(user_id, str(cluster.id), cluster.title, new_nodes_privateips, gateway_address)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 8:
                new_indices_counter = 0
                for machine in old_machines:
                    machine_index = int(machine.name.split('.')[0][-2:])
                    if machine_index > new_indices_counter:
                        new_indices_counter = machine_index
                new_indices_counter += 1

                environment_providers.fix_added_machines_hostnames(machines, user_id, new_nodes_privateips, cluster.id, gateway_address, new_indices_counter)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 9:
                dc_ip, dc_hostname = environment_providers.get_dc_node_name_and_private_ip(resources, old_machines, clouds)

                ansible_client.run_secure_nodes_client(user_id, str(cluster.id), cluster.title, cluster.krb_admin_password, cluster.kdc_master_password, cluster.ldap_admin_password, new_nodes_privateips, dc_ip, dc_hostname, gateway_address, json.loads(cluster.config)['internal_dns_zone'])

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 10:
                nodes_addresses = environment_creation_steps.get_nodes_addresses(resources, user_id, cluster)

                master_nodes = []
                worker_nodes = []

                for node in nodes_addresses:
                    if node['kube_master']:
                        master_nodes.append({'address': node['address'], 'id': node['id']})
                    else:
                        worker_nodes.append({'address': node['address'], 'id': node['id']})

                if 'kubernetesConfiguration' not in resources:
                    resources['kubernetesConfiguration'] = {
                        'networkPlugin': 'flannel',
                        'podsSubnet': '10.233.64.0/18',
                        'serviceAddresses': '10.233.0.0/18',
                        'version': SUPPORTED_K3S_VERSIONS[0]
                    }

                ansible_client.run_add_k3s_node(user_id, str(cluster.id), cluster.title, master_nodes, worker_nodes, gateway_address, resources['kubernetesConfiguration'])

            cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
            cluster.resizestep = 0
            cluster.save()

            break
        
        except Exception as e:
            if i < MAX_AUTOMATIC_RETRIES:

                if last_resizestep != cluster.resizestep:
                    last_resizestep = cluster.resizestep
                    current_retries = 1

                else:
                    current_retries += 1

                if current_retries < CREATE_VMS_AUTOMATIC_RETRIES:
                    log_data = {
                        'client_request': json.dumps(machines),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_add_machines_to_vms',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e) + '\n retrying... ' + str(current_retries), extra=log_data)

                    time.sleep(10)
                    continue


            encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
            encoded_error = str(encoded_error_bytes, "utf-8")

            cluster = Clusters.objects.filter(id=cluster.id)[0]
            cluster.resizestep = - cluster.resizestep
            error_msg = {
                'message': encoded_error
            }
            cluster.error_msg = json.dumps(error_msg)
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

    return


@shared_task(ignore_result=False, time_limit=1800)
def worker_add_machines_to_k3s(machines, user_id):
    cluster = Clusters.objects.filter(id=machines['clusterID'])[0]

    cluster.resizestep = abs(cluster.resizestep)
    cluster.save()

    ansible_client = AnsibleClient()

    if cluster.resizestep == 1:
        resources = json.loads(cluster.config)

        old_machines = Machine.objects.filter(cluster=cluster)
        new_indices_counter = 0
        gateway_address = ''

        for machine in old_machines:
            if gateway_address == '' and machine.publicIP:
                gateway_address = 'clouduser' + '@' + machine.publicIP
            machine_index = int(machine.name.split('.')[0][-2:])
            if machine_index > new_indices_counter:
                new_indices_counter = machine_index

        environment_providers.create_new_machines(resources, user_id, cluster.id, machines, new_indices_counter, old_machines)

        resources = environment_providers.add_new_machines_to_resources(machines, resources)

        cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
        cluster.config = json.dumps(resources)
        cluster.resizestep += 1
        cluster.save()

    if cluster.resizestep == 2:
        clouds = environment_providers.get_tfstate_resources(cluster.tfstate, json.loads(cluster.config))

        cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
        cluster.resizestep += 1
        cluster.save()

    if cluster.resizestep == 3:
        new_indices_counter = 0
        for machine in old_machines:
            machine_index = int(machine.name.split('.')[0][-2:])
            if machine_index > new_indices_counter:
                new_indices_counter = machine_index

        old_machine_counter = environment_providers.count_provider_machines(machines, resources)

        new_machines = environment_providers.get_provider_machine_records(resources, clouds, cluster.id, machines['provider'], new_indices_counter, old_machine_counter)

        Machine.objects.bulk_create(new_machines)

        new_nodes_privateips = []

        for new_machine in new_machines:
            new_nodes_privateips.append(new_machine.privateIP)

        cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
        cluster.resizestep += 1
        cluster.save()

    if cluster.resizestep == 4:
        try:
            ansible_client.run_prepare_nodes(user_id, str(cluster.id), cluster.title, new_nodes_privateips, gateway_address)
        except Exception as e:
            cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
            cluster.resizestep = -4
            cluster.save()
            log_data = {
                'client_request': json.dumps(machines),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_add_machines_to_k3s',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
            return

        cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
        cluster.resizestep += 1
        cluster.save()

    for machine in clouds[machines['provider']]:
        if 'public_ip' in machine:
            server_private_ip = machine['private_ip']

    if cluster.resizestep == 5:
        environment_providers.run_add_dns_address(machines, new_nodes_privateips, clouds, user_id, cluster, server_private_ip, gateway_address)

        cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
        cluster.resizestep += 1
        cluster.save()

    if cluster.resizestep == 6:
        try:
            ansible_client.run_dns_client(user_id, str(cluster.id), cluster.title, new_nodes_privateips, server_private_ip, machines['provider'], gateway_address)
        except Exception as e:
            cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
            cluster.resizestep = -6
            cluster.save()
            log_data = {
                'client_request': json.dumps(machines),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_add_machines_to_k3s',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
            return

        cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
        cluster.resizestep += 1
        cluster.save()

    if cluster.resizestep == 7:
        try:
            ansible_client.run_host_interface_mtu(user_id, str(cluster.id), cluster.title, new_nodes_privateips, gateway_address)
        except Exception as e:
            cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
            cluster.resizestep = -7
            cluster.save()
            log_data = {
                'client_request': json.dumps(machines),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_add_machines_to_k3s',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
            return

        cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
        cluster.resizestep += 1
        cluster.save()

    if cluster.resizestep == 8:
        new_indices_counter = 0
        for machine in old_machines:
            machine_index = int(machine.name.split('.')[0][-2:])
            if machine_index > new_indices_counter:
                new_indices_counter = machine_index
        new_indices_counter += 1

        environment_providers.fix_added_machines_hostnames(machines, user_id, new_nodes_privateips, cluster.id, gateway_address, new_indices_counter)

        cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
        cluster.resizestep += 1
        cluster.save()

    if cluster.resizestep == 9:
        dc_ip, dc_hostname = environment_providers.get_dc_node_name_and_private_ip(resources, old_machines, clouds)

        try:
            ansible_client.run_secure_nodes_client(user_id, str(cluster.id), cluster.title, cluster.krb_admin_password, cluster.kdc_master_password, cluster.ldap_admin_password, new_nodes_privateips, dc_ip, dc_hostname, gateway_address, json.loads(cluster.config)['internal_dns_zone'])
        except Exception as e:
            cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
            cluster.resizestep = -9
            cluster.save()
            log_data = {
                'client_request': json.dumps(machines),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_add_machines_to_k3s',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
            return

        cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
        cluster.resizestep += 1
        cluster.save()

    if cluster.resizestep == 10:
        environment_providers.remove_nodeselector_from_ccm(resources, user_id, dc_ip, gateway_address, cluster.id)

        cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
        cluster.resizestep += 1
        cluster.save()

    if cluster.resizestep == 11:

        try:
            nodes_addresses = environment_creation_steps.get_nodes_addresses(resources, user_id, cluster)

            master_nodes = []
            worker_nodes = []

            for node in nodes_addresses:
                if node['kube_master']:
                    master_nodes.append({'address': node['address'], 'id': node['id']})
                else:
                    worker_nodes.append({'address': node['address'], 'id': node['id']})

            ansible_client.run_add_k3s_node(user_id, str(cluster.id), cluster.title, master_nodes, worker_nodes, gateway_address, resources['kubernetesConfiguration'])
        except Exception as e:
            cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
            cluster.resizestep = -11
            cluster.save()
            log_data = {
                'client_request': json.dumps(machines),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_add_machines_to_k3s',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
            return
        cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
        cluster.resizestep += 1
        cluster.save()

    if cluster.resizestep == 12:
        try:
            environment_providers.nodes_labels(resources, user_id, clouds, dc_ip, gateway_address, cluster.id)

        except Exception as e:
            encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
            encoded_error = str(encoded_error_bytes, "utf-8")

            cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
            cluster.resizestep = -12
            error_msg = {
                'message': encoded_error
            }
            cluster.error_msg = json.dumps(error_msg)
            cluster.save()

            log_data = {
                'client_request': json.dumps(resources),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_add_machines_to_k3s',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

            return

        cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
        cluster.resizestep += 1
        cluster.save()

    if cluster.resizestep == 13:
        environment_providers.add_nodeselector_to_ccm(resources, user_id, dc_ip, gateway_address, cluster.id)

        cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
        cluster.resizestep += 1
        cluster.save()

    if cluster.resizestep == 14:
        try:
            environment_providers.kubernetes_storage_integration(resources, user_id, clouds, dc_ip, gateway_address, cluster.id)
            environment_providers.kubernetes_loadbalancer_integration(resources, user_id, clouds, dc_ip, gateway_address, cluster.id)

        except Exception as e:
            encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
            encoded_error = str(encoded_error_bytes, "utf-8")

            cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
            cluster.resizestep = -14
            error_msg = {
                'message': encoded_error
            }
            cluster.error_msg = json.dumps(error_msg)
            cluster.save()

            log_data = {
                'client_request': json.dumps(resources),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_add_machines_to_k3s',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

            return

    cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
    cluster.resizestep = 0
    cluster.save()

    return

@shared_task(ignore_result=False, time_limit=1800)
def worker_add_machines_to_dlcm(machines, user_id):
    cluster = Clusters.objects.filter(id=machines['clusterID'])[0]

    cluster.resizestep = abs(cluster.resizestep)
    cluster.save()

    ansible_client = AnsibleClient()

    if type(CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES) != int or CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(machines),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_add_machines_to_dlcm',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')


    if type(MAX_AUTOMATIC_RETRIES) != int or MAX_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(machines),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_add_machines_to_dlcm',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for MAX_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    last_resizestep = None
    current_retries = 0

    for i in range(MAX_AUTOMATIC_RETRIES + 1):
        try:
            if cluster.resizestep == 1:
                resources = json.loads(cluster.config)

                old_machines = Machine.objects.filter(cluster=cluster)
                new_indices_counter = 0
                gateway_address = ''

                for machine in old_machines:
                    if gateway_address == '' and machine.publicIP:
                        gateway_address = 'clouduser' + '@' + machine.publicIP
                    machine_index = int(machine.name.split('.')[0][-2:])
                    if machine_index > new_indices_counter:
                        new_indices_counter = machine_index

                environment_providers.create_new_machines(resources, user_id, cluster.id, machines, new_indices_counter, old_machines)

                resources = environment_providers.add_new_machines_to_resources(machines, resources)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.config = json.dumps(resources)
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 2:
                clouds = environment_providers.get_tfstate_resources(cluster.tfstate, json.loads(cluster.config))

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 3:
                new_indices_counter = 0
                for machine in old_machines:
                    machine_index = int(machine.name.split('.')[0][-2:])
                    if machine_index > new_indices_counter:
                        new_indices_counter = machine_index

                old_machine_counter = environment_providers.count_provider_machines(machines, resources)

                new_machines = environment_providers.get_provider_machine_records(resources, clouds, cluster.id, machines['provider'], new_indices_counter, old_machine_counter)
                Machine.objects.bulk_create(new_machines)

                new_nodes_privateips = []

                for new_machine in new_machines:
                    new_nodes_privateips.append(new_machine.privateIP)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 4:
                ansible_client.run_prepare_nodes(user_id, str(cluster.id), cluster.title, new_nodes_privateips, gateway_address)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            server_private_ip = ''

            for machine in clouds[machines['provider']]:
                if 'public_ip' in machine:
                    server_private_ip = machine['private_ip']

            if not server_private_ip:
                log_data = {
                    'client_request': json.dumps(machines),
                    'level': 'ERROR',
                    'user_id': user_id,
                    'environment_id': str(cluster.id),
                    'environment_name': cluster.title,
                    'task': 'worker_add_machines_to_dlcm',
                }
                logger.error('Error getting dns server private IP', extra=log_data)

                raise Exception('Internal server error')

            if cluster.resizestep == 5:
                environment_providers.run_add_dns_address(machines, new_nodes_privateips, clouds, user_id, cluster, server_private_ip, gateway_address)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 6:
                ansible_client.run_dns_client(user_id, str(cluster.id), cluster.title, new_nodes_privateips, server_private_ip, machines['provider'], gateway_address)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 7:
                ansible_client.run_host_interface_mtu(user_id, str(cluster.id), cluster.title, new_nodes_privateips, gateway_address)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 8:
                new_indices_counter = 0
                for machine in old_machines:
                    machine_index = int(machine.name.split('.')[0][-2:])
                    if machine_index > new_indices_counter:
                        new_indices_counter = machine_index
                new_indices_counter += 1

                environment_providers.fix_added_machines_hostnames(machines, user_id, new_nodes_privateips, cluster.id, gateway_address, new_indices_counter)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 9:
                dc_ip, dc_hostname = environment_providers.get_dc_node_name_and_private_ip(resources, old_machines, clouds)

                ansible_client.run_secure_nodes_client(user_id, str(cluster.id), cluster.title, cluster.krb_admin_password, cluster.kdc_master_password, cluster.ldap_admin_password, new_nodes_privateips, dc_ip, dc_hostname, gateway_address, json.loads(cluster.config)['internal_dns_zone'])

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 10:
                environment_providers.remove_nodeselector_from_ccm(resources, user_id, dc_ip, gateway_address, cluster.id)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 11:
                kubespray_inventory_dir_name = str(uuid.uuid4())

                environment_creation_steps.prepare_kubespray(resources, ansible_client, user_id, machines['clusterID'], kubespray_inventory_dir_name, resources['kubernetesConfiguration'])

                for machine in new_machines:
                    ansible_client.run_refresh_kubespray_facts_cache(user_id, str(cluster.id), cluster.title, gateway_address, kubespray_inventory_dir_name)
                    ansible_client.run_add_kubespray_nodes(user_id, str(cluster.id), cluster.title, gateway_address, kubespray_inventory_dir_name, machine.kube_name)

                ansible_client.run_delete_kubespray_directory(user_id, str(cluster.id), cluster.title, kubespray_inventory_dir_name)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 12:
                environment_providers.nodes_labels(resources, user_id, clouds, dc_ip, gateway_address, cluster.id)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 13:
                environment_providers.add_nodeselector_to_ccm(resources, user_id, dc_ip, gateway_address, cluster.id)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 14:
                environment_providers.kubernetes_storage_integration(resources, user_id, clouds, dc_ip, gateway_address, cluster.id)
                environment_providers.kubernetes_loadbalancer_integration(resources, user_id, clouds, dc_ip, gateway_address, cluster.id)

            cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
            cluster.resizestep = 0
            cluster.save()

            break
        
        except Exception as e:
            if i < MAX_AUTOMATIC_RETRIES:

                if last_resizestep != cluster.resizestep:
                    last_resizestep = cluster.resizestep
                    current_retries = 1

                else:
                    current_retries += 1

                if current_retries < CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES:
                    log_data = {
                        'client_request': json.dumps(machines),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_add_machines_to_dlcm',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e) + '\n retrying... ' + str(current_retries), extra=log_data)

                    time.sleep(10)
                    continue


            encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
            encoded_error = str(encoded_error_bytes, "utf-8")

            cluster = Clusters.objects.filter(id=cluster.id)[0]
            cluster.resizestep = - cluster.resizestep
            error_msg = {
                'message': encoded_error
            }
            cluster.error_msg = json.dumps(error_msg)
            cluster.save()

            log_data = {
                'client_request': json.dumps(machines),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_add_machines_to_dlcm',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

            return

    return


@shared_task(ignore_result=False, time_limit=1800)
def worker_add_machines_to_dlcm_v2(machines, user_id):
    cluster = Clusters.objects.filter(id=machines['clusterID'])[0]

    cluster.resizestep = abs(cluster.resizestep)
    cluster.save()

    ansible_client = AnsibleClient()

    if type(CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES) != int or CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(machines),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_add_machines_to_dlcm_v2',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')


    if type(MAX_AUTOMATIC_RETRIES) != int or MAX_AUTOMATIC_RETRIES < 0:
        log_data = {
            'client_request': json.dumps(machines),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_add_machines_to_dlcm_v2',
        }
        logger.error(str(traceback.format_exc()) + '\n' + 'Invalid value for MAX_AUTOMATIC_RETRIES', extra=log_data)

        raise Exception('Internal server error')

    last_resizestep = None
    current_retries = 0

    for i in range(MAX_AUTOMATIC_RETRIES + 1):
        try:
            if cluster.resizestep == 1:
                resources = json.loads(cluster.config)

                old_machines = Machine.objects.filter(cluster=cluster)
                new_indices_counter = 0
                gateway_address = ''

                for machine in old_machines:
                    if gateway_address == '' and machine.publicIP:
                        gateway_address = 'clouduser' + '@' + machine.publicIP
                    machine_index = int(machine.name.split('.')[0][-2:])
                    if machine_index > new_indices_counter:
                        new_indices_counter = machine_index

                environment_providers.create_new_machines(resources, user_id, cluster.id, machines, new_indices_counter, old_machines)

                resources = environment_providers.add_new_machines_to_resources(machines, resources)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.config = json.dumps(resources)
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 2:
                clouds = environment_providers.get_tfstate_resources(cluster.tfstate, json.loads(cluster.config))
                clouds = add_kubernetes_roles_to_nodes(resources, clouds)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 3:
                new_indices_counter = 0
                for machine in old_machines:
                    machine_index = int(machine.name.split('.')[0][-2:])
                    if machine_index > new_indices_counter:
                        new_indices_counter = machine_index

                old_machine_counter = environment_providers.count_provider_machines(machines, resources)

                new_machines = environment_providers.get_provider_machine_records(resources, clouds, cluster.id, machines['provider'], new_indices_counter, old_machine_counter)
                Machine.objects.bulk_create(new_machines)

                new_nodes_privateips = []

                for new_machine in new_machines:
                    new_nodes_privateips.append(new_machine.privateIP)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 4:
                environment_creation_steps.prepare_nodes(ansible_client, user_id, new_nodes_privateips, gateway_address, cluster.id, v2=True)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            server_private_ip = ''

            for machine in clouds[machines['provider']]:
                if 'public_ip' in machine:
                    server_private_ip = machine['private_ip']
                    break

            if not server_private_ip:
                log_data = {
                    'client_request': json.dumps(machines),
                    'level': 'ERROR',
                    'user_id': user_id,
                    'environment_id': str(cluster.id),
                    'environment_name': cluster.title,
                    'task': 'worker_add_machines_to_dlcm_v2',
                }
                logger.error('Error getting dns server private IP', extra=log_data)

                raise Exception('Internal server error')

            if cluster.resizestep == 5:
                environment_providers.run_add_dns_address(machines, new_nodes_privateips, clouds, user_id, cluster, server_private_ip, gateway_address)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 6:
                ansible_client.run_dns_client(user_id, str(cluster.id), cluster.title, new_nodes_privateips, server_private_ip, machines['provider'], gateway_address)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 7:
                ansible_client.run_host_interface_mtu(user_id, str(cluster.id), cluster.title, new_nodes_privateips, gateway_address)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 8:
                new_indices_counter = 0
                for machine in old_machines:
                    machine_index = int(machine.name.split('.')[0][-2:])
                    if machine_index > new_indices_counter:
                        new_indices_counter = machine_index
                new_indices_counter += 1

                environment_providers.fix_added_machines_hostnames(machines, user_id, new_nodes_privateips, cluster.id, gateway_address, new_indices_counter, v2=True)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 9:
                dc_ip, dc_hostname = environment_providers.get_dc_node_name_and_private_ip(resources, old_machines, clouds)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 10:
                environment_providers.remove_nodeselector_from_ccm(resources, user_id, dc_ip, gateway_address, cluster.id)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 11:
                master_machine = Machine.objects.filter(cluster_id=cluster.id, kube_master=True)[0]
                master_machine_public_ip = master_machine.publicIP

                join_command = environment_creation_steps.get_kubeadm_join_command(master_machine_public_ip)

                for machine in new_machines:
                    environment_creation_steps.join_kubeadm_node(machine, join_command, False, gateway_address=master_machine_public_ip)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 12:
                environment_providers.nodes_labels(resources, user_id, clouds, dc_ip, gateway_address, cluster.id)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 13:
                environment_providers.add_nodeselector_to_ccm(resources, user_id, dc_ip, gateway_address, cluster.id)

                cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
                cluster.resizestep += 1
                cluster.save()

            if cluster.resizestep == 14:
                environment_providers.kubernetes_storage_integration(resources, user_id, clouds, dc_ip, gateway_address, cluster.id)
                environment_providers.kubernetes_loadbalancer_integration(resources, user_id, clouds, dc_ip, gateway_address, cluster.id)

            cluster = Clusters.objects.filter(id=machines['clusterID'])[0]
            cluster.resizestep = 0
            cluster.save()

            break
        
        except Exception as e:
            if i < MAX_AUTOMATIC_RETRIES:

                if last_resizestep != cluster.resizestep:
                    last_resizestep = cluster.resizestep
                    current_retries = 1

                else:
                    current_retries += 1

                if current_retries < CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES:
                    log_data = {
                        'client_request': json.dumps(machines),
                        'level': 'ERROR',
                        'user_id': user_id,
                        'environment_id': str(cluster.id),
                        'environment_name': cluster.title,
                        'task': 'worker_add_machines_to_dlcm_v2',
                    }
                    logger.error(str(traceback.format_exc()) + '\n' + str(e) + '\n retrying... ' + str(current_retries), extra=log_data)

                    time.sleep(10)
                    continue


            encoded_error_bytes = base64.b64encode(str(e).encode("utf-8"))
            encoded_error = str(encoded_error_bytes, "utf-8")

            cluster = Clusters.objects.filter(id=cluster.id)[0]
            cluster.resizestep = - cluster.resizestep
            error_msg = {
                'message': encoded_error
            }
            cluster.error_msg = json.dumps(error_msg)
            cluster.save()

            log_data = {
                'client_request': json.dumps(machines),
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_add_machines_to_dlcm_v2',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

            return

    return


@shared_task(ignore_result=True, time_limit=1800)
def worker_delete_machine_from_vms(machine, cluster_user):
    print('Implement me!!!')
    return


@shared_task(ignore_result=False, time_limit=1800)
def worker_create_cluster_user(cluster_user, clusterId, user_id):
    cluster = Clusters.objects.filter(id=clusterId)[0]

    new_cluster_user = ClusterUser.objects.filter(
        cluster = clusterId,
        username = cluster_user['username']
    )[0]

    clouds = get_nodes(clusterId, user_id)

    ansible_client = AnsibleClient()
    config = json.loads(cluster.config)

    gateway_address, dc_ip, _ = environment_providers.get_gateway_address_dc_private_ip_and_client_hosts(clouds, cluster.id, user_id)

    try:
        ansible_client.run_add_cluster_user(user_id, str(cluster.id), cluster.title, cluster.ldap_admin_password, dc_ip, cluster_user, gateway_address, config['internal_dns_zone'])
    except Exception as e:
        new_cluster_user.status = -1
        new_cluster_user.save()
        log_data = {
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_create_cluster_user',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
        return

    if cluster_user['kubernetesUser']:
        try:
            ansible_client.add_user_to_ldap_group(user_id, str(cluster.id), cluster.title, cluster.ldap_admin_password, dc_ip, cluster_user, LDAP_KUBERNETES_USERS_GROUP_NAME, gateway_address, config['internal_dns_zone'])
        except Exception as e:
            new_cluster_user.status = -2
            new_cluster_user.save()
            log_data = {
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_create_cluster_user',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
            return

        try:
            ansible_client.run_add_kubernetes_role_to_user(user_id, str(cluster.id), cluster.title, dc_ip, cluster_user['username'], gateway_address)
        except Exception as e:
            new_cluster_user.status = -3
            new_cluster_user.save()
            log_data = {
                'level': 'ERROR',
                'user_id': user_id,
                'environment_id': str(cluster.id),
                'environment_name': cluster.title,
                'task': 'worker_create_cluster_user',
            }
            logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
            return

    # Update cluster user db record
    new_cluster_user.status = 0
    new_cluster_user.save()

    return

@shared_task(ignore_result=False, time_limit=300)
def get_longhorn_storage_info(cluster_id):
    cluster = Clusters.objects.filter(id=cluster_id)
    if len(cluster) == 0:
        cluster = CapiCluster.objects.filter(id=cluster_id)
        if len(cluster) == 0:
            cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
    else:
        cluster = cluster[0]

    with tempfile.TemporaryDirectory() as credentials_path:
        credentials_path = credentials_path + "/"

        with open(credentials_path + 'kubectl_config', 'a') as text_file:
            text_file.write(cluster.kubeconfig)
        os.chmod(credentials_path + 'kubectl_config', 0o700)

        kubeconfig_path = credentials_path + 'kubectl_config'

        # get cluster nodes
        command = ['kubectl', '--kubeconfig=' + kubeconfig_path, '--request-timeout=3s', '-n', 'longhorn-system', 'exec', '-it', 'deploy/longhorn-ui', '--', 'curl', 'http://localhost:8000/v1/nodes']

        command_output = run_shell.run_shell_with_subprocess_popen(command, workdir='./', return_stdout=True)['stdout'][0]

        data = json.loads(command_output)['data']

        output = {"nodes": []}

        for node in data:
            disks = node['disks']
            storage_available = 0
            storage_maximum = 0

            for disk in disks:
                storage_available += int(node['disks'][disk]['storageAvailable'])
                storage_maximum += int(node['disks'][disk]['storageMaximum'])

            output_node = {
                'name': node['name'],
                'storageAvailable': storage_available,
                'storageMaximum': storage_maximum,
            }

            output["nodes"].append(output_node)

    return output

@shared_task(ignore_result=False, time_limit=2700)
def worker_delete_cluster_user(cluster_user_username, clusterId, user_id, payload):
    cluster = Clusters.objects.filter(id=clusterId)[0]

    # Update cluster user db record
    cluster_user = ClusterUser.objects.filter(cluster=cluster, username=cluster_user_username)[0]
    cluster_user.status = 10
    cluster_user.save()

    clouds = get_nodes(clusterId, user_id)

    ansible_client = AnsibleClient()
    config = json.loads(cluster.config)

    gateway_address, dc_ip, client_hosts = environment_providers.get_gateway_address_dc_private_ip_and_client_hosts(clouds, cluster.id, user_id)

    try:
        ansible_client.run_delete_cluster_user(user_id, str(cluster.id), cluster.title, cluster.ldap_admin_password, dc_ip, client_hosts, cluster_user_username, cluster_user.kubernetes_user, gateway_address, config['internal_dns_zone'])
    except Exception as e:
        cluster_user.status = -10
        cluster_user.save()
        log_data = {
            'client_request': json.dumps(payload),
            'level': 'ERROR',
            'user_id': user_id,
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'worker_delete_cluster_user',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
        return

    # Delete cluster user db record
    cluster_user.delete()

    return

@shared_task(ignore_result=False, time_limit=1800)
def worker_delete_cluster(cluster_id, user_id):
    try:
        cluster = Clusters.objects.filter(id=cluster_id)[0]
        cluster.config = json.dumps(add_node_names_to_config(cluster, copy.deepcopy(json.loads(cluster.config))))
        cluster.save()

        if settings.USE_DNS_FOR_SERVICES:
            try:
                environment_creation_steps.delete_daiteap_dns_record(cluster.id)
            except Exception as e:
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
                return

        destroyed = environment_providers.destroy_resources(cluster_id, user_id)

        if destroyed:
            cluster.delete()

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

    return

@shared_task(ignore_result=False, time_limit=1800)
def create_vm_user(daiteap_user_id, cluster_id, machine_id, public_key, username, gw_address):
    cluster = Clusters.objects.get(id=cluster_id)
    daiteap_user = DaiteapUser.objects.get(id=daiteap_user_id)

    if cluster.installstep < 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(daiteap_user.user.id),
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'create_vm_user',
        }
        logger.error('Cluster status does not allow user creation.' + '\n', extra=log_data)
        return

    ansible_client = AnsibleClient()

    gw_address = 'clouduser@' + gw_address

    machine = Machine.objects.get(id=machine_id, cluster=cluster)
    if machine.sync_ssh_status > constants.SyncUserTaskStatus.SYNCHRONIZED.value:
        log_data = {
            'level': 'ERROR',
            'user_id': str(daiteap_user.user.id),
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'create_vm_user',
        }
        logger.error('Another user operation is in progress.' + '\n', extra=log_data)

    try:
        machine.sync_ssh_status = constants.SyncUserTaskStatus.ADD.value
        machine.sync_ssh_error_message = ''
        machine.save()

        ansible_client.run_create_user(daiteap_user_id,
                                    str(cluster.id),
                                    cluster.title,
                                    public_key,
                                    username,
                                    ['clouduser@' + machine.privateIP],
                                    gw_address)

        machine.sync_ssh_status = constants.SyncUserTaskStatus.SYNCHRONIZED.value
        machine.sync_ssh_error_message = ''
        machine.save()

        daiteap_user.user.profile.ssh_synchronized_machines.add(machine)
        daiteap_user.user.profile.save()
    except Exception as e:
        machine.sync_ssh_status = constants.SyncUserTaskStatus.ADD_ERROR.value
        machine.sync_ssh_error_message = str(e)
        machine.save()
        log_data = {
            'level': 'ERROR',
            'user_id': str(daiteap_user.user.id),
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'create_vm_user',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

    return

@shared_task(ignore_result=False, time_limit=1800)
def delete_vm_user(daiteap_user_id, cluster_id, machine_id, username, gw_address):
    cluster = Clusters.objects.get(id=cluster_id)
    daiteap_user = DaiteapUser.objects.get(id=daiteap_user_id)
    if cluster.installstep < 0:
        log_data = {
            'level': 'ERROR',
            'user_id': str(daiteap_user.user.id),
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'delete_vm_user',
        }
        logger.error('Cluster status does not allow user deletion.' + '\n', extra=log_data)
        return

    ansible_client = AnsibleClient()

    gw_address = 'clouduser@' + gw_address

    machine = Machine.objects.get(id=machine_id, cluster=cluster)
    if machine.sync_ssh_status > constants.SyncUserTaskStatus.SYNCHRONIZED.value:
        log_data = {
            'level': 'ERROR',
            'user_id': str(daiteap_user.user.id),
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'delete_vm_user',
        }
        logger.error('Another user operation is in progress.' + '\n', extra=log_data)

    try:
        machine.sync_ssh_status = constants.SyncUserTaskStatus.REMOVE.value
        machine.sync_ssh_error_message = ''
        machine.save()

        ansible_client.run_delete_user(daiteap_user_id,
                                    str(cluster.id),
                                    cluster.title,
                                    username,
                                    ['clouduser@' + machine.privateIP],
                                    gw_address)

        machine.sync_ssh_status = constants.SyncUserTaskStatus.SYNCHRONIZED.value
        machine.sync_ssh_error_message = ''
        machine.save()

        daiteap_user.user.profile.ssh_synchronized_machines.add(machine)
        daiteap_user.user.profile.save()
    except Exception as e:
        machine.sync_ssh_status = constants.SyncUserTaskStatus.REMOVE_ERROR.value
        machine.sync_ssh_error_message = str(e)
        machine.save()
        log_data = {
            'level': 'ERROR',
            'user_id': str(daiteap_user.user.id),
            'environment_id': str(cluster.id),
            'environment_name': cluster.title,
            'task': 'delete_vm_user',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)
    return

@shared_task(ignore_result=False, time_limit=5400)
def create_kubernetes_user(user_id, cluster_id, username, kubeconfig_value, cluster_type):

    if cluster_type == constants.ClusterType.CAPI.value:
        cluster = CapiCluster.objects.filter(id=cluster_id)[0]
    elif cluster_type == constants.ClusterType.YAOOKCAPI.value:
        cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
    else:
        cluster = Clusters.objects.filter(id=cluster_id)[0]

    ansible_client = AnsibleClient()

    ansible_client.run_create_kubernetes_user(user_id,
                                              str(cluster.id),
                                              cluster.title,
                                              username,
                                              kubeconfig_value
                                              )

    with open(os.path.join(settings.BASE_DIR + '/cloudcluster/v1_0_0/ansible/playbooks/create_kubernetes_user/k8s-users/' + str(cluster.id) + '_' + username + '/kubeconfig'), 'r') as file:
        lines = file.readlines()
        lines = [line.rstrip() for line in lines]

    os.remove(settings.BASE_DIR + '/cloudcluster/v1_0_0/ansible/playbooks/create_kubernetes_user/k8s-users/' + str(cluster.id) + '_' + username + '/kubeconfig')
    os.rmdir(settings.BASE_DIR + '/cloudcluster/v1_0_0/ansible/playbooks/create_kubernetes_user/k8s-users/' + str(cluster.id) + '_' + username)

    return lines

@shared_task(ignore_result=False, time_limit=1800)
def delete_kubernetes_user(user_id, cluster_id, username, kubeconfig_value, cluster_type):

    if cluster_type == constants.ClusterType.CAPI.value:
        cluster = CapiCluster.objects.filter(id=cluster_id)[0]
    elif cluster_type == constants.ClusterType.YAOOKCAPI.value:
        cluster = YaookCapiCluster.objects.filter(id=cluster_id)[0]
    else:
        cluster = Clusters.objects.filter(id=cluster_id)[0]

    ansible_client = AnsibleClient()

    ansible_client.run_delete_kubernetes_user(user_id,
                                              str(cluster.id),
                                              cluster.title,
                                              username,
                                              kubeconfig_value
                                              )
    return

@shared_task(ignore_result=False, time_limit=5400)
def worker_cancel_cluster_creation(cluster_id, user_id):
    max_retries = 240
    wait_seconds = 20
    for _ in range(0, max_retries):
        time.sleep(wait_seconds)
        cluster = Clusters.objects.filter(id=cluster_id)[0]
        if cluster.installstep == 1:
            continue
        else:
            break
    
    # cancel creation task
    celerytask_id = CeleryTask.objects.filter(user=user_id, cluster=cluster)[0].task_id
    install_task = AsyncResult(celerytask_id)

    install_task.revoke(terminate=True)

    cluster.installstep = 100
    cluster.save()

    # submit deletion
    worker_delete_cluster(cluster_id, user_id)


@shared_task(ignore_result=False, time_limit=300)
def worker_create_azure_oauth_credentials(payload, user_id, daiteap_user_id):
    user = User.objects.filter(id=user_id)[0]
    daiteap_user = DaiteapUser.objects.filter(id=daiteap_user_id)[0]
    try:
        azure_auth_client = AzureAuthClient(authorize_tenant=payload['tenant'])
        azure_credentials = azure_auth_client.createApp(payload['authCode'], payload['subscriptionId'], payload['origin'], user)
    except Exception as e:
        log_data = {
            'level': 'ERROR',
        }
        logger.error(str(traceback.format_exc()) + '\n' + str(e), extra=log_data)

        return {'error': str(e)}

    azure_credentials['subscriptionId'] = payload['subscriptionId']
    azure_credentials['tenant'] = payload['tenant']

    update_user_cloud_credentials_req_body = {
        "provider": "azure",
        "account_params": {
            "old_label": "azure-oauth-" + azure_credentials['subscriptionId'][0:8],
            "label": "azure-oauth-" + azure_credentials['subscriptionId'][0:8],
            "azure_tenant_id": azure_credentials['tenant'],
            "azure_subscription_id": azure_credentials['subscriptionId'],
            "azure_client_id": azure_credentials['applicationId'],
            "azure_client_secret": azure_credentials['secret']
        }
    }

    request = HttpRequest
    request.user = user
    request.daiteap_user = daiteap_user

    views.__update_user_cloud_credentials(request, update_user_cloud_credentials_req_body)

    return {'success': True}