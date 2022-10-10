import json
import ast

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from cloudcluster.models import *

class Command(BaseCommand):
    can_import_settings = True
    
    def handle(self, *args, **options):
        with transaction.atomic():
            # Create service categories if missing
            service_categories = ['Web Development', 'DevOps', 'Data & Analytics', 'Databases']

            for category in service_categories:
                if ServiceCategory.objects.filter(name=category).count() == 0:
                    service_category = ServiceCategory(name=category)
                    service_category.save()

            # Create service records if missing
            services = [
                {
                    'name': 'mysql',
                    'logo_url': '/media/service_logo/mysql.png',
                    'description': 'MySQL is a freely available open source Relational Database Management System (RDBMS) that uses Structured Query Language (SQL).',
                    'options': '{"name":{"choice":"custom","type":"string"},"namespace":{"choice":"custom","type":"string","default":"default"},"service_type":{"choice":"single","values":["NodePort","LoadBalancer"],"default":"NodePort"},"cloud_providers":{"choice":"single","values":["google","aws","azure","alicloud","openstack"]},"yamlConfig":true}',
                    'categories': [
                        'Databases'
                    ],
                    'accessible_from_browser': False,
                    'implemented': True
                },
                {
                    'name': 'jupyter-notebook',
                    'logo_url': '/media/service_logo/jupyter-notebook.png',
                    'description': 'The Jupyter Notebook is an open source web application that you can use to create and share documents that contain live code, equations, visualizations, and text.',
                    'options': '{"name": {"choice": "custom", "type": "string"}, "namespace": {"choice": "custom", "type": "string", "default": "default"}, "service_type": {"choice": "single", "values": ["NodePort", "LoadBalancer"], "default": "NodePort"}, "cloud_providers": {"choice": "single", "values": ["google", "aws", "azure", "alicloud", "openstack"]}, "yamlConfig": true}',
                    'categories': [
                        'Data & Analytics'
                    ],
                    'implemented': True
                },
                {
                    'name': 'nginx',
                    'logo_url': '/media/service_logo/nginx-ingress.png',
                    'description': 'NGINX is a free, open-source, high-performance HTTP server and reverse proxy, as well as an IMAP/POP3 proxy server.',
                    'options': '{"name": {"choice": "custom", "type": "string"}, "namespace": {"choice": "custom", "type": "string", "default": "default"}, "service_type": {"choice": "single", "values": ["NodePort", "LoadBalancer"], "default": "NodePort"}, "cloud_providers": {"choice": "multiple", "values": ["google", "aws", "azure", "alicloud", "openstack"]}, "replicas": {"choice": "custom", "type": "int", "default": 1}, "yamlConfig": true}',
                    'categories': [
                        'DevOps'
                    ],
                    'implemented': True
                },
                {
                    'name': 'nextcloud',
                    'logo_url': '/media/service_logo/nextcloud.png',
                    'description': 'Nextcloud is a suite of client-server software for creating and using file hosting services. It is enterprise-ready with comprehensive support options.',
                    'options': '{"name":{"choice":"custom","type":"string"},"namespace":{"choice":"custom","type":"string","default":"default"},"service_type":{"choice":"single","values":["NodePort","LoadBalancer"],"default":"NodePort"},"cloud_providers":{"choice":"single","values":["google","aws","azure","alicloud", "openstack"]},"yamlConfig":true}',
                    'categories': [],
                    'implemented': True
                },
                {
                    'name': 'kubeapps',
                    'logo_url': '/media/service_logo/kubeapps.png',
                    'description': 'Kubeapps is an in-cluster web-based application that enables users with a one-time installation to deploy, manage, and upgrade applications on a Kubernetes cluster.',
                    'options': '{"name":{"choice":"custom","type":"string"},"namespace":{"choice":"custom","type":"string","default":"default"},"service_type":{"choice":"single","values":["NodePort","LoadBalancer"],"default":"NodePort"},"cloud_providers":{"choice":"single","values":["google","aws","azure","alicloud", "openstack"]},"yamlConfig":true}',
                    'categories': [
                        'DevOps'
                    ],
                    'implemented': True
                },
                {
                    'name': 'nginx-ingress',
                    'logo_url': '/media/service_logo/nginx-ingress.png',
                    'description': 'NGINX is a free, open-source, high-performance HTTP server and reverse proxy, as well as an IMAP/POP3 proxy server.',
                    'options': '{"name": {"choice": "custom", "type": "string"}, "namespace": {"choice": "custom", "type": "string", "default": "default"}, "service_type": {"choice": "single", "values": ["NodePort", "LoadBalancer"], "default": "NodePort"}, "cloud_providers": {"choice": "multiple", "values": ["google", "aws", "azure", "alicloud", "openstack"]}, "replicas": {"choice": "custom", "type": "int", "default": 1}, "yamlConfig": true}',
                    'categories': [],
                    'implemented': True,
                    'visible': False,
                },
            ]

            for service in services:
                if Service.objects.filter(name=service['name']).count() == 0:
                    service_obj = Service(name=service['name'],logo_url=service['logo_url'],description=service['description'],options=service['options'])
                    service_obj.save()
                    for category in service['categories']:
                        service_obj.categories.add(ServiceCategory.objects.filter(name=category)[0])
                else:
                    service_obj = Service.objects.filter(name=service['name'])[0]
                    service_obj.logo_url = service['logo_url']
                    service_obj.description = service['description']
                    service_obj.options = service['options']
                    if 'accessible_from_browser' in service:
                        service_obj.accessible_from_browser = service['accessible_from_browser']
                    if 'implemented' in service:
                        service_obj.implemented = service['implemented']
                    if 'visible' in service:
                        service_obj.visible = service['visible']
                    service_obj.save()
                    for category in service['categories']:
                        service_obj.categories.add(ServiceCategory.objects.filter(name=category)[0])
