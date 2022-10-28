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
                    'implemented': True,
                    'supports_multiple_installs': False
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
                    'name': 'tensorflow-notebook',
                    'logo_url': '/media/service_logo/tensorflow-notebook.png',
                    'description': 'TensorFlow is an open source software library for numerical computation using data flow graphs, and tensorboard is the tool visualizing TensorFlow programs.',
                    'options': '{"name": {"choice": "custom", "type": "string"}, "namespace": {"choice": "custom", "type": "string", "default": "default"}, "service_type": {"choice": "single", "values": ["NodePort", "LoadBalancer"], "default": "NodePort"}, "cloud_providers": {"choice": "single", "values": ["google", "aws", "azure", "alicloud"]}, "yamlConfig": true}',
                    'categories': [
                        'Data & Analytics'
                    ]
                },
                {
                    'name': 'redis',
                    'logo_url': '/media/service_logo/redis.png',
                    'description': 'Redis is an open source (BSD licensed), in-memory data structure store, used as a database, cache, and message broker.',
                    'options': '',
                    'categories': [
                        'Databases'
                    ]
                },
                {
                    'name': 'jenkins',
                    'logo_url': '/media/service_logo/jenkins.png',
                    'description': 'Jenkins is an open source automation server which enables developers around the world to reliably build, test, and deploy their software.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'mongodb',
                    'logo_url': '/media/service_logo/mongodb.png',
                    'description': 'MongoDB is a source-available cross-platform document-oriented database program and is classified as a NoSQL database program.',
                    'options': '',
                    'categories': [
                        'Databases'
                    ]
                },
                {
                    'name': 'rabbitmq',
                    'logo_url': '/media/service_logo/rabbitmq.png',
                    'description': 'RabbitMQ is a message-queueing software also known as a message broker or queue manager.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'mariadb',
                    'logo_url': '/media/service_logo/mariadb.png',
                    'description': 'MariaDB Server is one of the most popular open source relational databases. It is made by the original developers of MySQL and guaranteed to stay open source.',
                    'options': '',
                    'categories': [
                        'Databases'
                    ]
                },
                {
                    'name': 'owncloud',
                    'logo_url': '/media/service_logo/owncloud.png',
                    'description': 'ownCloud is a suite of client–server software for creating and using file hosting services.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'keycloak',
                    'logo_url': '/media/service_logo/keycloak.png',
                    'description': 'Keycloak is an open source Identity and Access Management solution aimed at modern applications and services.It makes it easy to secure applications and services.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'gitlab',
                    'logo_url': '/media/service_logo/gitlab.png',
                    'description': 'GitLab is a web-based DevOps lifecycle tool that provides a Git-repository manager providing wiki, issue-tracking and continuous integration and deployment pipeline features.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'apache-spark',
                    'logo_url': '/media/service_logo/apache-spark.png',
                    'description': 'Apache Spark is a unified analytics engine for large-scale data processing.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'apache-nifi',
                    'logo_url': '/media/service_logo/apache-nifi.png',
                    'description': 'Apache NiFi is a dataflow system based on the concepts of flow-based programming.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'apache-kafka',
                    'logo_url': '/media/service_logo/apache-kafka.png',
                    'description': 'Apache Kafka® is a distributed streaming platform that: Publishes and subscribes to streams of records, similar to a message queue or enterprise messaging system.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'apache-tomcat',
                    'logo_url': '/media/service_logo/apache-tomcat.png',
                    'description': 'Apache Tomcat is an open-source implementation of the Java Servlet, JavaServer Pages, Java Expression Language and WebSocket technologies.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'nodejs',
                    'logo_url': '/media/service_logo/nodejs.png',
                    'description': 'Node.js is an open-source, cross-platform, back-end JavaScript runtime environment that runs on the V8 engine and executes JavaScript code outside a web browser.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'apache-solr',
                    'logo_url': '/media/service_logo/apache-solr.png',
                    'description': 'Solr is an open-source enterprise-search platform, written in Java.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'memcached',
                    'logo_url': '/media/service_logo/memcached.png',
                    'description': 'Memcached is a general-purpose distributed memory-caching system. It is often used to speed up dynamic database-driven websites by caching data and objects in RAM.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'postgresql',
                    'logo_url': '/media/service_logo/postgresql.png',
                    'description': 'PostgreSQL is a free and open-source relational database management system (RDBMS) emphasizing extensibility and SQL compliance.',
                    'options': '',
                    'categories': [
                        'Databases'
                    ]
                },
                {
                    'name': 'grafana',
                    'logo_url': '/media/service_logo/grafana.png',
                    'description': 'Grafana is a multi-platform open source analytics and interactive visualization web application.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'apache',
                    'logo_url': '/media/service_logo/apache.png',
                    'description': 'Apache HTTP Server is a free and open-source web server that delivers web content through the internet.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'couchdb',
                    'logo_url': '/media/service_logo/couchdb.png',
                    'description': 'CouchDB is an open source NoSQL database based on common standards to facilitate Web accessibility and compatibility with a variety of devices.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'cert-manager',
                    'logo_url': '/media/service_logo/cert-manager.png',
                    'description': 'Cert Manager is a native Kubernetes certificate management controller.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'php-myadmin',
                    'logo_url': '/media/service_logo/php-myadmin.png',
                    'description': 'phpMyAdmin is a popular and free open source tool used for administering MySQL with a web browser.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'php-pgadmin',
                    'logo_url': '/media/service_logo/php-pgadmin.png',
                    'description': 'phpPgAdmin is a third-party tool that you can use to manipulate PostgreSQL® databases.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'etcd',
                    'logo_url': '/media/service_logo/etcd.png',
                    'description': 'Etcd is a distributed key-value store designed to securely store data across a cluster.',
                    'options': '',
                    'categories': []
                },
                {
                    'name': 'kubeflow',
                    'logo_url': '/media/service_logo/kubeflow.png',
                    'description': 'Kubeflow is a free and open-source machine learning platform designed to enable using machine learning pipelines to orchestrate complicated workflows running on Kubernetes.',
                    'options': '{"name":{"choice":"custom","type":"string"},"yamlConfig":false}',
                    'categories': []
                },
                {
                    'name': 'istio',
                    'logo_url': '/media/service_logo/istio.png',
                    'description': 'Istio is an open source service mesh platform that provides a way to control how microservices share data with one another.',
                    'options': '',
                    'categories': []
                }
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
                    if 'supports_multiple_installs' in service:
                        service_obj.supports_multiple_installs = service['supports_multiple_installs']
                    service_obj.save()
                    for category in service['categories']:
                        service_obj.categories.add(ServiceCategory.objects.filter(name=category)[0])
