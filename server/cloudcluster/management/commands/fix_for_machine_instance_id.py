import json
import ast

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from cloudcluster.models import *

class Command(BaseCommand):
    can_import_settings = True
    
    def handle(self, *args, **options):
        with transaction.atomic():
            machines = Machine.objects.filter(provider__in=['aws', 'alicloud'])

            for machine in machines:
                cluster = Clusters.objects.filter(id=machine.cluster_id)[0]

                resources = ast.literal_eval(cluster.tfstate)['resources']
                for resource in resources:
                    if resource['type'] == 'alicloud_instance':
                        instances = resource['instances']
                        for i in range(len(instances)):
                            if instances[i]['attributes']['private_ip'] == machine.privateIP:
                                machine.instance_id = instances[i]['attributes']['id']
                                machine.save()

                    elif resource['type'] == 'aws_eip':
                        eips = resource['instances']
                        instances = []
                        for resource_option in resources:
                            if resource_option['type'] == 'aws_instance':
                                for instance in resource_option['instances']:
                                    instances.append(instance)
                                break
                        for i in range(len(eips)):
                            if eips[i]['attributes']['private_ip'] == machine.privateIP:
                                machine.instance_id = instances[i]['attributes']['id']
                                machine.save()
