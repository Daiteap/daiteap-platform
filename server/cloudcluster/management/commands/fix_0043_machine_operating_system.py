from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from cloudcluster.models import *

class Command(BaseCommand):
    can_import_settings = True
    
    def handle(self, *args, **options):
        with transaction.atomic():
            machines = Machine.objects.all()

            for machine in machines:
                machine.operating_system = '-'
                machine.save()
