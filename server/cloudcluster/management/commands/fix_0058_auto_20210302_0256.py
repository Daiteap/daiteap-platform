import json
import ast

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from cloudcluster.models import *

class Command(BaseCommand):
    can_import_settings = True
    
    def handle(self, *args, **options):
        with transaction.atomic():
            all_profiles = Profile.objects.all()

            for profile in all_profiles:
                user = profile.user

                google_accounts = profile.google_accounts.all()

                for account in google_accounts:
                    account.user = user
                    account.save()

                alicloud_accounts = profile.alicloud_accounts.all()

                for account in alicloud_accounts:
                    account.user = user
                    account.save()

                aws_accounts = profile.aws_accounts.all()

                for account in aws_accounts:
                    account.user = user
                    account.save()

                azure_accounts = profile.azure_accounts.all()

                for account in azure_accounts:
                    account.user = user
                    account.save()
                
                onpremise_accounts = profile.onpremise_accounts.all()

                for account in onpremise_accounts:
                    account.user = user
                    account.save()
