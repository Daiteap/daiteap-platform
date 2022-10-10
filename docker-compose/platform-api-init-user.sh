#!/bin/bash
python3 manage.py shell << EOF
from django.contrib.auth.models import User
from cloudcluster import models

user = User.objects.create_user('platformuser', password='platformpass')
user.save()

tenant=models.Tenant.objects.create(name='platformuser', owner='platformuser')

tenant_settings=models.TenantSettings.objects.create(tenant=tenant)
tenant_settings.save()

daiteapuser=models.DaiteapUser.objects.create(user_id=user.id, tenant_id=tenant.id, role='RegularUser', selected=True)
daiteapuser.save()

userconfiguration = models.UserConfiguration.objects.create(daiteap_user=daiteapuser)
userconfiguration.account_type = daiteapuser.role
userconfiguration.limit_kubernetes_cluster_environments=200000
userconfiguration.limit_compute_vms_environments=500000
userconfiguration.limit_nodes=2000000
userconfiguration.limit_services=500000
userconfiguration.save()

quit()
EOF