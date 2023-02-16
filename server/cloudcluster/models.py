import os
from statistics import mode
import uuid
import datetime

from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from cloudcluster.v1_0_0.services.constants import *
# import cloudcluster.v1_0_0.services.constants

class Tenant(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    name = models.TextField(blank=True, null=True, unique=False)
    owner = models.TextField(blank=True, null=True)
    email = models.CharField(max_length=150, blank=True)
    phone = models.TextField(blank=True, null=True)
    company = models.TextField(blank=True, null=True)
    status = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def hasConnectedResources(self):
        users = list(DaiteapUser.objects.filter(tenant_id=self.id))
        clouds = list(CloudAccount.objects.filter(tenant_id=self.id))
        projects = list(Project.objects.filter(tenant_id=self.id))
        templates = list(EnvironmentTemplate.objects.filter(tenant_id=self.id))
        return (len(users) + len(clouds) + len(projects) + len(templates)) > 0

    def hasAllocatedResources(self):
        buckets = list(Bucket.objects.filter(project__tenant_id=self.id))
        clusters = list(Clusters.objects.filter(project__tenant_id=self.id))
        capiclusters = list(CapiCluster.objects.filter(project__tenant_id=self.id))
        yaookclusters = list(YaookCapiCluster.objects.filter(project__tenant_id=self.id))
        cloud_accounts = list(CloudAccount.objects.filter(tenant_id=self.id))
        return (len(buckets) + len(clusters) + len(capiclusters) + len(yaookclusters) + len(cloud_accounts)) > 0

class TenantSettings(models.Model):
    tenant = models.OneToOneField(Tenant, on_delete=models.CASCADE, null=False)

    enable_compute = models.BooleanField(blank=False, null=False, default=True)
    enable_storage = models.BooleanField(blank=False, null=False, default=True)
    enable_service_catalog = models.BooleanField(blank=False, null=False, default=True)
    enable_templates = models.BooleanField(blank=False, null=False, default=True)
    enable_kubernetes_dlcm = models.BooleanField(blank=False, null=False, default=True)
    enable_kubernetes_k3s = models.BooleanField(blank=False, null=False, default=False)
    enable_kubernetes_capi = models.BooleanField(blank=False, null=False, default=False)
    enable_kubernetes_yaookcapi = models.BooleanField(blank=False, null=False, default=False)
    advanced_cluster_configuration = models.BooleanField(blank=False, null=False, default=False)
    enable_cluster_resize = models.BooleanField(blank=False, null=False, default=False)

    providers_enable_gcp = models.BooleanField(blank=False, null=False, default=True)
    providers_enable_aws = models.BooleanField(blank=False, null=False, default=True)
    providers_enable_ali = models.BooleanField(blank=False, null=False, default=False)
    providers_enable_azure = models.BooleanField(blank=False, null=False, default=True)
    providers_enable_onprem = models.BooleanField(blank=False, null=False, default=False)
    providers_enable_openstack = models.BooleanField(blank=False, null=False, default=False)
    providers_enable_arm = models.BooleanField(blank=False, null=False, default=False)

class Project(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, null=True)
    name = models.CharField(max_length=128, blank=False, null=False)
    description = models.CharField(max_length=1024, blank=True, null=True)
    contact = models.CharField(max_length=1024, blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.PROTECT, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # Checks if user should have access to this Project
    # Access rules:
    # - Project belongs to this user
    # - Project has no user association (old Project created before this change)
    # - the user has admin rights
    # - user is added as a member to the project
    def checkUserAccess(self, *args):
        if self.user == None:
            return True
        daiteapuser = args[0]
        if self.user == daiteapuser.user:
            return True
        if daiteapuser.isAdmin():
            return True
        if daiteapuser.isOwner():
            return True
        if daiteapuser.isBusinessAccountOwner():
            return True
        if self in daiteapuser.projects.all():
            return True
        return False

    # checks if project has connected/associated resources
    def hasConnectedResources(self):
        project_clusters = list(Clusters.objects.filter(project_id=self.id))
        capi_clusters = list(CapiCluster.objects.filter(project_id=self.id))
        yaookcapi_clusters = list(YaookCapiCluster.objects.filter(project_id=self.id))
        machines = list(Machine.objects.filter(project_id=self.id))
        buckets = list(Bucket.objects.filter(project_id=self.id))
        return (len(project_clusters) + len(capi_clusters) + len(yaookcapi_clusters) + len(machines) + len(buckets)) > 0

class DaiteapUser(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=20, blank=False, null=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, null=True)
    projects = models.ManyToManyField(Project)
    selected = models.BooleanField(default=False)
    role = models.TextField(blank=True, null=True)

    def isAdmin(self):
        return self.role == USER_ROLE_ADMIN
    
    def isOwner(self):
        return self.role == USER_ROLE_OWNER

    def isBusinessAccountOwner(self):
        return self.role == USER_ROLE_BUSINESSACCOUNTOWNER

    def isRegularUser(self):
        return self.role == USER_ROLE_REGULAR

class Group(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    daiteap_user = models.ManyToManyField(DaiteapUser)

class Policy(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    group = models.ManyToManyField(Group)

class Clusters(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    tfstate = models.TextField(blank=True, null=True)
    config = models.TextField(blank=True, null=True)
    tfcode = models.TextField(blank=True, null=True)
    resources = models.TextField(blank=True, null=True)
    kubeconfig = models.TextField(blank=True, null=True)
    name = models.CharField(max_length=20, blank=False, null=False)
    title = models.CharField(max_length=1024, blank=False, null=False)
    description = models.CharField(max_length=1024, blank=True, null=True)
    contact = models.CharField(max_length=1024, blank=True, null=True)
    error_msg = models.TextField(blank=True, null=True)
    error_msg_delete = models.TextField(blank=True, null=True)
    installstep = models.IntegerField(blank=True, null=True)
    resizestep = models.IntegerField(default=0, blank=True, null=True)
    resizeconfig = models.TextField(blank=True, null=True)
    kube_upgrade_status = models.IntegerField(blank=False, null=False, default=0)
    providers = models.CharField(max_length=254, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    type = models.IntegerField(blank=True, null=True)
    status = models.IntegerField(default=0, blank=True, null=True)
    grafana_admin_password = models.TextField(blank=False, null=False)
    grafana_address = models.CharField(max_length=1024, blank=True, null=True)
    longhorn_address = models.CharField(max_length=1024, blank=True, null=True)
    longhorn_password = models.TextField(blank=False, null=False)
    longhorn_username = models.CharField(max_length=1024, blank=True, null=True)
    kibana_address = models.CharField(max_length=1024, blank=True, null=True)
    es_admin_password = models.TextField(blank=False, null=False)
    krb_admin_password = models.TextField(blank=False, null=False)
    kdc_master_password = models.TextField(blank=False, null=False)
    ldap_admin_password = models.TextField(blank=False, null=False)
    vpn_secrets = models.TextField(blank=False, null=False)
    ca_password = models.TextField(blank=False, null=False)
    used_resources_graph_path = models.TextField(blank=True, null=True)
    terraform_graph_index = models.TextField(blank=True, null=True)
    canceled = models.BooleanField(default=False)
    daiteap_user = models.ForeignKey(DaiteapUser, on_delete=models.CASCADE, null=True)
    user = models.ForeignKey(User, on_delete=models.PROTECT, null=True)
    gateway_cloud = models.CharField(max_length=30, blank=True, null=True)

    def __str__(self):
        return self.title + ' - ' + str(self.id)

    def checkUserAccess(self, *args):
        daiteap_user = args[0]

        return self.project.checkUserAccess(daiteap_user)

# class UserKubeconfig(models.Model):
#     kubeconfig = models.TextField(blank=True, null=True)
#     cluster = models.ForeignKey(Clusters, on_delete=models.CASCADE)
#     daiteapuser = models.ForeignKey(DaiteapUser, on_delete=models.CASCADE)

class EnvironmentTemplate(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, null=True)
    description = models.CharField(max_length=1024, blank=True, null=True)
    contact = models.CharField(max_length=1024, blank=True, null=True)
    name = models.CharField(max_length=1024, blank=False, null=False)
    config = models.TextField(blank=True, null=True)
    providers = models.CharField(max_length=254, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    type = models.IntegerField(blank=True, null=True)
    daiteap_user = models.ForeignKey(DaiteapUser, on_delete=models.CASCADE, null=True)

    # Checks if user should have access to this Template
    # Access rules:
    # - Template belongs to this user
    # - Template has no user association (old Template created before this change)
    # - the user has admin rights
    def checkUserAccess(self, *args):
        if self.daiteap_user == None:
            # print("No user/account association found")
            return True

        if self.daiteap_user.user == None:
            # print("No user/account association found")
            return True

        daiteapuser = args[0]

        if self.daiteap_user == daiteapuser:
            # print("account belongs to user")
            return True

        if daiteapuser.isAdmin():
            # print("user is admin")
            return True

        if daiteapuser.isBusinessAccountOwner():
            return True

        return False

class CapiCluster(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    name = models.CharField(max_length=1024, blank=False, null=False)
    title = models.CharField(max_length=1024, blank=False, null=False)
    description = models.CharField(max_length=1024, blank=True, null=True)
    contact = models.CharField(max_length=1024, blank=True, null=True)
    providers = models.CharField(max_length=254, blank=True, null=True)
    capi_config = models.TextField(blank=True, null=True)
    installstep = models.IntegerField(blank=True, null=True)
    resizestep = models.IntegerField(default=0, blank=True, null=True)
    kubeconfig = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    error_msg = models.TextField(blank=True, null=True)
    type = models.IntegerField(default=5, blank=True, null=True)
    daiteap_user = models.ForeignKey(DaiteapUser, on_delete=models.CASCADE, null=True)
    user = models.ForeignKey(User, on_delete=models.PROTECT, null=True)

class YaookCapiCluster(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    name = models.CharField(max_length=1024, blank=False, null=False)
    title = models.CharField(max_length=1024, blank=False, null=False)
    description = models.CharField(max_length=1024, blank=True, null=True)
    contact = models.CharField(max_length=1024, blank=True, null=True)
    providers = models.CharField(max_length=254, blank=True, null=True)
    yaookcapi_config = models.TextField(blank=True, null=True)
    installstep = models.IntegerField(blank=True, null=True)
    resizestep = models.IntegerField(default=0, blank=True, null=True)
    kubeconfig = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    error_msg = models.TextField(blank=True, null=True)
    type = models.IntegerField(default=5, blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.PROTECT, null=True)
    daiteap_user = models.ForeignKey(DaiteapUser, on_delete=models.CASCADE, null=True)

    wireguard_public_key = models.TextField(blank=False, null=False)
    wireguard_private_key = models.TextField(blank=False, null=False)

    wireguard_indent = models.TextField(blank=True, null=True)

    wireguard_config = models.TextField(blank=False, null=False)

    wireguard_user_configs = models.TextField(blank=False, null=False)


class Machine(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True)
    cluster = models.ForeignKey(Clusters, on_delete=models.CASCADE)
    name = models.CharField(max_length=62, blank=True, null=True)
    type = models.CharField(max_length=20, blank=True, null=True)
    publicIP = models.CharField(max_length=15, blank=True, null=True)
    operating_system = models.CharField(max_length=500, blank=True, null=True)
    privateIP = models.CharField(max_length=15, blank=True, null=True)
    provider = models.CharField(max_length=20, blank=True, null=True)
    instance_id = models.CharField(max_length=40, blank=True, null=True)
    region = models.CharField(max_length=25, blank=True, null=True)
    zone = models.CharField(max_length=30, blank=True, null=True)
    status = models.IntegerField(default=0, blank=True, null=True)
    kube_master = models.BooleanField(blank=True, null=True)
    kube_etcd = models.BooleanField(blank=True, null=True)
    kube_name = models.TextField(blank=True, null=True)
    cpu = models.IntegerField(blank=True, null=True)
    ram = models.IntegerField(blank=True, null=True)
    hdd = models.IntegerField(blank=True, null=True)
    # dns_server = models.BooleanField(blank=False, null=False, default=False)
    sync_ssh_status = models.IntegerField(default=0, blank=True, null=True)
    sync_ssh_error_message = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name + ' - ' + str(self.publicIP)

class CeleryTask(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    cluster = models.ForeignKey(Clusters, null=True, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    task_id = models.CharField(max_length=36, blank=False, null=False)

class TerraformGraphPlan(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    path = models.TextField(blank=True, null=True)

class ClusterUser(models.Model):
    cluster = models.ForeignKey(Clusters, on_delete=models.CASCADE)
    username = models.CharField(max_length=50, blank=True, null=True)
    first_name = models.CharField(max_length=23, blank=True, null=True)
    last_name = models.CharField(max_length=23, blank=True, null=True)
    type = models.CharField(max_length=30, blank=True, null=True)
    public_ssh_key = models.TextField(blank=True, null=True)
    email = models.CharField(max_length=150, blank=True, null=True)
    status = models.IntegerField(blank=True, null=True)
    kubernetes_user = models.BooleanField(null=False)
    kubeconfig = models.TextField(blank=False, null=False)

    def __str__(self):
        return self.username + ' - ' + self.cluster.name

class ServiceCategory(models.Model):
    name = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return self.name

class Service(models.Model):
    name = models.CharField(max_length=50, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    logo_url = models.CharField(max_length=254, blank=True, null=True)
    options = models.TextField(blank=True, null=True)
    values_file = models.TextField(blank=True, null=True)
    categories = models.ManyToManyField(ServiceCategory)
    accessible_from_browser = models.BooleanField(blank=True, null=True, default=True)
    implemented = models.BooleanField(blank=True, null=True, default=False)
    visible = models.BooleanField(blank=True, null=True, default=True)
    supports_multiple_installs = models.BooleanField(blank=True, null=True, default=True)

    def __str__(self):
        return self.name

class ClusterService(models.Model):
    cluster = models.ForeignKey(Clusters, on_delete=models.CASCADE, null=True)
    capi_cluster = models.ForeignKey(CapiCluster, on_delete=models.CASCADE, null=True)
    yaookcapi_cluster = models.ForeignKey(YaookCapiCluster, on_delete=models.CASCADE, null=True)
    name = models.CharField(max_length=50, blank=True, null=True)
    service = models.ForeignKey(Service, null=True, on_delete=models.CASCADE)
    namespace = models.CharField(max_length=23, blank=True, null=True)
    providers = models.CharField(max_length=254, blank=True, null=True)
    publicIP = models.CharField(max_length=15, blank=True, null=True)
    status = models.IntegerField(blank=True, null=True)
    service_type = models.CharField(max_length=15, blank=True, null=True)
    connection_info = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name

class Profile(models.Model):
    def upload_to_profile_pictures(self, filename):
        _, file_extension = os.path.splitext(filename)
        return os.path.join('profile_pictures/', str(self.user.id), 'profile_picture' + file_extension)

    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True)
    picture = models.ImageField(upload_to=upload_to_profile_pictures, blank=True, null=True)
    timezone = models.CharField(max_length=150, blank=False, null=False, default='UTC')

    google_auth_creds = models.BinaryField(blank=True, null=True)

    company = models.TextField(blank=True, null=True)
    phone = models.TextField(blank=True, null=True)

    sshpubkey = models.TextField(blank=True, null=True)
    ssh_synchronized_machines = models.ManyToManyField(Machine, blank=True)
    wireguard_public_key = models.TextField(blank=True, null=True)

    news_subscribbed = models.BooleanField(blank=False, null=False, default=True)

class Statistics(models.Model):
    daiteap_user = models.ForeignKey(DaiteapUser, on_delete=models.CASCADE, null=True)
    request = models.TextField(blank=True, null=True)

    authorized = models.BooleanField(blank=True, null=True)
    requested_at = models.DateTimeField(auto_now_add=True)

class UserConfiguration(models.Model):
    daiteap_user = models.OneToOneField(DaiteapUser, on_delete=models.CASCADE, null=True)
    account_type = models.TextField(blank=True, null=True, default='trial')

    limit_kubernetes_cluster_environments = models.IntegerField(blank=True, null=True, default=1)
    limit_compute_vms_environments = models.IntegerField(blank=True, null=True, default=1)
    limit_nodes = models.IntegerField(blank=True, null=True, default=10)
    limit_services = models.IntegerField(blank=True, null=True, default=3)

class CloudAccount(models.Model):
    label = models.CharField(max_length=100, blank=False, null=False)
    description = models.CharField(max_length=1024, blank=True, null=True)
    contact = models.CharField(max_length=1024, blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    tenant = models.ForeignKey(Tenant, null=False, on_delete=models.CASCADE, default=None)
    credentials = models.TextField(blank=False, null=False)
    provider = models.CharField(max_length=500, blank=False, null=False)
    regions = models.TextField(blank=True, null=True)
    regions_update_status = models.IntegerField(blank=False, null=False, default=-2)
    regions_failed_msg = models.TextField(blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.PROTECT, null=True, default=None)
    valid = models.BooleanField(default=True, null=True)
    shared = models.BooleanField(default=False, null=True)
    cloud_account_info = models.TextField(blank=True, null=True)

    # Checks if user should have access to this CloudAccount
    # Access rules:
    # - CloudAccount belongs to this user
    # - CloudAccount has no user association (old CloudAccounts created before this change)
    # - the user has admin rights
    # - CloudAccount is shared
    def checkUserAccess(self, *args):
        if self.user == None:
            # print("No user/account association found")
            return True

        daiteapuser = args[0]
        if self.user == daiteapuser.user:
            # print("account belongs to user")
            return True

        if daiteapuser.isAdmin():
            # print("user is admin")
            return True

        if self.shared == True:
            return True

        if daiteapuser.isBusinessAccountOwner():
            return True

        return False

class Bucket(models.Model):
    name = models.CharField(max_length=300, blank=False, null=False)
    provider = models.CharField(max_length=7, blank=False, null=False)
    created_at = models.DateTimeField(auto_now_add=True)
    project = models.ForeignKey(Project, on_delete=models.PROTECT, null=False)
    credential = models.ForeignKey(CloudAccount, on_delete=models.PROTECT, null=False)
    storage_account = models.CharField(max_length=1000, blank=True, null=True)
    storage_class = models.CharField(blank=True, null=True, max_length=100)
    bucket_location = models.CharField(blank=True, null=True, max_length=100)
    contact = models.CharField(max_length=1024, blank=True, null=True)
    description = models.CharField(max_length=1024, blank=True, null=True)

    def checkUserAccess(self, *args):
        daiteap_user = args[0]

        return self.project.checkUserAccess(daiteap_user)

@receiver(post_save, sender=DaiteapUser)
def create_user_profile(sender, instance, created, **kwargs):
    print("Creating profile for user")
    if created:
        profile = Profile.objects.filter(user=instance.user)

        if not profile:
            profile = Profile.objects.create(user=instance.user)

class SynchronizedUsers(models.Model):
    daiteapuser = models.ForeignKey(DaiteapUser, on_delete=models.DO_NOTHING, null=False)
    cluster = models.ForeignKey(Clusters, on_delete=models.CASCADE, null=True)
    capicluster = models.ForeignKey(CapiCluster, on_delete=models.CASCADE, null=True)
    yaookcluster = models.ForeignKey(YaookCapiCluster, on_delete=models.CASCADE, null=True)
    synchronized = models.BooleanField(default=False, null=True)