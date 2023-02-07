from cloudcluster import models
from cloudcluster.models import Clusters
from rest_framework import serializers


class ClustersSerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(required=False)
    project_id = serializers.CharField(required=False)
    machines_count = serializers.IntegerField(required=False)
    users_count = serializers.IntegerField(required=False)
    services_count = serializers.IntegerField(required=False)
    name = serializers.CharField(required=False)
    title = serializers.CharField(required=False)
    grafana_admin_password = serializers.CharField(required=False)
    es_admin_password = serializers.CharField(required=False)
    krb_admin_password = serializers.CharField(required=False)
    kdc_master_password = serializers.CharField(required=False)
    ldap_admin_password = serializers.CharField(required=False)
    longhorn_address = serializers.CharField(required=False)
    longhorn_password = serializers.CharField(required=False)
    longhorn_username = serializers.CharField(required=False)
    vpn_secrets = serializers.CharField(required=False)
    ca_password = serializers.CharField(required=False)
    clusterType = serializers.IntegerField(required=False)
    loadBalancerIntegration = serializers.CharField(required=False)
    hasLoadBalancerIntegration = serializers.BooleanField(required=False)
    kubernetesConfiguration = serializers.DictField(required=False)
    errorMsg = serializers.CharField(required=False)
    kubeUpgradeStatus = serializers.IntegerField(required=False)
    terraform_graph_index_path = serializers.CharField(required=False)
    usersList = serializers.ListField(required=False)
    machinesList = serializers.ListField(required=False)
    serviceList = serializers.ListField(required=False)
    providers = serializers.JSONField(required=False)
    resources = serializers.JSONField(required=False)
    config = serializers.JSONField(required=False)
    credentials = serializers.JSONField(required=False)

    class Meta:
        model = Clusters
        fields = ("id", "name", "description", "contact", "created_at", "project", "user",
                  "config", "type", "providers", "status", "title", "daiteap_user", "canceled",
                  "installstep", "resizestep", "kubeconfig", "resizeconfig", "resources",
                  "error_msg", "error_msg_delete", "tfstate", "tfcode", "credentials",
                  "kube_upgrade_status", "grafana_admin_password", "grafana_address",
                  "kibana_address", "es_admin_password", "krb_admin_password", "kdc_master_password",
                  "ldap_admin_password", "vpn_secrets", "ca_password", "used_resources_graph_path",
                  "terraform_graph_index", "gateway_cloud", "machines_count", "users_count", "services_count",
                  "project_id", "project_name", "clusterType", "loadBalancerIntegration",
                  "hasLoadBalancerIntegration", "kubernetesConfiguration", "errorMsg",
                  "kubeUpgradeStatus", "terraform_graph_index_path", "usersList", "machinesList", "serviceList", 'longhorn_address', 'longhorn_password', 'longhorn_username')
        read_only_fields = ("id", "created_at", "project", "user")
        required = ("id", "name")


class ClustersField(serializers.PrimaryKeyRelatedField):
    def to_representation(self, value):
        project = models.Clusters.objects.get(pk=value.pk)
        serializer = ClustersSerializer(project)
        return serializer.data

    def get_queryset(self):
        return Clusters.objects.all()
