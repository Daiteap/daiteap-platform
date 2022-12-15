from cloudcluster import models
from cloudcluster.models import Tenant, TenantSettings
from rest_framework import serializers


class TenantSerializer(serializers.ModelSerializer):
    selected = serializers.BooleanField(required=False)

    class Meta:
        model = Tenant
        fields = ("id", "name", "owner", "email", "phone", "company",
                  "status", "created_at", "updated_at", "selected")
        read_only_fields = ("id", "created_at", "updated_at")

    def create(self, validated_data):
        return super().create(validated_data)


class TenantField(serializers.PrimaryKeyRelatedField):
    def to_representation(self, value):
        tenant = models.Tenant.objects.get(pk=value.pk)
        serializer = TenantSerializer(tenant)
        return serializer.data

    def get_queryset(self):
        return Tenant.objects.all()


class ActiveTenantsSerializer(serializers.Serializer):
    activeTenants = TenantSerializer(many=True, required=True)
    selectedTenant = serializers.CharField(required=True)


class TenantSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = TenantSettings
        fields = ("tenant", "enable_compute", "enable_storage", "enable_service_catalog", "enable_templates",
                  "enable_kubernetes_dlcm", "enable_kubernetes_k3s", "enable_kubernetes_capi",
                  "enable_kubernetes_yaookcapi", "advanced_cluster_configuration", "enable_cluster_resize",
                  "providers_enable_gcp", "providers_enable_aws", "providers_enable_ali",
                  "providers_enable_azure", "providers_enable_onprem", "providers_enable_openstack",
                  "providers_enable_arm")
        read_only_fields = ("id", "tenant")

    def create(self, validated_data):
        return super().create(validated_data)


class TenantSettingsField(serializers.PrimaryKeyRelatedField):
    def to_representation(self, value):
        tenant_settings = models.TenantSettings.objects.get(pk=value.pk)
        serializer = TenantSettingsSerializer(tenant_settings)
        return serializer.data

    def get_queryset(self):
        return TenantSettings.objects.all()
