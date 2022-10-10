import json
from wsgiref import validate
import environment_providers.environment_providers as environment_providers
from cloudcluster import models
from cloudcluster.models import CloudAccount
from rest_framework import serializers


class CloudAccountSerializer(serializers.ModelSerializer):
    account_params = serializers.DictField(required=False)
    sharedCredentials = serializers.BooleanField(required=False)
    label = serializers.CharField(required=False)
    credential_data = serializers.DictField(required=False)

    class Meta:
        model = CloudAccount
        fields = ("label", "description", "contact", "created_at", "tenant", "provider", "regions_update_status", "regions_failed_msg", "user", "valid", "shared", "sharedCredentials", "account_params", "id", "credential_data")
        read_only_fields = ("id", "regions_update_status", "regions_failed_msg", "regions")

    def update(self, instance, validated_data):
        if len(models.CloudAccount.objects.filter(tenant_id=self.context.get("request").daiteap_user.tenant_id, label=validated_data['label']).exclude(id=instance.id)) > 0:
            raise serializers.ValidationError("Cloud account with this label already exists")

        if validated_data['sharedCredentials']:
            validated_data['shared'] = True
        else:
            validated_data['shared'] = False

        return super().update(instance, validated_data)

    def create(self, validated_data):
        all_account_labels = [cloud_account.label for cloud_account in models.CloudAccount.objects.filter(tenant_id=self.context.get("request").daiteap_user.tenant_id)]
        request = self.context.get("request")

        try:
            environment_providers.create_cloud_credentials(validated_data, request, all_account_labels)
        except Exception as e:
            raise serializers.ValidationError(e)

        cloudaccount = models.CloudAccount.objects.filter(tenant_id=request.daiteap_user.tenant_id, label=validated_data['account_params']['label'])[0]

        cloudaccount.description = validated_data['account_params']['description']
        cloudaccount.user = request.user

        if validated_data['sharedCredentials']:
            cloudaccount.shared = True
        else:
            cloudaccount.shared = False

        cloudaccount.save()

        return validated_data

class CloudAccountField(serializers.PrimaryKeyRelatedField):
    def to_representation(self, value):
        cloudaccount = models.CloudAccount.objects.get(pk=value.pk)
        serializer = CloudAccountSerializer(cloudaccount)
        return serializer.data

    def get_queryset(self):
        return CloudAccount.objects.all()