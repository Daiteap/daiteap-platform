from cloudcluster import models
from cloudcluster.models import EnvironmentTemplate
from rest_framework import serializers


class EnvironmentTemplateSerializer(serializers.ModelSerializer):
    config = serializers.JSONField(required=False)

    class Meta:
        model = EnvironmentTemplate
        fields = ("id", "name", "description", "contact",
                  "created_at", "tenant", "config",
                  "providers", "type", "daiteap_user")
        read_only_fields = ("id", "created_at", "tenant", "daiteap_user")

    def create(self, validated_data):
        if len(models.EnvironmentTemplate.objects.filter(tenant_id=self.context.get("request").daiteap_user.tenant_id, name=validated_data['name'])) > 0:
            raise serializers.ValidationError(
                'Environment template with this name already exists.')

        return super().create(validated_data)


class EnvironmentTemplateField(serializers.PrimaryKeyRelatedField):
    def to_representation(self, value):
        environment_template = models.EnvironmentTemplate.objects.get(
            pk=value.pk)
        serializer = EnvironmentTemplateSerializer(environment_template)
        return serializer.data

    def get_queryset(self):
        return EnvironmentTemplate.objects.all()
