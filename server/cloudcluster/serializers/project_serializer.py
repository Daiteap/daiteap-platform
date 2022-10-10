from cloudcluster import models
from cloudcluster.models import Project
from rest_framework import serializers


class ProjectSerializer(serializers.ModelSerializer):

    class Meta:
        model = Project
        fields = ("id", "name", "description", "contact", "created_at", "tenant", "user")
        read_only_fields = ("id", "created_at", "tenant", "user")

    def create(self, validated_data):
        if len(models.Project.objects.filter(tenant_id=self.context.get("request").daiteap_user.tenant_id, name=validated_data['name'])) > 0:
            raise serializers.ValidationError('Project with this name already exists')

        return super().create(validated_data)

    def update(self, instance, validated_data):
        if models.Project.objects.filter(tenant_id=self.context.get("request").daiteap_user.tenant_id, name=validated_data['name']).exclude(id=self.instance.id).count() > 0:
            raise serializers.ValidationError("Project with this name already exists")

        return super().update(instance, validated_data)

class ProjectField(serializers.PrimaryKeyRelatedField):
    def to_representation(self, value):
        project = models.Project.objects.get(pk=value.pk)
        serializer = ProjectSerializer(project)
        return serializer.data

    def get_queryset(self):
        return Project.objects.all()