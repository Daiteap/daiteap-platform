from cloudcluster import models
from cloudcluster.models import Service
from rest_framework import serializers


class ServiceSerializer(serializers.ModelSerializer):
    categories = serializers.ListField(child=serializers.CharField())

    class Meta:
        model = Service
        fields = ("id", "name", "description", "logo_url", "options", "values_file",
                  "categories", "accessible_from_browser", "implemented", "visible",
                  "supports_multiple_installs")
        read_only_fields = ("id", "name")

    def create(self, validated_data):
        return super().create(validated_data)


class ServiceField(serializers.PrimaryKeyRelatedField):
    def to_representation(self, value):
        service = models.Service.objects.get(pk=value.pk)
        serializer = ServiceSerializer(service)
        return serializer.data

    def get_queryset(self):
        return Service.objects.all()
