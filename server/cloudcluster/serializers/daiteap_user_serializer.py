from cloudcluster.models import DaiteapUser
from rest_framework import serializers


class DaiteapUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = DaiteapUser
        fields = ("__all__")
        read_only_fields = ("id", "user", "tenant")
