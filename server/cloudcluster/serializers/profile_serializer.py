from cloudcluster.models import DaiteapUser, Profile
from rest_framework import serializers


class ProfileSerializer(serializers.ModelSerializer):
    role = serializers.SerializerMethodField()

    def get_role(self, obj):
        return DaiteapUser.objects.get(id=self.context.get("request").daiteap_user.id).role

    class Meta:
        model = Profile
        fields = (
            "picture",
            "timezone",
            "company",
            "phone",
            "sshpubkey",
            "wireguard_public_key",
            "role",
            "news_subscribbed",
        )

        read_only_fields = tuple("role")