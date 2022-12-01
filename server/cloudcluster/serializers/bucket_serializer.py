import copy
from cloudcluster.serializers.project_serializer import ProjectField
from cloudcluster.serializers.cloud_account_serializer import CloudAccountField

import environment_providers.environment_providers as environment_providers
from cloudcluster.models import Bucket, CloudAccount, Project
from rest_framework import serializers


class BucketSerializer(serializers.ModelSerializer):
    project = ProjectField()
    credential = CloudAccountField()

    class Meta:
        model = Bucket
        fields = ("id", "name", "provider", "created_at", "project", "credential", "storage_account", "storage_class", "bucket_location")
        read_only_fields = ("id", "created_at")

    def create(self, validated_data):
        request = self.context.get("request")
        tenant_id = request.parser_context['kwargs']['tenant_id']

        account = CloudAccount.objects.get(id=validated_data['credential'].id, tenant_id=tenant_id)
        if not account.checkUserAccess(request.daiteap_user):
            raise serializers.ValidationError("You don't have access to this account")
        if account.valid != True:
            raise serializers.ValidationError("This account is not valid")
        project = Project.objects.get(id=validated_data['project'].id, tenant_id=tenant_id)
        if not project.checkUserAccess(request.daiteap_user):
            raise serializers.ValidationError("You don't have access to this project")

        create_storage_bucket_data = copy.deepcopy(validated_data)

        create_storage_bucket_data['credential_id'] = account.id
        create_storage_bucket_data['project_id'] = project.id
        create_storage_bucket_data['bucket_name'] = validated_data['name']

        if 'storage_account' in validated_data:
            create_storage_bucket_data['storage_account_url'] = validated_data['storage_account']

        response = environment_providers.create_storage_bucket(create_storage_bucket_data, request)
        if 'error' in response.keys():
            raise serializers.ValidationError({
                'error': response['error'], })

        bucket = Bucket(
            **validated_data
        )

        bucket.save()

        return bucket
