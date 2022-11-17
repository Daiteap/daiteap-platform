from django.http import Http404

from rest_framework import exceptions, permissions
from cloudcluster import models
from django.contrib.auth.models import User
from . import views

SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS')


class CloudAccountAccessPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.parser_context['kwargs']['tenant_id']
        cloudaccount_id = request.parser_context['kwargs']['cloudaccount_id']

        # check if cloud credential exists in tenant
        try:
            cloudaccount = models.CloudAccount.objects.get(
                id=cloudaccount_id, tenant_id=tenant_id)
        except models.CloudAccount.DoesNotExist:
            return False

        # check if user can access cloud credential
        return cloudaccount.checkUserAccess(request.daiteap_user)


class ProjectAccessPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.parser_context['kwargs']['tenant_id']
        project_id = request.parser_context['kwargs']['project_id']

        # check if project exists in tenant
        try:
            project = models.Project.objects.get(
                id=project_id, tenant_id=tenant_id)
        except models.Project.DoesNotExist:
            return False

        # check if user can access project
        return project.checkUserAccess(request.daiteap_user)


class ClusterAccessPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.parser_context['kwargs']['tenant_id']
        cluster_id = request.parser_context['kwargs']['cluster_id']

        # check if cluster exists in tenant
        try:
            cluster = models.Clusters.objects.get(
                id=cluster_id, project__tenant_id=tenant_id)
        except models.Clusters.DoesNotExist:
            try:
                cluster = models.CapiCluster.objects.get(
                    id=cluster_id, project__tenant_id=tenant_id)
            except models.CapiCluster.DoesNotExist:
                try:
                    cluster = models.YaookCapiCluster.objects.get(
                        id=cluster_id, project__tenant_id=tenant_id)
                except models.YaookCapiCluster.DoesNotExist:
                    return False

        # check if user can access cluster
        return cluster.checkUserAccess(request.daiteap_user)


class EnvironmentTemplateAccessPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.parser_context['kwargs']['tenant_id']
        template_id = request.parser_context['kwargs']['environment_template_id']

        # check if template exists in tenant
        try:
            template = models.EnvironmentTemplate.objects.get(
                id=template_id, tenant_id=tenant_id)
        except models.EnvironmentTemplate.DoesNotExist:
            return False

        # check if user can access template
        return template.checkUserAccess(request.daiteap_user)


class BucketAccessPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.parser_context['kwargs']['tenant_id']
        bucket_id = request.parser_context['kwargs']['bucket_id']

        # check if bucket exists in tenant
        try:
            bucket = models.Bucket.objects.get(
                id=bucket_id, project__tenant_id=tenant_id)
        except models.Bucket.DoesNotExist:
            return False

        # check if user can access bucket
        return bucket.checkUserAccess(request.daiteap_user)


class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.daiteap_user:
            return False

        daiteapuser = request.daiteap_user
        if daiteapuser.isBusinessAccountOwner():
            return True

        return daiteapuser.isAdmin()


class IsUnregistered(permissions.BasePermission):
    def has_permission(self, request, view):
        if hasattr(request, 'userinfo') and request.userinfo and not request.user:
            return True
        else:
            return False
