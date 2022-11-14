from django.http import Http404

from rest_framework import exceptions, permissions
from cloudcluster import models
from django.contrib.auth.models import User
from . import views

SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS')


class TenantAccessPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.parser_context['kwargs']['tenant_id']
        user = request.user

        # check if tenant exists
        try:
            tenant = models.Tenant.objects.get(id=tenant_id)
        except models.Tenant.DoesNotExist:
            return False

        # check if user is in tenant
        try:
            daiteap_user = models.DaiteapUser.objects.get(
                user=user, tenant=tenant)
        except models.DaiteapUser.DoesNotExist:
            return False

        return True


class CloudAccountAccessPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.parser_context['kwargs']['tenant_id']
        cloudaccount_id = request.parser_context['kwargs']['cloudaccount_id']
        user = request.user

        # check if tenant exists
        try:
            tenant = models.Tenant.objects.get(id=tenant_id)
        except models.Tenant.DoesNotExist:
            return False

        # check if user is in tenant
        try:
            daiteap_user = models.DaiteapUser.objects.get(
                user=user, tenant=tenant)
        except models.DaiteapUser.DoesNotExist:
            return False

        # check if cloud credential exists in tenant
        try:
            cloudaccount = models.CloudAccount.objects.get(
                id=cloudaccount_id, tenant_id=tenant_id)
        except models.CloudAccount.DoesNotExist:
            return False

        # check if user can access cloud credential
        if daiteap_user.isAdmin() or cloudaccount.shared or cloudaccount.user == user or cloudaccount.user == None:
            return True
        else:
            return False


class ProjectAccessPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.parser_context['kwargs']['tenant_id']
        project_id = request.parser_context['kwargs']['project_id']
        user = request.user

        # check if tenant exists
        try:
            tenant = models.Tenant.objects.get(id=tenant_id)
        except models.Tenant.DoesNotExist:
            return False

        # check if user is in tenant
        try:
            daiteap_user = models.DaiteapUser.objects.get(
                user=user, tenant=tenant)
        except models.DaiteapUser.DoesNotExist:
            return False

        # check if project exists in tenant
        try:
            project = models.Project.objects.get(
                id=project_id, tenant_id=tenant_id)
        except models.Project.DoesNotExist:
            return False

        # check if user can access project
        if daiteap_user.isAdmin() or project in daiteap_user.projects.all():
            return True
        else:
            return False


class ClusterAccessPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.parser_context['kwargs']['tenant_id']
        cluster_id = request.parser_context['kwargs']['cluster_id']
        user = request.user

        # check if tenant exists
        try:
            tenant = models.Tenant.objects.get(id=tenant_id)
        except models.Tenant.DoesNotExist:
            return False

        # check if user is in tenant
        try:
            daiteap_user = models.DaiteapUser.objects.get(
                user=user, tenant=tenant)
        except models.DaiteapUser.DoesNotExist:
            return False

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
        if daiteap_user.isAdmin() or cluster.project in daiteap_user.projects.all():
            return True
        else:
            return False


class EnvironmentTemplateAccessPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.parser_context['kwargs']['tenant_id']
        template_id = request.parser_context['kwargs']['template_id']
        user = request.user

        # check if tenant exists
        try:
            tenant = models.Tenant.objects.get(id=tenant_id)
        except models.Tenant.DoesNotExist:
            return False

        # check if user is in tenant
        try:
            daiteap_user = models.DaiteapUser.objects.get(
                user=user, tenant=tenant)
        except models.DaiteapUser.DoesNotExist:
            return False

        # check if template exists in tenant
        try:
            template = models.EnvironmentTemplate.objects.get(
                id=template_id, project__tenant_id=tenant_id)
        except models.EnvironmentTemplate.DoesNotExist:
            return False

        # check if user can access template
        if daiteap_user.isAdmin() or template.daiteap_user == daiteap_user:
            return True

        return False


class BucketAccessPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.parser_context['kwargs']['tenant_id']
        bucket_id = request.parser_context['kwargs']['bucket_id']
        user = request.user

        # check if tenant exists
        try:
            tenant = models.Tenant.objects.get(id=tenant_id)
        except models.Tenant.DoesNotExist:
            return False

        # check if user is in tenant
        try:
            daiteap_user = models.DaiteapUser.objects.get(
                user=user, tenant=tenant)
        except models.DaiteapUser.DoesNotExist:
            return False

        # check if bucket exists in tenant
        try:
            bucket = models.Bucket.objects.get(
                id=bucket_id, project__tenant_id=tenant_id)
        except models.Bucket.DoesNotExist:
            return False

        # check if user can access bucket
        if daiteap_user.isAdmin() or bucket.project in daiteap_user.projects.all():
            return True
        else:
            return False


class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.parser_context['kwargs']['tenant_id']
        user = request.user

        # check if tenant exists
        try:
            tenant = models.Tenant.objects.get(id=tenant_id)
        except models.Tenant.DoesNotExist:
            return False

        # check if user is in tenant
        try:
            daiteap_user = models.DaiteapUser.objects.get(
                user=user, tenant=tenant)
        except models.DaiteapUser.DoesNotExist:
            return False

        if daiteap_user.isBusinessAccountOwner():
            return True

        return daiteap_user.isAdmin()


class IsUnregistered(permissions.BasePermission):
    def has_permission(self, request, view):
        if hasattr(request, 'userinfo') and request.userinfo and not request.user:
            return True
        else:
            return False
