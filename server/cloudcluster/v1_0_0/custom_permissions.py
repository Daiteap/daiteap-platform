from django.http import Http404

from rest_framework import exceptions, permissions
from cloudcluster import models
from django.contrib.auth.models import User
from . import views

SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS')

# requires 'projectId' parameter within JSON-formatted payload in request
class ProjectAccessPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        payload, error = views.get_request_body(request)
        if error:
            return False

        projects = models.Project.objects.filter(id=payload['projectId'])
        if len(projects) == 0:
            return False
        project = projects[0]
        
        return project.checkUserAccess(request.daiteap_user)

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
