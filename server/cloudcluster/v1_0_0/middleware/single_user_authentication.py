from cloudcluster import models
from rest_framework import authentication
from rest_framework.exceptions import PermissionDenied

from cloudcluster.settings import SINGLE_USER_MODE_USERNAME


class SingleUserAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request):
        # Add to userinfo to the view
        request.userinfo = {}

        # Checks if there is a daiteap user
        user = models.User.objects.filter(username=SINGLE_USER_MODE_USERNAME)
        if len(user) > 0:
            request.user = user[0]

            if 'tenant_id' in request.parser_context['kwargs']:
                tenant_id = request.parser_context['kwargs']['tenant_id']
                try:
                    daiteap_user = models.DaiteapUser.objects.get(user=request.user, tenant_id=tenant_id)
                    request.daiteap_user = daiteap_user
                except:
                    raise PermissionDenied('You do not have access to this tenant.')
            else:
                try:
                    daiteap_user = models.DaiteapUser.objects.get(user=request.user, selected=True)
                except:
                    daiteap_user = models.DaiteapUser.objects.filter(user=request.user)[0]
                request.daiteap_user = daiteap_user
        else:
            request.user = None

        return (request.user, None)