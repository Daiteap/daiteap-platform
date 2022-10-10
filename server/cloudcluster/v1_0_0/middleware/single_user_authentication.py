from cloudcluster import models
from rest_framework import authentication

from cloudcluster.settings import SINGLE_USER_MODE_USERNAME


class SingleUserAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request):
        # Add to userinfo to the view
        request.userinfo = {}

        # Checks if there is a daiteap user
        user = models.User.objects.filter(username=SINGLE_USER_MODE_USERNAME)
        if len(user) > 0:
            request.user = user[0]

            daiteap_user = models.DaiteapUser.objects.filter(user=request.user, selected=True)
            if len(daiteap_user) > 0:
                request.daiteap_user = daiteap_user[0]
            else:
                request.daiteap_user = models.DaiteapUser.objects.filter(user=request.user)[0]
        else:
            request.user = None

        return (request.user, None)