# ========================================================================
# KeycloakMiddleware
# Middleware responsible for intercepting authentication tokens.
#
# Copyright (C) 2020 Marcelo Vinicius de Sousa Campos <mr.225@hotmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import requests
from .keycloak import KeycloakConnect
from cloudcluster import models
from django.conf import settings
from django.http.response import JsonResponse
from rest_framework.exceptions import PermissionDenied, AuthenticationFailed, NotAuthenticated
from rest_framework import authentication


class KeycloakAuthentication(authentication.BaseAuthentication):

    def __init__(self):
        
        # Set configurations from the settings file
        self.config = settings.KEYCLOAK_CONFIG

        # Read keycloak configurations and set each attribute
        try:
            self.server_url = self.config['KEYCLOAK_SERVER_URL']
            self.realm = self.config['KEYCLOAK_REALM']
            self.client_id = self.config['KEYCLOAK_CLIENT_ID']
            self.client_secret_key = self.config['KEYCLOAK_CLIENT_SECRET_KEY']            
        except KeyError as e:
            raise Exception("The mandatory KEYCLOAK configuration variables has not defined.")

        if self.config['KEYCLOAK_SERVER_URL'] is None:
            raise Exception("The mandatory KEYCLOAK_SERVER_URL configuration variables has not defined.")
            
        if self.config['KEYCLOAK_REALM'] is None:
            raise Exception("The mandatory KEYCLOAK_REALM configuration variables has not defined.")
            
        if self.config['KEYCLOAK_CLIENT_ID'] is None:
            raise Exception("The mandatory KEYCLOAK_CLIENT_ID configuration variables has not defined.")
            
        if self.config['KEYCLOAK_CLIENT_SECRET_KEY'] is None:
            raise Exception("The mandatory KEYCLOAK_CLIENT_SECRET_KEY configuration variables has not defined.")

        # Create Keycloak instance
        self.keycloak = KeycloakConnect(server_url=self.server_url,
                                        realm_name=self.realm,
                                        client_id=self.client_id,
                                        client_secret_key=self.client_secret_key)

    def authenticate(self, request):
        # Checks the URIs (paths) that doesn't needs authentication
        if hasattr(settings, 'KEYCLOAK_EXEMPT_URIS'):
            path = request.path_info.lstrip('/')
            if any(re.match(m, path) for m in settings.KEYCLOAK_EXEMPT_URIS):
                return (None, None)

        # Checks if exists an authentication in the http request header
        if 'HTTP_AUTHORIZATION' not in request.META:
            raise AuthenticationFailed('"HTTP_AUTHORIZATION" header is missing.')

        # Get access token in the http request header
        auth_header = request.META.get('HTTP_AUTHORIZATION').split()
        token = auth_header[1] if len(auth_header) == 2 else auth_header[0]

        # Checks token is active
        if not self.keycloak.is_token_active(token):
            return (None, None)

        # Add to userinfo to the view
        request.userinfo = self.keycloak.userinfo(token)

        # Checks if there is a daiteap user
        user = models.User.objects.filter(username=request.userinfo['preferred_username'])
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