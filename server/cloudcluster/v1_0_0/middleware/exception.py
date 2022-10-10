import json
import logging
import sys
import traceback

from django.http import HttpResponse
from django.http.response import JsonResponse
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)


class ExceptionMiddleware(MiddlewareMixin):
    def process_exception(self, request, exception):
        log_data = {
            'level': 'ERROR',
            'user_id': str(request.user.id),
        }

        logger.error(traceback.format_exc() + '\n' + str(exception), extra=log_data)

        return JsonResponse({
            'error': {
                'message': 'Internal Server Error'
            }
        }, status=500)
