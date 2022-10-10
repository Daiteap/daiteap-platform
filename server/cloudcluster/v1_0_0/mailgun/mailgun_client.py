import json
import logging
import os
from string import Template

import requests
from django.conf import settings

from ...models import CapiCluster, Clusters, Machine, User, YaookCapiCluster
from ..mailgun import templates

logger = logging.getLogger(__name__)

class MailgunClient:

    def __send_mail(self, user_id, template, files=[]):
        user = User.objects.filter(id=user_id)[0]

        if not user.profile.news_subscribbed:
            logger

        recipient_email = User.objects.get(id=user_id).email

        try:
            response = requests.post(
                settings.EMAIL_API_URL,
                auth=("api", settings.EMAIL_API_KEY),
                files=files,
                data={
                    "from": settings.SERVER_EMAIL_ADDRESS,
                    "to": recipient_email,
                    "subject": template['subject'],
                    "html": template['html']
                },
                timeout=500
            )
        except:
            raise Exception('Mailgun timeout')
        
        if response.status_code != 200:
            log_data = {
                'level': 'ERROR',
                'Request': {
                    'url': settings.EMAIL_API_URL,
                    'auth': ("api", settings.EMAIL_API_KEY),
                    'data': {
                        "from": settings.SERVER_EMAIL_ADDRESS,
                        "to": recipient_email,
                        "subject": template['subject'],
                        "html": template['html']
                    },
                    'timeout': 5
                },
                'mailgunResponse': str(response.text),
                'message': 'Mailgun error'
            }
            raise Exception(json.dumps(log_data))


    def email_environment_created(self, user_id, environment_id):
        if User.objects.filter(id=user_id).count() == 0:
            raise Exception('invalid user_id')

        user = User.objects.filter(id=user_id)[0]

        is_capi = False
        is_yaookcapi = False
        try:
            cluster = Clusters.objects.filter(id=environment_id)
            if len(cluster) == 0:
                cluster = CapiCluster.objects.filter(id=environment_id)
                if len(cluster) == 0:
                    cluster = YaookCapiCluster.objects.filter(id=environment_id)[0]
                    is_yaookcapi = True
                else:
                    is_capi = True
            else:
                cluster = cluster[0]
                machines = Machine.objects.filter(cluster=cluster)

        except:
            raise Exception('cluster does not exist')

        template = {}

        if is_capi:
            subject_template = Template(templates.capi_environment_created_template['subject'])
        elif is_yaookcapi:
            subject_template = Template(templates.yaookcapi_environment_created_template['subject'])
        else:
            subject_template = Template(templates.dlcm_environment_created_template['subject'])

        template['subject'] = subject_template.substitute(
            environment_title=cluster.title
        )

        if not is_capi and not is_yaookcapi:
            machines_template = ''

            for machine in machines:
                machine_template = Template(templates.environment_created_machine_template['name-ip'])
                machine_text = machine_template.substitute(
                    machine_name=machine.name,
                    machine_ip=machine.publicIP
                )
                machines_template += machine_text

        daiteap_environment_url = settings.DAITEAP_ENVIRONMENT_URL + str(environment_id) + '/overview'
        daiteap_mail_url = settings.DAITEAP_MAIL_URL + str(environment_id)

        if is_capi:
            html_template = Template(templates.capi_environment_created_template['html'])
            template['html'] = html_template.substitute(
                environment_title=cluster.title,
                daiteap_environment_url=daiteap_environment_url,
                daiteap_unsubscribe_url=settings.DAITEAP_UNSUBSCRIBE_URL,
                daiteap_mail_url=daiteap_mail_url,
                user_guide_url=settings.USER_GUIDE_URL,
                user_names=user.first_name + ' ' + user.last_name
            )
        elif is_yaookcapi:
            html_template = Template(templates.yaookcapi_environment_created_template['html'])
            template['html'] = html_template.substitute(
                environment_title=cluster.title,
                daiteap_environment_url=daiteap_environment_url,
                daiteap_unsubscribe_url=settings.DAITEAP_UNSUBSCRIBE_URL,
                daiteap_mail_url=daiteap_mail_url,
                user_guide_url=settings.USER_GUIDE_URL,
                user_names=user.first_name + ' ' + user.last_name
            )
        else:
            html_template = Template(templates.dlcm_environment_created_template['html'])
            template['html'] = html_template.substitute(
                environment_title=cluster.title,
                daiteap_environment_url=daiteap_environment_url,
                daiteap_unsubscribe_url=settings.DAITEAP_UNSUBSCRIBE_URL,
                daiteap_mail_url=daiteap_mail_url,
                user_guide_url=settings.USER_GUIDE_URL,
                machines=machines_template,
                user_names=user.first_name + ' ' + user.last_name
            )

        files=[
            ('inline[0]', ('image-1.png', open(os.path.join(settings.BASE_DIR + '/cloudcluster/v1_0_0/mailgun/email_images/image-1.png'), mode='rb').read())),
            ('inline[1]', ('image-2.png', open(os.path.join(settings.BASE_DIR + '/cloudcluster/v1_0_0/mailgun/email_images/image-2.png'), mode='rb').read()))
        ]

        self.__send_mail(user_id, template, files)

    def email_environment_creation_failed(self, user_id, environment_title):
        if User.objects.filter(id=user_id).count() == 0:
            raise Exception('invalid user_id')

        if len(environment_title) == 0:
            raise Exception('invalid environment_title')

        template = {}

        subject_template = Template(templates.environment_creation_failed_template['subject'])
        template['subject'] = subject_template.substitute(
            environment_title=environment_title
        )

        text_template = Template(templates.environment_creation_failed_template['text'])
        template['text'] = text_template.substitute(
            environment_title=environment_title
        )

        self.__send_mail(user_id, template)

    def email_welcome_message(self, user_id):
        if User.objects.filter(id=user_id).count() == 0:
            raise Exception('invalid user_id')

        template = {}
        subject_template = Template(templates.welcome_to_platform_template['subject'])

        template['subject'] = subject_template.substitute()

        html_template = Template(templates.welcome_to_platform_template['text'])
        template['html'] = html_template.substitute()

        self.__send_mail(user_id, template)
