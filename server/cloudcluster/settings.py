import datetime
import os

SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', 'secret-key')

DEBUG = (os.getenv("DJANGO_DEBUG") == 'True')

ALLOWED_HOSTS = os.getenv('DJANGO_ALLOWED_HOSTS', '*')


# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STATIC_ROOT = os.path.join(BASE_DIR, 'static/')

# Application definition

INSTALLED_APPS = [
    # 'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    # 'django.contrib.staticfiles',
    'django.contrib.staticfiles',  # required for serving swagger ui's css/js files
    'drf_yasg',
    'rest_framework',
    'rest_framework.authtoken',
    'cloudcluster',
    'environment_providers',
]

ETC_DIR = '/etc'

SINGLE_USER_MODE = os.getenv('SINGLE_USER_MODE', 'True')
SINGLE_USER_MODE_USERNAME = os.getenv('SINGLE_USER_MODE_USERNAME', 'platformuser')

if SINGLE_USER_MODE == 'True':
    REST_FRAMEWORK_AUTH_CLASS = 'cloudcluster.v1_0_0.middleware.single_user_authentication.SingleUserAuthentication'
else:
    REST_FRAMEWORK_AUTH_CLASS = 'cloudcluster.v1_0_0.keycloak.keycloak_authentication.KeycloakAuthentication'

REST_FRAMEWORK = {
    # Use Django's standard `django.contrib.auth` permissions,
    # or allow read-only access for unauthenticated users.
    'DEFAULT_PERMISSION_CLASSES': [],
    'DEFAULT_AUTHENTICATION_CLASSES': [
        REST_FRAMEWORK_AUTH_CLASS
    ]
}


MIDDLEWARE = [
    "cloudcluster.v1_0_0.middleware.exception.ExceptionMiddleware",
    "django_prometheus.middleware.PrometheusBeforeMiddleware",
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    "django_prometheus.middleware.PrometheusAfterMiddleware",
]

ROOT_URLCONF = 'cloudcluster.urls'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose'
        },
    },
    'formatters': {
        'verbose': {
            '()': 'cloudcluster.v1_0_0.services.custom_log_formatter.CustomisedJSONFormatter'
        }
    },
    'loggers': {
        'cloudcluster': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False
        },
        'celery': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True
        },
    }
}

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'cloudcluster.wsgi.application'


# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        # 'ENGINE': 'mysql.connector.django',
        'NAME': os.getenv('MYSQL_DATABASE'),
        'USER': os.getenv('MYSQL_USER'),
        'PASSWORD': os.getenv('MYSQL_PASS'),
        'HOST': os.getenv('MYSQL_URL'),
        'PORT': os.getenv('MYSQL_PORT'),
        'CONN_MAX_AGE': 0
    },
}

MEDIA_ROOT = os.path.join(BASE_DIR, 'cloudcluster_media')
MEDIA_URL = '/media/'

if DEBUG == True:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.dummy.DummyCache",
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": [
                f"redis://{os.getenv('REDIS_MASTER_ADDRESS', 'redis-master')}:6379/1",
                f"redis://{os.getenv('REDIS_SLAVE_ADDRESS', 'redis-slave')}:6379/1"
            ],
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
                "PASSWORD": os.getenv('REDIS_PASSWORD', '')
            },
            "KEY_PREFIX": "daiteap"
        }
    }

# Cache time to live is 5 minutes.
CACHE_TTL = 60 * 5

SESSION_ENGINE = 'django.contrib.sessions.backends.cache'


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.2/howto/static-files/

STATIC_URL = '/static/'

# email config

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = "smtp.mailgun.org"
EMAIL_PORT = 465
EMAIL_USE_TLS = False
EMAIL_USE_SSL = True
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', '')

EMAIL_API_URL = os.environ.get('EMAIL_API_URL', '')
EMAIL_API_KEY = os.environ.get('EMAIL_API_KEY', '')
SERVER_EMAIL_ADDRESS = os.environ.get('SERVER_EMAIL_ADDRESS', '')

DAITEAP_ENVIRONMENT_URL = os.environ.get('DAITEAP_ENVIRONMENT_URL', '')
DAITEAP_UNSUBSCRIBE_URL = os.environ.get('DAITEAP_UNSUBSCRIBE_URL', '')
DAITEAP_MAIL_URL = os.environ.get('DAITEAP_MAIL_URL', '')

USER_GUIDE_URL = os.environ.get('USER_GUIDE_URL', '')
DAITEAP_LOGO_URL = os.environ.get('DAITEAP_LOGO_URL', '')

# Celery variables

BROKER_USER = os.getenv('BROKER_USER', '')
BROKER_PASSWORD = os.getenv('BROKER_PASSWORD', '')
BROKER_HOST = os.getenv('BROKER_HOST', '')
BROKER_PORT = os.getenv('BROKER_PORT', '5672')
BROKER_VHOST = os.getenv('BROKER_VHOST', '')
BROKER_CONNECTION_TIMEOUT = os.getenv('BROKER_CONNECTION_TIMEOUT', '600')

CELERY_BROKER_URL = f"amqp://{BROKER_USER}:{BROKER_PASSWORD}@{BROKER_HOST}:{BROKER_PORT}/{BROKER_VHOST}"
CELERY_WORKER_SEND_TASK_EVENTS = True
CELERY_TASK_SEND_SENT_EVENT = True

# Kerberos/LDAP variables


LDAP_KUBERNETES_USERS_GROUP_NAME = "kubernetes_users"

AZURE_CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
AZURE_CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')
AZURE_AUTH_SCOPES = os.getenv('AZURE_AUTH_SCOPES')

AZURE_CLIENT_CREATE_APP_URI = '/#/app/platform/cloudprofile/oauth/azure/createapp'
AZURE_CLIENT_AUTHORIZE_URI = '/#/app/platform/cloudprofile/oauth/azure/authorize'
AZURE_CLIENT_ADMINCONSENT_URI = '/#/app/platform/cloudprofile/oauth/azure/adminconsent'

GOOGLE_SERVICE_OAUTH_ACCOUNTS_PREFIX = os.getenv('GOOGLE_SERVICE_OAUTH_ACCOUNTS_PREFIX', 'datera')
AZURE_SERVICE_OAUTH_ACCOUNTS_PREFIX = os.getenv('AZURE_SERVICE_OAUTH_ACCOUNTS_PREFIX', 'datera')

APP_NAME = os.getenv('APP_NAME')
API_GIT_COMMIT_INFO = os.getenv('API_GIT_COMMIT_INFO', 'commit SHA | DATE | TIME UTC')

SSH_USERNAME = os.getenv('SSH_USERNAME', 'clouduser')

DAITEAP_GOOGLE_IMAGE_KEY = os.getenv('DAITEAP_GOOGLE_IMAGE_KEY', '/var/image_credentials/daiteap_image_credentials.json')

CAPI_MANAGEMENT_CLUSTER_NAMESPACE = os.getenv('CAPI_MANAGEMENT_CLUSTER_NAMESPACE', 'default')
YAOOKCAPI_MANAGEMENT_CLUSTER_NAMESPACE = os.getenv('CAPI_MANAGEMENT_CLUSTER_NAMESPACE', 'default')
YAOOKCAPI_MANAGEMENT_CLUSTER_KUBECONFIG_PATH = os.getenv('CAPI_MANAGEMENT_CLUSTER_KUBECONFIG_PATH', '/var/credentials/yaookcapi_mgmnt.yaml')
MAX_AUTOMATIC_RETRIES = 100
CREATE_CAPI_CLUSTER_AUTOMATIC_RETRIES = os.getenv('CREATE_CAPI_CLUSTER_AUTOMATIC_RETRIES', 3)
CREATE_YAOOKCAPI_CLUSTER_AUTOMATIC_RETRIES = os.getenv('CREATE_YAOOKCAPI_CLUSTER_AUTOMATIC_RETRIES', 3)
CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES = os.getenv('CREATE_KUBERNETES_CLUSTER_AUTOMATIC_RETRIES', 3)
CREATE_VMS_AUTOMATIC_RETRIES = os.getenv('CREATE_VMS_AUTOMATIC_RETRIES', 3)

AZURE_STORAGE_LOCATION = os.getenv('AZURE_STORAGE_LOCATION', 'France Central')
AZURE_STORAGE_RESOURCE_GROUP_NAME = os.getenv('AZURE_STORAGE_RESOURCE_GROUP_NAME', 'daiteapoauthstorage')
AZURE_STORAGE_ACCOUNT_NAME_PREFIX = os.getenv('AZURE_STORAGE_ACCOUNT_NAME_PREFIX', 'daiteapoauthstorage')

CAPI_IMAGES_TAG = os.getenv('CAPI_IMAGES_TAG', 'daiteap_capi')
DLCM_IMAGES_TAG = os.getenv('DLCM_IMAGES_TAG', 'daiteap_dlcm_v2')

SUPPORTED_CAPI_KUBERNETES_VERSIONS = [
    '1.20.12',
    '1.21.3'
]

SUPPORTED_YAOOKCAPI_KUBERNETES_VERSIONS = [
    '1.21.4'
]

AWS_DAITEAP_IMAGE_NAME = os.getenv('AWS_DAITEAP_IMAGE_NAME', '')
AWS_DAITEAP_IMAGE_OWNER = os.getenv('AWS_DAITEAP_IMAGE_OWNER', '')
GCP_DAITEAP_IMAGE_PROJECT = os.getenv('GCP_DAITEAP_IMAGE_PROJECT', '')
AZURE_DAITEAP_IMAGE_PARAMETERS = os.getenv('AZURE_DAITEAP_IMAGE_PARAMETERS', '')

SUPPORTED_YAOOKCAPI_OPERATING_SYSTEMS = [
    'ubuntu 20.04',
]

SUPPORTED_OPERATING_SYSTEMS = [
    # 'ubuntu 18.04',
    'ubuntu 20.04',
    'debian 9',
    # 'debian 10'
]

SUPPORTED_KUBERNETES_VERSIONS = [
    'v1.19.7',
    # 'v1.19.6',
    # 'v1.19.5',
    # 'v1.19.4',
    # 'v1.19.3',
    # 'v1.19.2',
    # 'v1.19.1',
    # 'v1.19.0',
    'v1.18.15',
    # 'v1.18.14',
    # 'v1.18.13',
    # 'v1.18.12',
    # 'v1.18.11',
    # 'v1.18.10',
    # 'v1.18.9',
    # 'v1.18.8',
    # 'v1.18.6',
    # 'v1.18.5',
    # 'v1.18.4',
    # 'v1.18.3',
    # 'v1.18.2',
    # 'v1.18.1',
    # 'v1.18.0'
]

SUPPORTED_KUBEADM_VERSIONS = [
    'v1.23.2',
    'v1.22.5',
]

SUPPORTED_KUBEADM_NETWORK_PLUGINS = [
    'flannel',
    # 'calico',
]

SUPPORTED_KUBERNETES_NETWORK_PLUGINS = [
    'flannel',
    'calico',
    'cilium',
    'weave',
]

SUPPORTED_K3S_VERSIONS = [
    'v1.21.1+k3s1',
    'v1.20.6+k3s1',
    'v1.19.10+k3s1',
    # 'v1.18.18+k3s1',
    # 'v1.17.17+k3s1',

]

SUPPORTED_K3S_NETWORK_PLUGINS = [
    'flannel',
]

# Keycloak config
KEYCLOAK_EXEMPT_URIS = ['admin', 'spec', 'isAlive', 'googleoauth', 'azureadminconsent', 'azureauthorize', 'azurecreateapp']
KEYCLOAK_CONFIG = {
    'KEYCLOAK_SERVER_URL': os.getenv('KEYCLOAK_SERVER_URL', ''),
    'KEYCLOAK_REALM': os.getenv('KEYCLOAK_REALM', ''),
    'KEYCLOAK_CLIENT_ID': os.getenv('KEYCLOAK_CLIENT_ID', ''),
    'KEYCLOAK_CLIENT_SECRET_KEY': os.getenv('KEYCLOAK_CLIENT_SECRET_KEY', '')
}
AUTOSUGGEST_OPENSTACK_REGION = os.getenv('AUTOSUGGEST_OPENSTACK_REGION', '')

VAULT_ADDR = os.getenv('VAULT_ADDR', 'http://localhost:8200')
VAULT_TOKEN = os.getenv('VAULT_TOKEN', 'myroot')

USE_DNS_FOR_SERVICES = os.getenv('USE_DNS_FOR_SERVICES', 'False') == 'True'
SERVICES_DNS_DOMAIN = os.getenv('SERVICES_DNS_DOMAIN', 'app.daiteap.com')
SERVICES_DNS_ZONE_NAME = os.getenv('SERVICES_DNS_ZONE_NAME', 'daiteap')
DAITEAP_GOOGLE_KEY = os.getenv('DAITEAP_GCP_KEY_PATH', '/var/dns_credentials/daiteap_dns_credentials.json')

FORCE_SCRIPT_NAME = "/server/"

SWAGGER_SETTINGS = {
    'USE_SESSION_AUTH': False,
    'SECURITY_DEFINITIONS': {
        'Your App API - Swagger': {
            'type': 'oauth2',
            'authorizationUrl': f'{KEYCLOAK_CONFIG["KEYCLOAK_SERVER_URL"]}/realms/{KEYCLOAK_CONFIG["KEYCLOAK_REALM"]}/protocol/openid-connect/auth',
            'flow': 'implicit',
            'nounce': 'my-nonce',
        }
    },
    'OAUTH2_CONFIG': {
          'clientId': KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_ID'],
          'clientSecret': KEYCLOAK_CONFIG['KEYCLOAK_CLIENT_SECRET_KEY'],
        'appName': KEYCLOAK_CONFIG['KEYCLOAK_REALM'],
    },
}
