
import datetime
import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

# Application definition

INSTALLED_APPS = [
    # 'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    # 'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework.authtoken',
    'cloudcluster',
]

ETC_DIR = '/etc'

REST_FRAMEWORK = {
    # Use Django's standard `django.contrib.auth` permissions,
    # or allow read-only access for unauthenticated users.
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.DjangoModelPermissionsOrAnonReadOnly'
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_jwt.authentication.JSONWebTokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ),
}

JWT_AUTH = {
    'JWT_VERIFY': True,
    'JWT_VERIFY_EXPIRATION': True,
    'JWT_LEEWAY': 0,
    'JWT_EXPIRATION_DELTA': datetime.timedelta(days=1),
    'JWT_ALLOW_REFRESH': True,
    'JWT_REFRESH_EXPIRATION_DELTA': datetime.timedelta(days=7),
}

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'cloudcluster.urls'

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
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': "sqlLite"
    },
}


# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


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
EMAIL_HOST =  "smtp.mailgun.org"
EMAIL_PORT = 465
EMAIL_USE_TLS = False
EMAIL_USE_SSL = True
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', '')

# Celery variables

BROKER_USER = os.getenv('BROKER_USER')
BROKER_PASSWORD = os.getenv('BROKER_PASSWORD')
BROKER_HOST = os.getenv('BROKER_HOST')
BROKER_PORT = os.getenv('BROKER_PORT')
BROKER_VHOST = os.getenv('BROKER_VHOST')

CELERY_BROKER_URL = f"amqp://{BROKER_USER}:{BROKER_PASSWORD}@{BROKER_HOST}:{BROKER_PORT}/{BROKER_VHOST}"

# Kerberos/LDAP variables

KRB_ADMIN_PASS = os.getenv('KRB_ADMIN_PASS')
KDC_MASTER_PASS = os.getenv('KDC_MASTER_PASS')
LDAP_ADMIN_PASS = os.getenv('LDAP_ADMIN_PASS')

AZURE_CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
AZURE_CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')
AZURE_AUTH_SCOPES = os.getenv('AZURE_AUTH_SCOPES')

AZURE_CLIENT_CREATE_APP_URI = '/app/platform/cloudprofile/oauth/azure/createapp'
AZURE_CLIENT_AUTHORIZE_URI = '/app/platform/cloudprofile/oauth/azure/authorize'
AZURE_CLIENT_ADMINCONSENT_URI = '/app/platform/cloudprofile/oauth/azure/adminconsent'

APP_NAME = os.getenv('APP_NAME')


SECRET_KEY = 'DJANGO_SECRET_KEY'

DEBUG = False

ALLOWED_HOSTS = ['*']

PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

BROKER_USER = 'guest'
BROKER_PASSWORD = 'guest'
BROKER_HOST = '172.17.0.2'
BROKER_PORT = 5672
BROKER_VHOST = ''

CELERY_BROKER_URL = f"amqp://{BROKER_USER}:{BROKER_PASSWORD}@{BROKER_HOST}:{BROKER_PORT}/{BROKER_VHOST}"

KRB_ADMIN_PASS = 'admin'
KDC_MASTER_PASS = 'admin'
LDAP_ADMIN_PASS = 'admin'

GOOGLE_REGIONS = ['']
GOOGLE_INSTANCE_TYPES = ['']
AWS_REGIONS = ['']
AWS_INSTANCE_TYPES = ['']
AZURE_REGIONS = ['']
AZURE_INSTANCE_TYPES = ['']
ALICLOUD_REGIONS = ['']
ALICLOUD_INSTANCE_TYPES = ['']

SUPPORTED_KUBERNETES_VERSIONS = [
    'v1.19.7',
    'v1.19.6',
    'v1.19.5',
    'v1.19.4',
    'v1.19.3',
    'v1.19.2',
    'v1.19.1',
    'v1.19.0',
    'v1.18.15',
    'v1.18.14',
    'v1.18.13',
    'v1.18.12',
    'v1.18.11',
    'v1.18.10',
    'v1.18.9',
    'v1.18.8',
    'v1.18.6',
    'v1.18.5',
    'v1.18.4',
    'v1.18.3',
    'v1.18.2',
    'v1.18.1',
    'v1.18.0'
]

class DisableMigrations(object):
    
    def __contains__(self, item):
        return True

    def __getitem__(self, item):
        return None

import sys
TESTS_IN_PROGRESS = False
if 'test' in sys.argv[1:] or 'jenkins' in sys.argv[1:]:
    PASSWORD_HASHERS = (
        'django.contrib.auth.hashers.MD5PasswordHasher',
    )
    DEBUG = False
    TEMPLATE_DEBUG = False
    TESTS_IN_PROGRESS = True
    MIGRATION_MODULES = DisableMigrations()