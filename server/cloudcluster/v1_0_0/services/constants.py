from enum import Enum
from drf_yasg import openapi

SAVE_PROJECT_VALIDATION_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1024
        },
        "description": {
            "type": "string",
            "maxLength": 1024
        },
    },
    "required": ["name"]
}

ACCOUNT_SAVE_SETTINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "tenant_id": {
            "type": "string"
        },
        "enable_compute": {
            "type": "boolean"
        },
        "enable_storage": {
            "type": "boolean"
        },
        "enable_service_catalog": {
            "type": "boolean"
        },
        "enable_templates": {
            "type": "boolean"
        },
        "enable_kubernetes_dlcm": {
            "type": "boolean"
        },
        "enable_kubernetes_k3s": {
            "type": "boolean"
        },
        "enable_kubernetes_capi": {
            "type": "boolean"
        },
        "enable_kubernetes_yaookcapi": {
            "type": "boolean"
        },
        "providers_enable_gcp": {
            "type": "boolean"
        },
        "providers_enable_aws": {
            "type": "boolean"
        },
        "providers_enable_ali": {
            "type": "boolean"
        },
        "providers_enable_azure": {
            "type": "boolean"
        },
        "providers_enable_onprem": {
            "type": "boolean"
        },
        "providers_enable_openstack": {
            "type": "boolean"
        },
        "providers_enable_arm": {
            "type": "boolean"
        },
    },
    "required": [
        "tenant_id", "enable_compute", "enable_storage", "enable_service_catalog", "enable_templates", "enable_kubernetes_dlcm", 
        "enable_kubernetes_k3s", "enable_kubernetes_capi", "enable_kubernetes_yaookcapi", "providers_enable_gcp", "providers_enable_aws",
        "providers_enable_ali", "providers_enable_azure", "providers_enable_onprem", "providers_enable_openstack",
        "providers_enable_arm"
    ]
}

RESIZE_KUBERNETES_INPUT_VALIDATION_SCHEMA = {
    "type": "object",
    "properties": {
        "clusterID": {
            "type": "string",
            "minLength": 36,
            "maxLength": 36
        },
        "projectId": {
            "type": "string",
            "minLength": 36,
            "maxLength": 36
        },
    },
    "required": ["clusterID", "projectId"]
}

CREATE_KUBERNETES_INPUT_VALIDATION_SCHEMA = {
    "type": "object",
    "properties": {
        "projectId": {
            "type": "string",
            "minLength": 36,
            "maxLength": 36
        },
        "clusterName": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1024
        },
        "load_balancer_integration": {
            "type": "string",
            "maxLength": 1024
        },
        "internal_dns_zone": {
            "type": "string",
            "pattern": r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$',
            "maxLength": 1024
        },
        "kubernetesConfiguration": {
            "type": "object",
            "properties": {
                    "version": {
                        "type": "string",
                        "maxLength": 1024
                    },
                "serviceAddresses": {
                        "type": "string",
                        "maxLength": 1024
                        },
                "podsSubnet": {
                        "type": "string",
                        "maxLength": 1024
                        },
                "networkPlugin": {
                        "type": "string",
                        "maxLength": 1024
                        }
            },
            "required": ["version", "serviceAddresses", "podsSubnet", "networkPlugin"]
        },
    },
    "required": ["projectId", "clusterName", "kubernetesConfiguration", "internal_dns_zone"]
}

CREATE_CAPI_INPUT_VALIDATION_SCHEMA = {
    "type": "object",
    "properties": {
        "projectId": {
            "type": "string",
            "minLength": 36,
            "maxLength": 36
        },
        "clusterName": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1024
        },
        "kubernetesConfiguration": {
                "type": "object",
                "properties": {
                    "version": {
                        "type": "string",
                        "maxLength": 1024
                    },
                },
                "required": ["version"]
            },
    },
    "required": ["projectId", "clusterName", "kubernetesConfiguration"]
}

RESIZE_CAPI_INPUT_VALIDATION_SCHEMA = {
    "type": "object",
    "properties": {
        "clusterID": {
            "type": "string",
            "minLength": 36,
            "maxLength": 36
        }
    },
    "required": ["clusterID"]
}

CREATE_YAOOKCAPI_INPUT_VALIDATION_SCHEMA = {
    "type": "object",
    "properties": {
        "projectId": {
            "type": "string",
            "minLength": 36,
            "maxLength": 36
        },
        "clusterName": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1024
        },
        "kubernetesConfiguration": {
                "type": "object",
                "properties": {
                    "version": {
                        "type": "string",
                        "maxLength": 1024
                    },
                },
                "required": ["version"]
            },
    },
    "required": ["projectId", "clusterName", "kubernetesConfiguration"]
}

RESIZE_YAOOKCAPI_INPUT_VALIDATION_SCHEMA = {
    "type": "object",
    "properties": {
        "clusterID": {
            "type": "string",
            "minLength": 36,
            "maxLength": 36
        }
    },
    "required": ["clusterID"]
}

CREATE_K3S_INPUT_VALIDATION_SCHEMA = {
    "type": "object",
    "properties": {
        "projectId": {
            "type": "string",
            "minLength": 36,
            "maxLength": 36
        },
        "clusterName": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1024
        },
        "load_balancer_integration": {
            "type": "string",
            "maxLength": 1024
        },
        "internal_dns_zone": {
            "type": "string",
            "pattern": r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$',
            "maxLength": 1024
        },
        "kubernetesConfiguration": {
            "type": "object",
            "properties": {
                    "version": {
                        "type": "string",
                        "maxLength": 1024
                    },
                "serviceAddresses": {
                        "type": "string",
                        "maxLength": 1024
                },
                "podsSubnet": {
                        "type": "string",
                        "maxLength": 1024
                },
                "networkPlugin": {
                        "type": "string",
                        "maxLength": 1024
                }
            },
            "required": ["version", "serviceAddresses", "podsSubnet", "networkPlugin"]
        },
    },
    "required": ["projectId", "clusterName", "kubernetesConfiguration", "internal_dns_zone"]
}

CREATE_VMS_INPUT_VALIDATION_SCHEMA = {
    "type": "object",
    "properties": {
        "projectId": {
            "type": "string",
            "minLength": 36,
            "maxLength": 36
        },
        "clusterName": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1024
        },
        "internal_dns_zone": {
            "type": "string",
            "pattern": r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$',
            "maxLength": 1024
        },
    },
    "required": ["projectId", "clusterName", "internal_dns_zone"]
}

CREATE_COMPUTE_VMS_INPUT_VALIDATION_SCHEMA = {
    "type": "object",
    "properties": {
        "projectId": {
            "type": "string",
            "minLength": 36,
            "maxLength": 36
        },
        "clusterName": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1024
        },
    },
    "required": ["projectId", "clusterName"]
}

CANCEL_CLUSTER_CREATION_INPUT_VALIDATION_SCHEMA = {
    "type": "object",
    "properties": {
        "clusterID": {
            "type": "string",
            "minLength": 36,
            "maxLength": 36
        }
    },
    "required": ["clusterID"]
}

PLAN_RESOURCES_INPUT_VALIDATION_SCHEMA = {
    "type": "object",
    "properties": {
            "clusterName": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1024
            },
        "internal_dns_zone": {
                "type": "string",
                "pattern": r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$',
                "maxLength": 1024
            },
    },
    "required": ["internal_dns_zone"]
}

ENVIRONMENT_CONFIG_SCHEMA = openapi.Schema(
    type = openapi.TYPE_OBJECT,
    properties = {
        'type': openapi.Schema(
            type = openapi.TYPE_NUMBER
        ),
        'load_balancer_integration': openapi.Schema(
            type = openapi.TYPE_STRING,
            maxLength = 1024
        ),
        'internal_dns_zone': openapi.Schema(
            type = openapi.TYPE_STRING,
            maxLength = 1024
        ),
        'kubernetesConfiguration': openapi.Schema(
            type = openapi.TYPE_OBJECT,
            properties = {
                'version': openapi.Schema(
                    type = openapi.TYPE_STRING,
                    maxLength = 1024
                ),
                'serviceAddresses': openapi.Schema(
                    type = openapi.TYPE_STRING,
                    maxLength = 1024
                ),
                'podsSubnet': openapi.Schema(
                    type = openapi.TYPE_STRING,
                    maxLength = 1024
                ),
                'networkPlugin': openapi.Schema(
                    type = openapi.TYPE_STRING,
                    maxLength = 1024
                )
            }
        ),
        'awsSelected': openapi.Schema(
            type = openapi.TYPE_BOOLEAN
        ),
        'googleSelected': openapi.Schema(
            type = openapi.TYPE_BOOLEAN
        ),
        'azureSelected': openapi.Schema(
            type = openapi.TYPE_BOOLEAN
        ),
        'openstackSelected': openapi.Schema(
            type = openapi.TYPE_BOOLEAN
        ),
        'onpremiseSelected': openapi.Schema(
            type = openapi.TYPE_BOOLEAN
        ),
        'iotarmSelected': openapi.Schema(
            type = openapi.TYPE_BOOLEAN
        ),
        'alicloudSelected': openapi.Schema(
            type = openapi.TYPE_BOOLEAN
        ),
        'provider_name': openapi.Schema(
            type = openapi.TYPE_OBJECT,
            description = 'One for each selected provider.',
            properties = {
                'account': openapi.Schema(
                    type = openapi.TYPE_NUMBER
                ),
                'region': openapi.Schema(
                    type = openapi.TYPE_STRING
                ),
                'vpcCidr': openapi.Schema(
                    type = openapi.TYPE_STRING
                ),
                'nodes': openapi.Schema(
                    type = openapi.TYPE_ARRAY,
                    items = openapi.Schema(
                        type = openapi.TYPE_OBJECT,
                        properties = {
                            'is_control_plane': openapi.Schema(
                                type = openapi.TYPE_BOOLEAN
                            ),
                            'zone': openapi.Schema(
                                type = openapi.TYPE_STRING
                            ),
                            'instanceType': openapi.Schema(
                                type = openapi.TYPE_STRING,
                                minLength = 6,
                                maxLength = 50
                            ),
                            'operatingSystem': openapi.Schema(
                                type = openapi.TYPE_STRING,
                                minLength = 6,
                                maxLength = 200
                            )
                        }
                    )
                )
            }
        )
    }
)        

TASK_ID_RESPONSE_SCHEMA = openapi.Schema(
    type = openapi.TYPE_OBJECT,
    properties = {
        'taskId': openapi.Schema(
            type = openapi.TYPE_STRING,
            format = openapi.FORMAT_UUID
        )
    }
)

ENV_ID_TASK_ID_RESPONSE_SCHEMA = openapi.Schema(
    type = openapi.TYPE_OBJECT,
    properties = {
        'ID': openapi.Schema(
            type = openapi.TYPE_STRING,
            format = openapi.FORMAT_UUID
        ),
        'taskId': openapi.Schema(
            type = openapi.TYPE_STRING,
            format = openapi.FORMAT_UUID
        )
    }
)

OPENSTACK_CLOUDS_CONF = '''
[Global]
auth-url="{0}"
application-credential-id="{1}"
application-credential-secret="{2}"
'''

# user roles
USER_ROLE_ADMIN = "Admin"
USER_ROLE_OWNER = "Owner"
USER_ROLE_BUSINESSACCOUNTOWNER = "BusinessAccountOwner"
USER_ROLE_REGULAR = "RegularUser"

class ClusterType(Enum):
    DLCM = 1
    VMS = 2
    K3S = 3
    CAPI = 5
    COMPUTE_VMS = 6
    DLCM_V2 = 7
    YAOOKCAPI = 8

class SyncUserTaskStatus(Enum):
    ADD = 1
    REMOVE = 2
    ADD_ERROR = -1
    REMOVE_ERROR = -2
    SYNCHRONIZED = 0