INPUT_VALIDATION_SCHEMA = {
    "openstack": {
        "type": "object",
        "properties": {
            "account": {
                "type": "number"
            },
            "region": {
                "type": "string"
            },
            "vpcCidr": {
                "type": "string"
            },
            "nodes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "is_control_plane": {
                            "type": "boolean"
                        },
                        "zone": {
                            "type": "string"
                        },
                        "instanceType": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 50
                        },
                        "operatingSystem": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 200
                        }
                    },
                    "required": [
                        "is_control_plane",
                        "instanceType",
                        "operatingSystem"
                    ]
                }
            }
        },
        "required": [
            "region",
            "vpcCidr",
            "account",
            "nodes",
        ]
    },
}

CREDENTIALS_INPUT_VALIDATION_SCHEMA = {
    "openstack": {
        "type": "object",
        "properties": {
            "label": {
                "type": "string",
                "minLength": 3,
                "maxLength": 100
            },
            "application_credential_id": {
                "type": "string",
                "minLength": 32,
                "maxLength": 32
            },
            "application_credential_secret": {
                "type": "string"
            },
            "region_name": {
                "type": "string"
            },
            "auth_url": {
                "type": "string"
            },
            "external_network_id": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            }
        },
        "required": [
            "label",
            "application_credential_id",
            "application_credential_secret",
            "region_name",
            "auth_url",
            "external_network_id"
        ]
    },
}
