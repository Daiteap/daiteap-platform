INPUT_VALIDATION_SCHEMA = {
    "azure": {
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
                            "minLength": 6,
                            "maxLength": 50
                        },
                        "operatingSystem": {
                            "type": "string",
                            "minLength": 6,
                            "maxLength": 1024
                        }
                    },
                    "required": [
                        "is_control_plane",
                        "zone",
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
    "azure": {
        "type": "object",
        "properties": {
            "label": {
                "type": "string",
                "minLength": 3,
                "maxLength": 100
            },
            "azure_tenant_id": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            },
            "azure_subscription_id": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            },
            "azure_client_id": {
                "type": "string",
                "minLength": 36,
                "maxLength": 36
            },
            "azure_client_secret": {
                "type": "string",
                "minLength": 5,
                "maxLength": 100
            },
            "description": {
                "type": "string",
                "minLength": 0,
                "maxLength": 1000
            }
        },
        "required": [
            "label",
            "azure_tenant_id",
            "azure_subscription_id",
            "azure_client_id",
            "azure_client_secret"
        ]
    }
}
