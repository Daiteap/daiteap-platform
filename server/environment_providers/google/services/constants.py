INPUT_VALIDATION_SCHEMA = {
    "google": {
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
                            "maxLength": 200
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
    "google": {
        "type": "object",
        "properties": {
            "label": {
                "type": "string",
                "minLength": 3,
                "maxLength": 100
            },
            "google_key": {
                "type": "string",
                "minLength": 10,
                "maxLength": 5000,
            },
            "description": {
                "type": "string",
                "minLength": 0,
                "maxLength": 5000
            }
        },
        "required": [
            "label",
            "google_key"
        ]
    },
}
