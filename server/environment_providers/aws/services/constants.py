INPUT_VALIDATION_SCHEMA = {
    "aws": {
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
    "aws": {
        "type": "object",
        "properties": {
            "label": {
                "type": "string",
                "minLength": 3,
                "maxLength": 100
            },
            "aws_access_key_id": {
                "type": "string",
                "minLength": 20,
                "maxLength": 20
            },
            "aws_secret_access_key": {
                "type": "string",
                "minLength": 40,
                "maxLength": 40
            },
            "description": {
                "type": "string",
                "minLength": 0,
                "maxLength": 1000
            }
        },
        "required": [
            "label",
            "aws_access_key_id",
            "aws_secret_access_key"
        ]
    },
}
