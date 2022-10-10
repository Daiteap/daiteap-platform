INPUT_VALIDATION_SCHEMA = {
    "onpremise": {
        "type": "object",
        "properties": {
            "account": {
                "type": "number"
            },
            "machines": {
                "type": "string"
            },
            "address": {
                "type": "string",
                "minLength": 6,
                "maxLength": 50
            },
            "operatingSystem": {
                "type": "string",
                "minLength": 6,
                "maxLength": 200
            },
            "vpcCidr": {
                "type": "string"
            }
        },
        "required": [
            "account",
            "machines",
            "vpcCidr",
            "address",
            "operatingSystem"
        ]
    }
}
