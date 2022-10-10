INPUT_VALIDATION_SCHEMA = {
    "iotarm": {
        "type": "object",
        "properties": {
                "account": {
                    "type": "number"
                },
            "machines": {
                    "type": "array"
                    },
            "operatingSystem": {
                    "type": "string",
                    "minLength": 6,
                    "maxLength": 200
                    }
        },
        "required": [
            "account",
            "machines",
            "vpcCidr",
            "operatingSystem"
        ]
    },
}
