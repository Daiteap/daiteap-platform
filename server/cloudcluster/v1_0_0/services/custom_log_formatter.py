import logging
import json_log_formatter
from . import data_masker

class CustomisedJSONFormatter(json_log_formatter.JSONFormatter):
    def json_record(self, message: str, extra: dict, record: logging.LogRecord) -> dict:
        if 'data' in extra:
            if 'args' in extra['data']:
                extra['data']['args'] = data_masker.mask_in_string(extra['data']['args'])
            if 'return_value' in extra['data']:
                extra['data']['return_value'] = data_masker.mask_in_string(extra['data']['return_value'])

        extra['message'] = data_masker.mask_in_string(message)

        return extra