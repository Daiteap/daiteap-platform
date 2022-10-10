import json
import pathlib

FILE_BASE_DIR = str(pathlib.Path(__file__).parent.absolute().parent)

def get_providers_params():
    config = {}
    with open(FILE_BASE_DIR + '/providers_params.json', 'r') as f:
        config = json.load(f)

    return config