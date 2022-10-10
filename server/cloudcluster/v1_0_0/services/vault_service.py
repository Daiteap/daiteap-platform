import hvac
from cloudcluster import settings

client = hvac.Client(
    url=settings.VAULT_ADDR,
    token=settings.VAULT_TOKEN
)

def upsert_secret(path, data):
    client.secrets.kv.v2.create_or_update_secret(
        path=path,
        secret=data,
    )

def read_secret(path):
    read_response = client.secrets.kv.v2.read_secret_version(
        path=path,
    )

    return read_response['data']['data']

def delete_secret(path):
    client.secrets.kv.v2.delete_metadata_and_all_versions(
        path=path,
    )

def list_secrets(path):
    try:
        list_response = client.secrets.kv.v2.list_secrets(
            path=path,
        )
    except Exception as e:
        if 'None, on list' in str(e):
            print(e)
            return []
        else:
            raise e

    return list_response['data']['keys']
