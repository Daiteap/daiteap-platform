#!/bin/bash
# abort processing on the first error
set -e -o pipefail

# load config
. setup.cfg

# Init vault
kubectl -n daiteap exec -it vault-0 -- /bin/sh -c "vault operator init -key-shares=1 -key-threshold=1 -format=json" > docker-compose/vault/vault-init.json
kubectl -n daiteap exec -it vault-0 -- /bin/sh -c "vault operator unseal $(jq -r .unseal_keys_b64[0] docker-compose/vault/vault-init.json)"


