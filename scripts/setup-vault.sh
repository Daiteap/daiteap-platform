#!/bin/bash
# abort processing on the first error
set -e -o pipefail

# load config
. setup.cfg

# Setup vault in daiteap-platfor and celeryworker
POD1=$(kubectl -n daiteap get pods | grep ^celeryworker- | awk '{print $1}' | head -n 1)
POD2=$(kubectl -n daiteap get pods | grep ^platform-api- | awk '{print $1}' | head -n 1)

export VAULT_TOKEN=$(jq -r .root_token docker-compose/vault/vault-init.json)
docker -n daiteap exec -it $POD1 -- /bin/sh -c "export VAULT_TOKEN=$VAULT_TOKEN"
docker -n daiteap exec -it $POD2 -- /bin/sh -c "export VAULT_TOKEN=$VAULT_TOKEN"



