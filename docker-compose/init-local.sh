#!/bin/sh

DOCKER_COMPOSE=docker-compose.local.yml

# generate ssh keys
mkdir -p docker-compose/.ssh
ssh-keygen -o -a 100 -t rsa -f docker-compose/.ssh/id_rsa -C "user@server.com" -N "" -m PEM

docker-compose -f "$DOCKER_COMPOSE" build
docker-compose -f "$DOCKER_COMPOSE" up -d

# Wait for the database to be ready
sleep 25

docker exec daiteap-ui mkdir -p /app/cloudcluster_media
docker exec daiteap-platform bash /docker-compose/platform-api-migrate.sh
docker exec daiteap-platform python manage.py fix_service_catalog_prod
docker exec daiteap-platform bash /docker-compose/platform-api-init-user.sh
docker exec daiteap-vault vault operator init -key-shares=1 -key-threshold=1 -format=json > docker-compose/vault/vault-init.json
docker exec daiteap-vault vault operator unseal $(jq -r .unseal_keys_b64[0] docker-compose/vault/vault-init.json)
export VAULT_TOKEN=$(jq -r .root_token docker-compose/vault/vault-init.json)
docker exec -i daiteap-vault sh -c "export VAULT_TOKEN=$VAULT_TOKEN && echo a$VAULT_TOKEN && vault secrets enable -path=secret kv"

docker-compose -f "$DOCKER_COMPOSE" down

# set VAULT_TOKEN variable
export VAULT_TOKEN=$(jq -r .root_token docker-compose/vault/vault-init.json)

echo "Setup complete. Please now proceed with the export token step."