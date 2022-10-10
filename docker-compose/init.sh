#!/bin/sh

docker exec daiteap-ui mkdir -p /app/cloudcluster_media
docker cp docker-compose/service_logo daiteap-ui:/app/cloudcluster_media/
docker exec daiteap-platform bash /docker-compose/platform-api-migrate.sh
docker exec daiteap-platform python manage.py fix_service_catalog_prod
docker exec daiteap-platform bash /docker-compose/platform-api-init-user.sh
