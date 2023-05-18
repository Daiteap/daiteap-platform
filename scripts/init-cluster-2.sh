#!/bin/bash

echo --- Set Keycloak Environment Variable ---

argocd app set argocd/daiteap-platform --helm-set keycloakClientSecretKey=$KEYCLOAK_SECRET
kubectl -n daiteap rollout restart deploy platform-api
sleep 60

echo --- Copy Static Files ---

export NFS_POD=$(kubectl -n daiteap get pods --no-headers -o custom-columns=":metadata.name" | grep nfs-server)
kubectl -n daiteap cp docker-compose/service_logo $NFS_POD:/exports/service_logo
kubectl -n daiteap cp docker-compose/drf-yasg $NFS_POD:/exports/drf-yasg

echo --- Execute Database Migrations ---

kubectl -n daiteap wait --timeout=10m --for=condition=ready pod --all
sleep 20
kubectl -n daiteap wait --timeout=10m --for=condition=ready pod --all
sleep 20

export BACKEND_POD=$(kubectl -n daiteap get pods --no-headers -o custom-columns=":metadata.name" | grep platform-api -m 1)
kubectl -n daiteap exec -it $BACKEND_POD -- /bin/sh -c "python3 ./manage.py migrate"
kubectl -n daiteap exec -it $BACKEND_POD -- /bin/sh -c "python3 ./manage.py fix_service_catalog_prod"

echo --- Port-Forward UI ---

kubectl port-forward svc/vuejs-client -n daiteap 8083:8080 &