#!/bin/bash

# Error Interrupt
set -e

LOGFILE="init-cluster-2.log"

echo --- Set Keycloak Environment Variable ---

argocd app set argocd/daiteap-platform --helm-set keycloakClientSecretKey=$KEYCLOAK_SECRET
kubectl -n daiteap rollout restart deploy platform-api
kubectl -n daiteap rollout status deploy platform-api --timeout=15m

echo --- Copy Static Files ---

export NFS_POD=$(kubectl -n daiteap get pods --no-headers -o custom-columns=":metadata.name" | grep nfs-server)
kubectl -n daiteap wait --timeout=15m --for=condition=ready pod $NFS_POD

kubectl -n daiteap cp docker-compose/service_logo $NFS_POD:/exports/service_logo
kubectl -n daiteap cp docker-compose/drf-yasg $NFS_POD:/exports/drf-yasg

echo --- Execute Database Migrations ---

echo ---- Waiting For Platform Pods ----
export BACKEND_POD=$(kubectl get pods -n daiteap -l app=platform-api -o json | jq -r '.items[] | select(.status.phase!="Succeeded" and .status.phase!="Failed") | .metadata.name' | head -n 1)
kubectl -n daiteap wait --timeout=15m --for=condition=ready pod $BACKEND_POD

kubectl -n daiteap exec -it $BACKEND_POD -- /bin/sh -c "python3 ./manage.py migrate"
kubectl -n daiteap exec -it $BACKEND_POD -- /bin/sh -c "python3 ./manage.py fix_service_catalog_prod"

echo --- Restart Back-End Pods ---

kubectl -n daiteap rollout restart deploy platform-api
kubectl -n daiteap rollout status deploy platform-api --timeout=15m
echo ---- Waiting For Platform Pods ----
export BACKEND_POD=$(kubectl get pods -n daiteap -l app=platform-api -o json | jq -r '.items[] | select(.status.phase!="Succeeded" and .status.phase!="Failed") | .metadata.name' | head -n 1)
kubectl -n daiteap wait --timeout=15m --for=condition=ready pod $BACKEND_POD

echo --- Port-Forward UI ---

kubectl port-forward svc/vuejs-client -n daiteap 8083:8080 >$LOGFILE 2>&1 & echo "Port forwarding started. Logs are being saved to $LOGFILE."