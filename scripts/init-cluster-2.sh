#!/bin/bash

echo --- Set Keycloak Environment Variable ---

argocd app set argocd/daiteap-platform --helm-set keycloakClientSecretKey=$KEYCLOAK_SECRET

echo --- Execute Database Migrations ---

export BACKEND_POD=$(kubectl -n daiteap get pods --no-headers -o custom-columns=":metadata.name" | grep platform -m 1)
kubectl -n daiteap exec -it $BACKEND_POD -- /bin/sh -c "python3 ./manage.py migrate"
kubectl cp docker-compose/platform-api-init-user.sh $BACKEND_POD:./ -n daiteap
kubectl -n daiteap exec -it $BACKEND_POD -- /bin/sh -c "sh platform-api-init-user.sh"

echo --- Port-Forward UI ---

kubectl port-forward svc/vuejs-client -n daiteap 8083:8080 &