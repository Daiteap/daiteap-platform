#!/bin/bash
# abort processing on the first error
set -e -o pipefail

# load config
. setup.cfg

# Redirect ports of keycloak and daiteap-ui
echo "> waiting for platform-ui pod to be ready"
POD=$(kubectl -n daiteap get pods | grep ^vuejs-client- | awk '{print $1}' | head -n 1)
kubectl -n daiteap wait --timeout=5m --for=condition=ready pod/$POD

echo "> redirect ports of keycloak and daiteap-ui"
kubectl port-forward svc/keycloak -n daiteap 8082:80 &
kubectl port-forward svc/vuejs-client -n daiteap 8083:8080 &
