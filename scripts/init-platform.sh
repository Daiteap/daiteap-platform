#!/bin/bash
# abort processing on the first error
set -e -o pipefail

# load config
. setup.cfg

# Init daiteap platform
echo "> Init daiteap platform"
POD=$(kubectl -n daiteap get pods | grep ^celeryworker- | awk '{print $1}' | head -n 1)
kubectl -n daiteap wait --timeout=10m --for=condition=ready pod/$POD

kubectl -n daiteap exec -it $POD -- /bin/sh -c "python3 ./manage.py migrate"
kubectl -n daiteap cp docker-compose/platform-api-init-user.sh $POD:./
kubectl -n daiteap exec -it $POD -- /bin/sh -c "sh platform-api-init-user.sh"



