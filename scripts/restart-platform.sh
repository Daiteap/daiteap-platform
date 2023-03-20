#!/bin/bash
# abort processing on the first error
set -e -o pipefail

# load config
. setup.cfg

# Restart daiteap-platform with new configs
echo "> Restart daiteap-platform with new configs"

argocd app delete argocd/daiteap-platform
argocd app create -f argocd/daiteap-platform.yaml
argocd app sync argocd/daiteap-platform
