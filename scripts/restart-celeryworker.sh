#!/bin/bash
# abort processing on the first error
set -e -o pipefail

# load config
. setup.cfg

# Restart celeryworker with new configs
echo "> Restart celeryworker with new configs"

argocd app delete argocd/celeryworker
argocd app create -f argocd/celeryworker.yaml
argocd app sync argocd/celeryworker