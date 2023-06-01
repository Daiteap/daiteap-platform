#!/bin/bash

echo --- Delete ArgoCD Apps ---

argocd app list | awk '{print $1}' | tail -n +2 | xargs -I {} argocd app delete {} -y
sleep 60

echo --- Delete Cluster ---

kind delete cluster