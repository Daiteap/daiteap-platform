#!/bin/bash
# abort processing on the first error
set -e -o pipefail

# load config
. setup.cfg

# create KIND cluster
echo "> create KIND cluster"
sysctl -w fs.inotify.max_user_watches=100000
./scripts/kind-cluster.sh
sleep 60

# install argocd
echo "> install argocd"
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.6.2/manifests/install.yaml

# install argocd cli
echo "> install argocd cli"
curl -sSL -o argocd-linux-amd64 https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
sleep 180
sudo install -m 555 argocd-linux-amd64 /usr/local/bin/argocd
rm argocd-linux-amd64

echo "> waiting for argocd-server pod to be ready"
POD=$(kubectl -n argocd get pods | grep ^argocd-server- | awk '{print $1}' | head -n 1)
kubectl -n argocd wait --timeout=5m --for=condition=ready pod/$POD

# forward argocd port
kubectl port-forward svc/argocd-server -n argocd 8080:443 &

# login to argocd
argocd login localhost:8080 --username admin --password $(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d) --insecure

# create daiteap namespace
kubectl create namespace daiteap

# create pull secret
kubectl create secret docker-registry regcred -n daiteap --docker-server "https://eu.gcr.io" --docker-username _json_key --docker-email email@example.com --docker-password="$(cat ./creds.json)"

# add daiteap-ui, daiteap-platform and helm-charts repoes
argocd repo add https://github.com/Daiteap/daiteap-ui.git
argocd repo add git@github.com:Daiteap/daiteap-platform.git
argocd repo add https://charts.bitnami.com/bitnami --type helm --name bitnami
argocd repo add https://helm.releases.hashicorp.com --type helm --name vault

sleep 20

# create all apps
echo "> create apps in argocd"
for f in $(ls argocd/*.yaml); do argocd app create -f $f; done

# sync all apps
argocd app list | awk '{print $1}' | tail -n +2 | xargs -I {} argocd app sync {}

# setup keycloack
echo "> waiting for keycloack pod to be ready"
kubectl -n daiteap wait --timeout=10m --for=condition=ready pod/keycloak-0
kubectl cp docker-compose/themes keycloak-0:/opt/bitnami/keycloak/ -n daiteap

# Redirect ports of keycloak and daiteap-ui
echo "> waiting for platform-ui pod to be ready"
POD=$(kubectl -n daiteap get pods | grep ^vuejs-client- | awk '{print $1}' | head -n 1)
kubectl -n daiteap wait --timeout=5m --for=condition=ready pod/$POD

echo "> redirect ports of keycloak and daiteap-ui"
kubectl port-forward svc/keycloak -n daiteap 8082:80 &
kubectl port-forward svc/vuejs-client -n daiteap 8083:8080 &

echo "> Finish starting the Platform!"

