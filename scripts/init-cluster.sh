#!/bin/bash

# Error Interrupt
set -e

LOGFILE="init-cluster.log"

echo --- Create KIND Cluster ---

kind create cluster

echo --- Change Kubelet Config ---

docker exec -it kind-control-plane /bin/bash -c 'echo allowedUnsafeSysctls: >> /var/lib/kubelet/config.yaml'
docker exec -it kind-control-plane /bin/bash -c 'echo - "net.core.somaxconn" >> /var/lib/kubelet/config.yaml'
docker exec -it kind-control-plane /bin/bash -c 'systemctl restart kubelet'

echo ---- Waiting For Node ----

kubectl wait --timeout=15m --for=condition=Ready nodes --all
sleep 30

echo --- Create Namespaces ---

kubectl create namespace daiteap
kubectl create namespace argocd

echo --- Install ArgoCD ---

kubectl -n argocd apply -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.6.2/manifests/install.yaml

echo --- Install ArgoCD CLI ---

curl -sSL -o argocd-linux-amd64 https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
sudo install -m 555 argocd-linux-amd64 /usr/local/bin/argocd
rm argocd-linux-amd64

echo --- Port-Forward ArgoCD + Login ---

echo ---- Waiting For ArgoCD Pods ----
sleep 30
kubectl -n argocd wait --timeout=15m --for=condition=ready pod --all
kubectl -n argocd port-forward svc/argocd-server 8000:443 >$LOGFILE 2>&1 & echo "Port forwarding started. Logs are being saved to $LOGFILE."
argocd login localhost:8000 --username admin --password $(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d) --insecure

echo --- Add ArgoCD Repos ---

argocd repo add https://github.com/Daiteap/daiteap-ui.git
argocd repo add https://github.com/Daiteap/daiteap-platform.git
argocd repo add https://github.com/Daiteap/Helms.git
argocd repo add https://helm.releases.hashicorp.com --type helm --name vault

echo --- Create Apps + Sync Apps ---

for f in $(ls argocd/*.yaml); do argocd app create -f $f; done;
sleep 30
argocd app list | awk '{print $1}' | tail -n +2 | xargs -I {} argocd app sync {}

echo --- Configure Vault ---

echo ---- Waiting For DB Pod ----
sleep 60
export DB_POD=$(kubectl -n daiteap get pods --no-headers -o custom-columns=":metadata.name" | grep database)
kubectl -n daiteap wait --timeout=15m --for=jsonpath='{.status.phase}'=Running pod/$DB_POD
sleep 60
kubectl -n daiteap exec -it $DB_POD -- mysql -u'root' -p'pass' -e "grant all privileges on *.* to 'daiteap'@'%';"

echo ---- Waiting For Vault Pod ----
kubectl -n daiteap wait --timeout=15m --for=jsonpath='{.status.phase}'=Running pod/vault-0
sleep 30
kubectl -n daiteap exec -it vault-0 -- /bin/sh -c "vault operator init -key-shares=1 -key-threshold=1 -format=json" > docker-compose/vault/vault-init.json
kubectl -n daiteap exec -it vault-0 -- /bin/sh -c "vault operator unseal $(jq -r .unseal_keys_b64[0] docker-compose/vault/vault-init.json)"
kubectl -n daiteap exec -it vault-0 -- /bin/sh -c "vault login $(jq -r '.root_token' docker-compose/vault/vault-init.json)"
kubectl -n daiteap exec -it vault-0 -- /bin/sh -c "vault secrets enable -version=1 -path secret kv"

argocd app set argocd/daiteap-platform --helm-set vaultToken=$(jq -r '.root_token' docker-compose/vault/vault-init.json)
argocd app set argocd/celeryworker --helm-set vaultToken=$(jq -r '.root_token' docker-compose/vault/vault-init.json)

echo --- Copy Themes + Port-Forward Keycloak ---

echo ---- Waiting For Keycloak Pod ----
sleep 45
kubectl -n daiteap wait --timeout=15m --for=jsonpath='{.status.phase}'=Running pod/keycloak-0
kubectl -n daiteap cp docker-compose/themes keycloak-0:/opt/bitnami/keycloak/
kubectl -n daiteap port-forward svc/keycloak 8082:80 >>$LOGFILE 2>&1 & echo "Port forwarding started. Logs are being saved to $LOGFILE."
