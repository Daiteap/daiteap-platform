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
argocd login localhost:8000 --username admin --password "$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)" --insecure

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
export DB_POD
DB_POD=$(kubectl -n daiteap get pods --no-headers -o custom-columns=":metadata.name" | grep database)
kubectl -n daiteap wait --timeout=15m --for=jsonpath='{.status.phase}'=Running pod/"$DB_POD"
sleep 60
kubectl -n daiteap exec -it "$DB_POD" -- mysql -h 127.0.0.1 -u'root' -p'pass' -e "grant all privileges on *.* to 'daiteap'@'%';"

echo ---- Waiting For Vault Pod ----
kubectl -n daiteap wait --timeout=15m --for=jsonpath='{.status.phase}'=Running pod/vault-0
sleep 60
kubectl -n daiteap exec -it vault-0 -- /bin/sh -c "vault operator init -key-shares=1 -key-threshold=1 -format=json" > docker-compose/vault/vault-init.json
kubectl -n daiteap exec -it vault-0 -- /bin/sh -c "vault operator unseal $(jq -r .unseal_keys_b64[0] docker-compose/vault/vault-init.json)"
kubectl -n daiteap exec -it vault-0 -- /bin/sh -c "vault login $(jq -r '.root_token' docker-compose/vault/vault-init.json)"
kubectl -n daiteap exec -it vault-0 -- /bin/sh -c "vault secrets enable -version=1 -path secret kv"

argocd app set argocd/daiteap-platform --helm-set vaultToken="$(jq -r '.root_token' docker-compose/vault/vault-init.json)"
argocd app set argocd/daiteap-platform --helm-set-string djangoDebug=True
argocd app set argocd/celeryworker --helm-set-string djangoDebug=True
argocd app set argocd/celeryworker --helm-set vaultToken="$(jq -r '.root_token' docker-compose/vault/vault-init.json)"

echo --- Configure Keycloak ---

echo ---- Waiting For Keycloak Pod ----
sleep 45
kubectl -n daiteap wait --timeout=15m --for=jsonpath='{.status.phase}'=Running pod/keycloak-0
export KC_PASS
KC_PASS=$(kubectl -n daiteap get secret keycloak -o jsonpath='{.data.admin-password}' | base64 --decode)
sleep 30

echo ---- Copy Files To Pod ----
kubectl -n daiteap cp docker-compose/themes keycloak-0:/opt/bitnami/keycloak/
kubectl -n daiteap cp docker-compose/DaiteapRealm.json keycloak-0:/realm.json

echo ---- Import Daiteap Realm ----
kubectl -n daiteap exec -it keycloak-0 -- /bin/sh -c "/opt/bitnami/keycloak/bin/kcadm.sh config credentials --server http://keycloak:80/auth --realm master --user user --password $KC_PASS"
kubectl -n daiteap exec -it keycloak-0 -- /bin/sh -c "/opt/bitnami/keycloak/bin/kcadm.sh create realms -f /realm.json -s realm=Daiteap -s enabled=true"

echo ---- Port-Forward Service ----
kubectl -n daiteap port-forward svc/keycloak 8082:80 >>$LOGFILE 2>&1 & echo "Port forwarding started. Logs are being saved to $LOGFILE."
sleep 30

echo ---- Regenerate Client Secret ----
export KC_TOKEN
KC_TOKEN=$(curl -X POST http://localhost:8082/auth/realms/master/protocol/openid-connect/token \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H "Accept: application/json" \
    -d username="user" \
    -d password="$KC_PASS" \
    -d grant_type=password \
    -d client_id="admin-cli" \
    | jq -r '.access_token')
export CLIENT_ID
CLIENT_ID=$(curl -X GET http://localhost:8082/auth/admin/realms/Daiteap/clients \
    -H 'Content-Type: application/json' \
    -H "Authorization: bearer $KC_TOKEN" \
    | jq -r --arg client_id "django-backend" '.[] | select(.clientId == $client_id) | .id')
export KEYCLOAK_SECRET
KEYCLOAK_SECRET=$(curl -X POST "http://localhost:8082/auth/admin/realms/Daiteap/clients/$CLIENT_ID/client-secret" \
    -H 'Content-Type: application/json' \
    -H "Authorization: bearer $KC_TOKEN" \
    | jq -r '.value')

echo --- Set Keycloak Environment Variable ---

argocd app set argocd/daiteap-platform --helm-set keycloakClientSecretKey="$KEYCLOAK_SECRET"
kubectl -n daiteap rollout restart deploy platform-api
echo ---- Waiting For Platform Pods ----
kubectl -n daiteap rollout status deploy platform-api --timeout=15m
sleep 30

echo --- Copy Static Files ---

export NFS_POD
NFS_POD=$(kubectl -n daiteap get pods --no-headers -o custom-columns=":metadata.name" | grep nfs-server)
kubectl -n daiteap wait --timeout=15m --for=condition=ready pod "$NFS_POD"

kubectl -n daiteap cp docker-compose/service_logo "$NFS_POD":/exports/service_logo
kubectl -n daiteap cp docker-compose/drf-yasg "$NFS_POD":/exports/drf-yasg

echo --- Execute Database Migrations ---

echo ---- Waiting For Platform Pods ----
export BACKEND_POD
BACKEND_POD=$(kubectl get pods -n daiteap -l app=platform-api -o json | jq -r '.items[] | select(.status.phase!="Succeeded" and .status.phase!="Failed") | .metadata.name' | head -n 1)
kubectl -n daiteap wait --timeout=15m --for=condition=ready pod "$BACKEND_POD"

kubectl -n daiteap exec -it "$BACKEND_POD" -- /bin/sh -c "python3 ./manage.py migrate"
kubectl -n daiteap exec -it "$BACKEND_POD" -- /bin/sh -c "python3 ./manage.py fix_service_catalog_prod"

echo --- Restart Back-End Pods ---

kubectl -n daiteap rollout restart deploy platform-api
echo ---- Waiting For Platform Pods ----
kubectl -n daiteap rollout status deploy platform-api --timeout=15m

echo --- Port-Forward UI ---

kubectl port-forward svc/vuejs-client -n daiteap 8083:8080 >$LOGFILE 2>&1 & echo "Port forwarding started. Logs are being saved to $LOGFILE."
