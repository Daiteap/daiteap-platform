# How to setup local dev environment using devcontainer

### Commands

```sh
# start devcontainer
devcontainer up --workspace-folder .

# start vscode
code

# attach vscode to the running devcontainer


```


### commands from the devcontainer
```sh
# create KIND cluster
./scripts/kind-cluster.sh

# delete KIND cluster
kind delete clusters cluster1

# install argocd
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.6.2/manifests/install.yaml

# install argocd cli
curl -sSL -o argocd-linux-amd64 https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
sudo install -m 555 argocd-linux-amd64 /usr/local/bin/argocd
rm argocd-linux-amd64

# forward argocd port
kubectl port-forward svc/argocd-server -n argocd 8080:443 &

# get argocd password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

# login to argocd
argocd login localhost:8080 --username admin --password $(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)

# create daiteap namespace
kubectl create namespace daiteap

# create pull secret
#kubectl create secret docker-registry regcred -n daiteap --docker-server "https://eu.gcr.io" --docker-username _json_key --docker-email ignatov@cst-bg.net --docker-password="$(cat ./creds.json)"

# add daiteap-ui, daiteap-platform and helm-charts repoes
argocd repo add https://github.com/Daiteap/daiteap-ui.git
argocd repo add git@gitlab.cst-bg.net:daiteap/helm-charts.git --insecure-ignore-host-key --ssh-private-key-path ./.cred/id_ed25519
argocd repo add git@github.com:Daiteap/daiteap-platform.git
argocd repo add https://charts.bitnami.com/bitnami --type helm --name bitnami
argocd repo add https://helm.releases.hashicorp.com --type helm --name vault

# # delete all apps
# argocd app list | awk '{print $1}' | tail -n +2 | xargs -I {} argocd app delete {} -y

# create all apps
cd argocd
for f in $(ls *.yaml); do argocd app create -f $f; done

# sync all apps
argocd app list | awk '{print $1}' | tail -n +2 | xargs -I {} argocd app sync {}

# copy themes in keycloack pod and redirect port
kubectl cp docker-compose/themes keycloak-0:/opt/bitnami/keycloak/ -n daiteap
kubectl port-forward svc/keycloak -n daiteap 8082:80 &

# Import REALM and create secret for daiteap-platform and configure Redirect URIs for Daiteap-ui in keycloak
- Login into keycloak at http://localhost:8082 with user "user" and password from decoded field "admin-password:" from command:
kubectl get secret keycloak -n daiteap -o yaml
- import REALM in "add realm" using file docker-compose/DaiteapRealm.json
- create secret in Configure->Clients->Django-backend / Credentials / Regenerate Secret , then copy it and enter it in File:Var :
argocd/daiteap-platform.yaml:keycloakClientSecretKey
- Configure Valid Redirect URIs for UI in keycloak
- Enter Configure->Clients->app-vue and in field "Valid Redirect URIs" add *


# Init vault
kubectl -n daiteap exec -it vault-0 -- /bin/sh -c "vault operator init -key-shares=1 -key-threshold=1 -format=json" > docker-compose/vault/vault-init.json
kubectl -n daiteap exec -it vault-0 -- /bin/sh -c "vault operator unseal $(jq -r .unseal_keys_b64[0] docker-compose/vault/vault-init.json)"

Put the "root_token" value from docker-compose/vault/vault-init.json into var vaultToken in argocd/celeryworker.yaml and argocd/daiteap-platform.yaml fails.

# Restart daiteap-platform and celeryworker with new configs
Recreate and sync apps daiteap-platform and celeryworker from argocd:
argocd app delete argocd/daiteap-platform
argocd app create -f argocd/daiteap-platform.yaml
argocd app sync daiteap-platform
argocd app delete argocd/celeryworker
argocd app create -f argocd/celeryworker.yaml
argocd app sync argocd/celeryworker

# Init daiteap platform
Execute following commands with replaced <celeryworker-POD> with name of the celeryworker-POD from 'kubectl get po -n daiteap'.

kubectl -n daiteap exec -it <celeryworker-POD> -- /bin/sh -c "python3 ./manage.py migrate"
kubectl cp docker-compose/platform-api-init-user.sh <celeryworker-POD>:./ -n daiteap
kubectl -n daiteap exec -it <celeryworker-POD> -- /bin/sh -c "sh platform-api-init-user.sh"

# Redirect port of daiteap-ui
kubectl port-forward svc/keycloak -n daiteap 8082:80 & 
kubectl port-forward svc/vuejs-client -n daiteap 8083:8080 &

# Enter Daiteap UI
- enter in Chrome: http://localhost:8083

- register a user

- enable it in keycloak
From "Users" switch "Email Verified" field to ON.


```