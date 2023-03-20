#!/bin/bash

# kind create cluster --config kind-example-config.yaml
export KIND_CLUSTER_NAME=cluster1


# create a cluster with the local registry enabled in containerd
cat <<EOF | kind create cluster --name "${KIND_CLUSTER_NAME}" --config=-
# three node (two workers) cluster config
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
EOF

# # install argocd
# kubectl create namespace argocd
# kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.6.2/manifests/install.yaml

# # install argocd cli
# curl -sSL -o argocd-linux-amd64 https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
# sudo install -m 555 argocd-linux-amd64 /usr/local/bin/argocd
# rm argocd-linux-amd64

# # forward argocd port
# kubectl port-forward svc/argocd-server -n argocd 8080:443 &

# # get argocd password
# kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

# # login to argocd
# argocd login localhost:8080 --username admin --password $(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)

# # create daiteap namespace
# kubectl create namespace daiteap

# # create pull secret
# kubectl create secret docker-registry regcred -n daiteap --docker-server "https://eu.gcr.io" --docker-username _json_key --docker-email desislav.arashev@daiteap.com --docker-password="$(cat ./creds.json)"

# # add daiteap-ui repo
# argocd repo add git@gitlab.cst-bg.net:daiteap/daiteap-ui.git --insecure-ignore-host-key --ssh-private-key-path ./id_ed25519
# # create daiteap-ui app
# argocd app create daiteap-ui --repo git@gitlab.cst-bg.net:daiteap/daiteap-ui.git --path helm --dest-server https://kubernetes.default.svc --dest-namespace daiteap

# # delete all apps
# argocd app list | awk '{print $1}' | tail -n +2 | xargs -I {} argocd app delete {} -y

# # create all apps
# for f in $(ls *.yaml); do argocd app create -f $f; done

# # sync all apps
# argocd app list | awk '{print $1}' | tail -n +2 | xargs -I {} argocd app sync {}

# # create mysql databases
# export MYSQL_ROOT_PASSWORD=$(kubectl get secret --namespace daiteap database -o jsonpath="{.data.MYSQL_ROOT_PASSWORD}" | base64 --decode)
# kubectl exec -it $(kubectl get pods -n daiteap | grep database | awk '{print $1}') -n daiteap -- mysql -u root -p$MYSQL_ROOT_PASSWORD -e "CREATE DATABASE IF NOT EXISTS Daiteap; CREATE DATABASE IF NOT EXISTS AM";