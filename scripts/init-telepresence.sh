#!/bin/bash

echo --- Install Telepresence + SSHFS ---

sudo sysctl -w fs.inotify.max_user_instances=1000000
sudo sysctl -w fs.inotify.max_user_watches=1000000
sudo curl -fL https://app.getambassador.io/download/tel2/linux/amd64/latest/telepresence -o /usr/local/bin/telepresence
sudo chmod a+x /usr/local/bin/telepresence
sudo apt update
sudo apt install sshfs -y

echo --- Install Telepresence In Cluster ---

telepresence helm install

echo ---- Waiting For Telepresence Pod ----

kubectl -n ambassador wait --for=condition=ready pod --all

echo --- Connect To Cluster ---

telepresence connect
