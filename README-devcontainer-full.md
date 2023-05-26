# Daiteap Platform Development Environment

# Requirements:
- kubectl
- curl
- argocd
- kind

# Start Devcontainer
There are 2 ways to start the devcontainer:
1. From VS Code:
- Install Dev Containers extension in VS Code
- From Remote Explorer tab -> Dev Containers -> + New Dev Container -> Open Current Folder in Container (If you don't see it restart VS Code window)
2. From Terminal:
- Install `devcontainers`
- Execute
```sh
# start devcontainer
devcontainer up --workspace-folder .
# start vscode
code .
# attach vscode to the running devcontainer
```

## Changing Ports

By default these ports are used to forward services:
- ArgoCD -> 8000
- Keycloak -> 8082
- UI -> 8083

If any of these ports are already in use on your machine, go through the scripts mentioned below and change the ports to the ones you want to use.

If you change the ports of Keycloak or the UI, make sure you also edit:
- the value of `keycloakConfig` in `argocd/daiteap-ui.yaml`
- in Keycloak, the frontend URL of the realm and the URL settings of `app-vue` and `django-backend` clients

## Start Platform
```
./scripts/init-cluster.sh
```

## Set-Up Keycloak
- Login into keycloak at http://127.0.0.1:8082 with:
    - user -> user
    - password -> kubectl -n daiteap get secret keycloak -o jsonpath='{.data.admin-password}' | base64 --decode
- Create realm using the file `docker-compose/DaiteapRealm.json`
- Create secret in Configure -> Clients -> django-backend -> Credentials -> Regenerate Secret; then copy it and create variable:

```
export KEYCLOAK_SECRET=secret
```

## Finish Platform Creation
```
./scripts/init-cluster-2.sh
```

## Create User
- Go to http://127.0.0.1:8083
- Register a user
- Enable it in Keycloak from "Users" switch "Email Verified" field to `ON`

## Cloud Credentials

For cloud credential creation to be successful, you may need to change some environment variables.

- AWS:

Execute the commands below, but replace `image_owner` with the ID of the AWS account, which owns the compute images you want to use and `image_name` with name of the image. These values are used to retrieve compute images from AWS, so they can be used for cluster creation.

```
argocd app set argocd/daiteap-platform --helm-set awsDaiteapImageOwner=image_owner
argocd app set argocd/daiteap-platform --helm-set awsDaiteapImageName=image_name
argocd app set argocd/celeryworker --helm-set awsDaiteapImageOwner=image_owner
argocd app set argocd/celeryworker --helm-set awsDaiteapImageName=image_name
kubectl -n daiteap rollout restart deploy platform-api
kubectl -n daiteap rollout restart deploy celeryworker
```

- GCP:

Execute the commands below, but replace `key_base64_encoded` with a GCP service account json key encoded in base64. This key is used to give access to the compute images of a GCP project, so they can be used for cluster creation.

```
argocd app set argocd/daiteap-platform --helm-set daiteapImageCredentials=key_base64_encoded
kubectl -n daiteap rollout restart deploy platform-api
```

# Delete Cluster
```
./scripts/delete-cluster.sh
```
