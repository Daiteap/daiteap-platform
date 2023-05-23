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

## Credentials
- For credential creation to be successful, you may need to change some environment variables in `daiteap-platform` and `celeryworker` apps, in the `values.yaml` files in `helm` directory you can see the names of the vars for a specific provider and change them with:
```
argocd app set argocd/daiteap-platform --helm-set key=value
```
just restart the deployment afterwards:
```
kubectl -n daiteap rollout restart deploy platform-api
```

## Changing Ports
If you change the ports of Keycloak or the UI, make sure you also edit:
- the value of `keycloakConfig` in `argocd/daiteap-ui.yaml`
- in Keycloak, the frontend url of the realm and the URL settings of `app-vue` and `django-backend` clients

# Delete Cluster
```
./scripts/delete-cluster.sh
```

# Telepresence
If you're running the platform in a devcontainer run this command inside:
```
cat ~/.kube/config > ./config
```
and use the config to connect to the cluster outside the container with:
```
export KUBECONFIG=path_to_conf_file
```

## Add Telepresence
```
./scripts/init-telepresence.sh
```

## Check Available Services And Interception Info
```
telepresence -n daiteap list
```

## Get Service Port
```
kubectl -n daiteap get svc service_of_your_choice -o yaml
```

## Intercept Service
```
telepresence -n daiteap intercept service_of_your_choice --port local_port:remote_port --env-file path_to_env_file
```
path_to_env_file -> file, to which the environment variables from the cluster service will be written, so you can use them when you start the local environment

## Stop Intercept
```
telepresence leave intercept_name
```

# Start Local Front-End
- Run the commands from this script `scripts/start-local-vuejs-client.sh` in the folder where you have the `daiteap-ui` repo
- Change `auth-server-url` in `daiteap-ui/app/public/keycloak.json`
- in Keycloak, change the URL settings of `app-vue` and `django-backend` clients
- Edit and copy `./docker-compose/cloudcluster.conf` to `/etc/nginx/sites-enabled/cloudcluster.conf` and restart Nginx with `sudo service nginx restart`
- Access the UI on http://127.0.0.1:8090