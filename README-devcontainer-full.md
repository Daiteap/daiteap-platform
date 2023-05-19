# Daiteap Platform Development Environment

## Start Platform
```
./scripts/init-cluster.sh
```

## Set-Up Keycloak
- Login into keycloak at http://localhost:8082 with:
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
- Go to http://localhost:8083
- Register a user
- Enable it in Keycloak from "Users" switch "Email Verified" field to `ON`

## Changing Ports

If you change the ports of Keycloak or the UI, make sure you also edit:
- the value of `keycloakConfig` in `argocd/daiteap-ui.yaml`
- in Keycloak, the frontend url of the realm and the URL settings of `app-vue` and `django-backend` clients

# Delete Cluster
```
./scripts/delete-cluster.sh
```

# Telepresence

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

## Start Local Front-End
```
./scripts/start-local-vuejs-client.sh
```
edit /workspaces/daiteap-ui/app/public/keycloak.json and KC URLs