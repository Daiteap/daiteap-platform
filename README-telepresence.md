# Debug Individual Services With Telepresence

- You will need the kubeconfig of the environment, you want to interact with.
  - For the Dev environment, you can find the config in the devcontainer at `~/.kube/config`.

- Set the path to the kubeconfig:
```
export KUBECONFIG=path_to_kubeconfig_file
```

- Run this script to install Telepresence on your machine and on the cluster and connect the two of them:
```
./scripts/init-telepresence.sh
```

## Telepresence Commands

### Check Available Services And Interception Info
```
telepresence -n daiteap list
```

### Get Service Info
```
kubectl -n daiteap get svc service_of_your_choice -o yaml
```

### Intercept Service
```
telepresence -n daiteap intercept service_of_your_choice --port local_port:remote_port --env-file path_to_env_file
```

`path_to_env_file` -> file, to which the environment variables from the cluster service will be written, so you can use them when you start your local environment

### Stop Interception
```
telepresence leave intercept_name
```

## Interception Details

### Intercepting `vuejs-client`

This service needs to interact with `keycloak` and `platform-api` services. You need to either port-forward them from the cluster or use their public addresses.

In Keycloak, change the URL settings of `app-vue` and `django-backend` clients to the address of your local UI, you might also need to change the frontend URL of the realm to the address where you've port-forwarded Keycloak.

Instructions on how to start the front-end locally can be found in the `daiteap-ui` repo in `README.md`.

### Intercepting `platform-api`

This service needs to interact with `database`, `rabbitmq` and `vault` services. You need to either port-forward them from the cluster or use their public addresses.

Instructions on how to start the back-end locally can be found in `./README-local.md`.