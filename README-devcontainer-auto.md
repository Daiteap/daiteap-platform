# How to setup local dev environment using devcontainer

### Commands

#### start devcontainer
```sh
# start devcontainer
devcontainer up --workspace-folder .

# start vscode
code .

# attach vscode to the running devcontainer
```

### commands from the devcontainer
Enter the devcontainer with: 'docker exec -it <CONTAINER> bash'

From plaform directory:
'cd workspaces/daiteap-platform/'

follow the next steps.


### delete KIND cluster /OPTIONAL/
kind delete clusters cluster1


#### Starting the platform
```sh
./scripts/start-platform.sh
```

Wait until the pods are ready.

```sh
./scripts/redirect-ports.sh
```

#### Import REALM and create secret for daiteap-platform and configure Redirect URIs for Daiteap-ui in keycloak
- Login into keycloak at http://localhost:8082 with user "user" and password from decoded field "admin-password:" from command:
kubectl get secret keycloak -n daiteap -o yaml
- import REALM in "add realm" using file docker-compose/DaiteapRealm.json
- create secret in Configure->Clients->Django-backend / Credentials / Regenerate Secret , then copy it and enter it in File:Var :
argocd/daiteap-platform.yaml:keycloakClientSecretKey
- Configure Valid Redirect URIs for UI in keycloak
Enter Configure->Clients->app-vue and in field "Valid Redirect URIs" add *


#### Init Vault
```sh
./scripts/init-vault.sh
```

Put the "root_token" value from docker-compose/vault/vault-init.json into var vaultToken in argocd/celeryworker.yaml and argocd/daiteap-platform.yaml fails.


#### Init platform
```sh
./scripts/init-platform.sh
```

#### Restart daiteap platform
```sh
./scripts/restart-celeryworker.sh
./scripts/restart-platform.sh
```

### Enter Daiteap UI
- open in Chrome: http://localhost:8083

- register a user with username: user@cst-bg.net

- enable it in keycloak
From "Users" switch "Email Verified" field to ON.
