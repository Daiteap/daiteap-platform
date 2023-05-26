# Debug Individual Services With Telepresence

If you're running the platform in a devcontainer run this command inside:
```
cat ~/.kube/config > ./config
```

And use the config to connect to the cluster outside of the devcontainer with:
```
export KUBECONFIG=path_to_conf_file
```

Run this script to install Telepresence on your machine and on the cluster and connect the two of them:
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

## Start Local Front-End

- Clone the front-end repo:
```
git clone https://github.com/Daiteap/daiteap-ui.git
```

- All the future commands should be executed in `app` directory:
```
cd ./daiteap-ui/app
```

- Install requirements:
```
sudo rm -r -f node_modules/
sudo rm package-lock.json
sudo apt install npm nginx -y
sudo npm install -g @vue/cli
sudo npm uninstall node-sass -g && npm cache clean --force && npm install node-sass
npm install
sudo service nginx restart
export VUE_APP_THEME=daiteap
export VUE_APP_SINGLE_USER_MODE=False
npm run build -- --modern
```

- Run UI:
```
export VUE_APP_THEME=daiteap
export VUE_APP_SINGLE_USER_MODE=False
npm run serve -- --port 8084
```

- Change `auth-server-url` in `daiteap-ui/app/public/keycloak.json` to "http://127.0.0.1:8082/auth/" (if you've changed the port for Keycloak, then change it here too)

- In Keycloak, change the URL settings of `app-vue` and `django-backend` clients to "http://127.0.0.1:8090/"

- Edit `platform_api_svc_cluster_ip` in `daiteap-platform/docker-compose/cloudcluster.conf`, copy the file to `/etc/nginx/sites-enabled/cloudcluster.conf` and restart Nginx with:
```
sudo service nginx restart
```

- Create the interception:
```
telepresence -n daiteap intercept vuejs-client --port 8090:8080
```

- Wait for the `vuejs-client` pods to be ready and running

- Access the UI on http://127.0.0.1:8090

- When you're done and have stopped your local environments, stop the interception with:
```
telepresence leave vuejs-client-daiteap
```
To access the cluster UI now you may need to port-forward it again and change the URL settings in Keycloak.

### Run Documentation
```
cp ./public/favicon-daiteap.ico ./docs/docs/img/favicon.ico
mkdocs build -f ./docs/mkdocs.yaml --site-dir ../public/documentation
mkdocs serve --config-file ./docs/mkdocs.yaml -a localhost:8085
```
