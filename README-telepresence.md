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

## Start Local Back-End

- Install Python 3.7
```
sudo apt update
sudo apt install libffi-dev -y
sudo apt-get install libmysqlclient-dev -y
wget https://www.python.org/ftp/python/3.7.16/Python-3.7.16.tgz
tar zxf Python-3.7.16.tgz
cd Python-3.7.16
./configure
sudo make
sudo make install
```

- Clone the back-end repo:
```
git clone https://github.com/Daiteap/daiteap-platform.git
```

- All the future commands should be executed in `server` directory:
```
cd ./daiteap-platform/server
```

- Create virtual environment:
```
python3.7 -m venv daiteap-env
```

- Activate environment:
```
source daiteap-env/bin/activate
```

- Install requirements:
```
pip install --upgrade pip
pip install -r cloudcluster/requirements.txt
python3.7 manage.py collectstatic --noinput
```

- Install Helm and Terraform:
```
wget https://releases.hashicorp.com/terraform/1.1.0/terraform_1.1.0_linux_$(dpkg --print-architecture).zip -O terraform.zip
wget https://get.helm.sh/helm-v3.3.4-linux-$(dpkg --print-architecture).tar.gz
tar zxf helm-v3.3.4-linux-$(dpkg --print-architecture).tar.gz
unzip terraform.zip
sudo mv ./linux-$(dpkg --print-architecture)/helm /usr/bin/
sudo mv terraform /usr/bin/
sudo mkdir -p /root/.terraform.d/plugin-cache
```

- Use these params in `server/cloudcluster/settings.py`, before copying the values, replace:
  - `database_service_cluster_ip` with the cluster IP of the database service in the cluster, you can get that with `kubectl -n daiteap get svc database -o yaml`
  - `secret` with the Keycloak client secret
  - `rabbitmq_service_cluster_ip` with the cluster IP of the rabbitmq service in the cluster, you can get that with `kubectl -n daiteap get svc rabbitmq -o yaml`
  - `vault_service_cluster_ip` with the cluster IP of the vault service in the cluster, you can get that with `kubectl -n daiteap get svc vault -o yaml`
  - `token` with the value of `root_token` from `docker-compose/vault/vault-init.json`

```py
DEBUG = (os.getenv("DJANGO_DEBUG"), True)
ALLOWED_HOSTS = os.getenv('DJANGO_ALLOWED_HOSTS', ['*'])
SINGLE_USER_MODE = os.getenv('SINGLE_USER_MODE', 'False')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        # 'ENGINE': 'mysql.connector.django',
        'NAME': "daiteap",
        'USER': "daiteap",
        'PASSWORD': "pass",
        'HOST': "database_service_cluster_ip",
        'PORT': 3306,
        'CONN_MAX_AGE': 0
    },
}

CELERY_BROKER_URL = f"amqp://guest:guest@rabbitmq_service_cluster_ip:5672/"

KEYCLOAK_CONFIG = {
    'KEYCLOAK_SERVER_URL': os.getenv('KEYCLOAK_SERVER_URL', 'http://localhost:8082/auth'),
    'KEYCLOAK_REALM': os.getenv('KEYCLOAK_REALM', 'Daiteap'),
    'KEYCLOAK_CLIENT_ID': os.getenv('KEYCLOAK_CLIENT_ID', 'django-backend'),
    'KEYCLOAK_CLIENT_SECRET_KEY': os.getenv('KEYCLOAK_CLIENT_SECRET_KEY', 'secret')
}

VAULT_ADDR = os.getenv('VAULT_ADDR', 'http://vault_service_cluster_ip:8200')
VAULT_TOKEN = os.getenv('VAULT_TOKEN', 'token')
```

- Run back-end:
```
python3.7 manage.py runserver 8070
```