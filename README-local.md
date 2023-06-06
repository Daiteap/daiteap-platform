
# Start Back-End

- Install Python version 3.7:

```bash
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

```bash
git clone https://github.com/Daiteap/daiteap-platform.git
```

- Enter `server` directory:

```bash
cd ./daiteap-platform/server
```

- Create virtual environment:

```bash
python3.7 -m venv daiteap-env
```

- Activate environment:

```bash
source daiteap-env/bin/activate
```

- Install requirements:

```bash
sudo apt update
sudo apt install libffi-dev -y
sudo apt-get install libmysqlclient-dev -y
pip install --upgrade pip
pip install -r cloudcluster/requirements.txt
python3.7 manage.py collectstatic --noinput
```

- Install Helm and Terraform:

```bash
sudo npm install -g @terraform-visual/cli@0.2.1
export ARC=$(dpkg --print-architecture)
wget \
  https://releases.hashicorp.com/terraform/1.1.0/terraform_1.1.0_linux_$ARC.zip \
  -O terraform.zip
wget https://get.helm.sh/helm-v3.3.4-linux-$ARC.tar.gz
tar zxf helm-v3.3.4-linux-$ARC.tar.gz
unzip terraform.zip
sudo mv ./linux-$ARC/helm /usr/bin/
sudo mv terraform /usr/bin/
sudo mkdir -p /root/.terraform.d/plugin-cache
sudo cp .terraformrc /root/
```

- Edit these params in `server/cloudcluster/settings.py`:
  - DEBUG
  - ALLOWED_HOSTS
  - SINGLE_USER_MODE
  - DATABASES
  - CELERY_BROKER_URL
  - KEYCLOAK_CONFIG
  - VAULT_ADDR
  - VAULT_TOKEN
  - DAITEAP_GOOGLE_IMAGE_KEY
  - AWS_DAITEAP_IMAGE_NAME
  - AWS_DAITEAP_IMAGE_OWNER
  - GCP_DAITEAP_IMAGE_PROJECT
  - AZURE_DAITEAP_IMAGE_PARAMETERS

- Run back-end:

```bash
python3.7 manage.py runserver 8070
```

## Start Celery Workers

- Start RabbitMQ Broker:

```bash
docker run -it --rm --name rabbitmq -p 5672:5672 -p 15672:15672 \
  rabbitmq:3.11.4-management
```

- Start Worker:

```bash
celery -A cloudcluster worker -l info -O fair -c 3
```
