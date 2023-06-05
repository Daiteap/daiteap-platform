# Start Back-End

- Install Python version 3.7:
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

- Enter `server` directory:
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
sudo apt update
sudo apt install libffi-dev -y
sudo apt-get install libmysqlclient-dev -y
pip install --upgrade pip
pip install -r cloudcluster/requirements.txt
python3.7 manage.py collectstatic --noinput
```

- Install Helm and Terraform:
```
sudo npm install -g @terraform-visual/cli@0.2.1
wget https://releases.hashicorp.com/terraform/1.1.0/terraform_1.1.0_linux_$(dpkg --print-architecture).zip -O terraform.zip
wget https://get.helm.sh/helm-v3.3.4-linux-$(dpkg --print-architecture).tar.gz
tar zxf helm-v3.3.4-linux-$(dpkg --print-architecture).tar.gz
unzip terraform.zip
sudo mv ./linux-$(dpkg --print-architecture)/helm /usr/bin/
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
```
python3.7 manage.py runserver 8070
```

# Start Celery Workers

- Start RabbitMQ Broker:
```
docker run -it --rm --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:3.11.4-management
```

- Start Worker:
```
celery -A cloudcluster worker -l info -O fair -c 3
```
