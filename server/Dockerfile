FROM python:3.7-slim
WORKDIR /cloudcluster

ENV PYTHONUNBUFFERED 1

# Create container user
RUN groupadd -r containerUser && useradd -r -m -g containerUser containerUser
WORKDIR /home/containerUser

RUN apt-get update

RUN apt-get install -y iproute2 ca-certificates gcc libffi-dev bash git tk-dev tcl-dev
RUN apt-get install -y tini wget unzip openssl
RUN apt-get install -y --no-install-recommends libmariadb-dev-compat

COPY cloudcluster/requirements.txt cloudcluster/requirements.txt
RUN pip install --upgrade pip
RUN pip3 install -r cloudcluster/requirements.txt

RUN wget https://releases.hashicorp.com/terraform/1.5.7/terraform_1.5.7_linux_$(dpkg --print-architecture).zip -O terraform.zip
RUN wget https://get.helm.sh/helm-v3.12.3-linux-$(dpkg --print-architecture).tar.gz
RUN tar zxf helm-v3.12.3-linux-$(dpkg --print-architecture).tar.gz
RUN unzip terraform.zip
RUN rm -rf terraform.zip
RUN rm -rf helm-v3.12.3-linux-$(dpkg --print-architecture).tar.gz
RUN mv ./linux-$(dpkg --print-architecture)/helm /usr/bin/
RUN mv terraform /usr/bin/

RUN apt-get purge -y wget unzip libmariadb-dev-compat gcc

RUN mkdir -p /root/.terraform.d/plugin-cache

ARG GIT_COMMIT_SHA=""
ENV GIT_SHA=$GIT_COMMIT_SHA
ARG BUILD_TIME=""
ENV BUILD_TIME_INFO=$BUILD_TIME
ENV API_GIT_COMMIT_INFO="${GIT_SHA} | ${BUILD_TIME_INFO} UTC"

EXPOSE 8080
COPY . .

USER containerUser

RUN python3 manage.py collectstatic --noinput

ENTRYPOINT ["tini", "--"]
CMD ["bash", "-c", "./start.sh"]
