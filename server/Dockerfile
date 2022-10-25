FROM python:3.7
WORKDIR /cloudcluster

ENV PYTHONUNBUFFERED 1

RUN apt-get update

RUN apt-get install -y iproute2 ca-certificates gcc libffi-dev bash  git tk-dev tcl-dev

COPY cloudcluster/requirements.txt cloudcluster/requirements.txt
RUN pip install --upgrade pip
RUN pip3 install -r cloudcluster/requirements.txt

RUN wget https://releases.hashicorp.com/terraform/1.1.0/terraform_1.1.0_linux_$(dpkg --print-architecture).zip -O terraform.zip
RUN wget https://get.helm.sh/helm-v3.3.4-linux-$(dpkg --print-architecture).tar.gz
RUN tar zxf helm-v3.3.4-linux-$(dpkg --print-architecture).tar.gz
RUN unzip terraform.zip
RUN mv ./linux-$(dpkg --print-architecture)/helm /usr/bin/
RUN mv terraform /usr/bin/

RUN apt-get update && apt-get install -y tini npm openssl

RUN mkdir -p /root/.terraform.d/plugin-cache

ARG GIT_COMMIT_SHA=""
ENV GIT_SHA=$GIT_COMMIT_SHA
ARG BUILD_TIME=""
ENV BUILD_TIME_INFO=$BUILD_TIME
ENV API_GIT_COMMIT_INFO="${GIT_SHA} | ${BUILD_TIME_INFO} UTC"

EXPOSE 8080
COPY . .

RUN python3 manage.py collectstatic --noinput

ENTRYPOINT ["tini", "--"]
CMD ["bash", "-c", "./start.sh"]
