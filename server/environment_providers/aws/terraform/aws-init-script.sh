#!/bin/bash

sudo useradd -m -G sudo clouduser
echo 'clouduser ALL=(ALL:ALL) NOPASSWD: ALL' | sudo EDITOR='tee -a' visudo
mkdir /home/clouduser/.ssh
chown clouduser:clouduser /home/clouduser/.ssh
chmod 700 /home/clouduser/.ssh
cat /root/.ssh/authorized_keys |grep -o -e "ssh-rsa .*" >> /home/clouduser/.ssh/authorized_keys
chown clouduser:clouduser /home/clouduser/.ssh/authorized_keys
chmod 600 /home/clouduser/.ssh/authorized_keys