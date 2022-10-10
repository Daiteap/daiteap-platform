#!/bin/sh

exitcode=0

./check_env_vars.sh

if [ $? -eq 0 ]
then
  echo "Environment variables are set."
else
  echo "Environment variables are not set."
  exitcode=-1
fi

yamllint -c cloudcluster/v1_0_0/ansible/.yamllint cloudcluster/v1_0_0/ansible/

if [ $? -eq 0 ]
then
  echo "Ansible validation is successful."
else
  echo "Ansible validation failed!!!!!"
  exitcode=-1
fi

python3 ./terraform_test.py

if [ $? -eq 0 ]
then
  echo "Terraform validation is successful."
else
  echo "Terraform validation failed!!!!!"
  exitcode=-1
fi

exit $exitcode