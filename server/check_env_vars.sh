#!/bin/sh

exitcode=0

if [ -z "${DEFAULT_FROM_EMAIL}" ];
then
  echo "Environment variable DEFAULT_FROM_EMAIL is not set."
  exitcode=-1
fi

if [ -z "${DJANGO_SECRET_KEY}" ];
then
  echo "Environment variable DJANGO_SECRET_KEY is not set."
  exitcode=-1
fi

if [ -z "${EMAIL_HOST_PASSWORD}" ];
then
  echo "Environment variable EMAIL_HOST_PASSWORD is not set."
  exitcode=-1
fi

if [ -z "${EMAIL_HOST_USER}" ];
then
  echo "Environment variable EMAIL_HOST_USER is not set."
  exitcode=-1
fi

if [ -z "${MYSQL_PASS}" ];
then
  echo "Environment variable MYSQL_PASS is not set."
  exitcode=-1
fi

exit $exitcode