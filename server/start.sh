#!/bin/bash

# ./test.sh

# if [ $? -eq 0 ]
# then

if [ -n "$SERVICE_CATALOG_COMMAND" ]
then
    python3 manage.py $SERVICE_CATALOG_COMMAND
else
    echo "SERVICE_CATALOG_COMMAND not set"
fi

# for sndd1a environment
# python3 manage.py fix_service_catalog_sndd1a
uwsgi --http :8080 --wsgi-file cloudcluster/wsgi.py --listen 1024 --buffer-size=32768 --post-buffering=1 --log-req-encoder=$'format ${msg}\n' --logger-req=stdio --logformat='{"pid": "%(pid)", "address": "%(addr)", "vars": {"count": "%(vars)", "bytes": "%(pktsize)"}, "date": "%(ctime)", "method": "%(method)", "uri": {"uri": "%(uri)", "bytes": "%(rsize)", "msec": "%(msecs)"}, "user_id": "%(var.HTTP_USER_ID)", "protocol": "%(proto)", "status": "%(status)", "headers": {"count": "%(headers)", "bytes": "%(hsize)"}, "switches": {"switches": "%(switches)", "core": "%(core)"}}'
# else
#   echo Tests failed!!!!!
#   exit -1
# fi