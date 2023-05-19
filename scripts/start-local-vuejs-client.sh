#!/bin/bash

sudo git clone https://github.com/Daiteap/daiteap-ui.git /workspaces/daiteap-ui
sudo chmod -R 777 /workspaces/daiteap-ui/app
cd /workspaces/daiteap-ui/app
sudo rm -r -f node_modules/
sudo rm package-lock.json

export VUE_APP_THEME=daiteap
export VUE_APP_SINGLE_USER_MODE=False

sudo apt install npm nginx -y
sudo npm install -g @vue/cli
sudo npm uninstall node-sass -g && npm cache clean --force && npm install node-sass
sudo cp /workspaces/daiteap-ui/app/nginx/cloudcluster.conf /etc/nginx/sites-enabled/cloudcluster.conf
npm install
sudo service nginx restart
npm run build -- --modern

npm run serve -- --port 8082

# sudo apt install python3 python2 make g++
# sudo apk add --update py-pip
# pip3 install markdown mkdocs jinja2==3.0.3
# cp ./public/favicon-$VUE_APP_THEME.ico ./docs/docs/img/favicon.ico
# mkdocs build -f ./docs/mkdocs.yaml --site-dir ../public/documentation
