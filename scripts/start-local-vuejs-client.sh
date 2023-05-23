#!/bin/bash

# Install Requirements - Only On First Run

cd ./app
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

# Run UI

export VUE_APP_THEME=daiteap
export VUE_APP_SINGLE_USER_MODE=False
npm run serve -- --port 8084

# Run Docs

cp ./public/favicon-daiteap.ico ./docs/docs/img/favicon.ico
mkdocs build -f ./docs/mkdocs.yaml --site-dir ../public/documentation
mkdocs serve --config-file ./docs/mkdocs.yaml -a localhost:8085