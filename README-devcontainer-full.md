# Start Platform
```
./scripts/init-cluster.sh
```

# Set-Up Keycloak
- Login into keycloak at http://localhost:8082 with:
    - user -> user
    - password -> kubectl get secret keycloak -n daiteap -o jsonpath='{.data.admin-password}' | base64 --decode
- Create realm using the file `docker-compose/DaiteapRealm.json`
- Create secret in Configure -> Clients -> django-backend -> Credentials -> Regenerate Secret; then copy it and create variable:

```
export KEYCLOAK_SECRET=secret
```

# Finish Platform Creation
```
./scripts/init-cluster-2.sh
```

# Create User
- Go to http://localhost:8083
- Register a user
- Enable it in Keycloak from "Users" switch "Email Verified" field to `ON`

# Delete Cluster
```
./scripts/delete-cluster.sh
```