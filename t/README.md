# How to setup keycloak for test

## Version

We choose [new keycloak image](https://quay.io/repository/keycloak/keycloak) docker image as test IdP. The version is `18.0.2`.

The lastest version has issues to import client key, so it's pending to check in future:

https://github.com/keycloak/keycloak/issues/13668

https://github.com/keycloak/keycloak/issues/13812

## Configuring keycloak for test

### 1. Run keycloak

```
docker run --rm --name keycloak -d -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:18.0.2 start-dev
```

### 2. Configuring keycloak

#### 2.1 Create realm "test"

#### 2.2 Create User "test"

After completion, in the `Credential` tab page, change password to "test" and disable `Temporary`.

#### 2.3 Create client

##### sp

* Name: sp
* Client Protocol: saml
* Set "Force POST Binding" to "OFF"
* Set Root URL "http://127.0.0.1:8088"
* Valid Redirect URIs: /acs
* Logout Service Redirect Binding URL: /sls
* From the keys tab page, import Signing Key, just paste your cert file content in PEM format

##### sp2

* Name: sp2
* Client Protocol: saml
* Set "Force POST Binding" to "OFF"
* Set Root URL "http://127.0.0.2:8099"
* Valid Redirect URIs: /acs
* Logout Service Redirect Binding URL: /sls
* From the keys tab page, import Signing Key, just paste your cert file content in PEM format

#### 2.4 Check IdP signing key

curl -s http://127.0.0.1:8080/realms/test/protocol/saml/descriptor

Copy and paste `<ds:X509Certificate>` block of the output to a file, e.g. `/tmp/idp.cert`, and use `utils/read_cert.py` to convert it into string.

```
# for test file
python3 utils/read_cert.py /tmp/idp.cert t

# for opts in `saml.new(opts)`
python3 utils/read_cert.py /tmp/idp.cert
```

#### 2.5 export the test realm

```
docker exec -it keycloak bash
/opt/keycloak/bin/kc.sh export --file /tmp/test-realm.json --realm test --users realm_file
docker cp keycloak:/tmp/test-realm.json /tmp/
```

## Run keycloak with import realm

```
docker run --rm --name keycloak -d -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin -v /tmp/test-realm.json:/opt/keycloak/data/import/realm.json quay.io/keycloak/keycloak:18.0.2 start-dev --import-realm
```
