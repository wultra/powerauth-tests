# Deploying the Test Server From Docker

1. Download a Docker image with the test server (current version of this component is 1.4.0):

```sh
docker login wultra.jfrog.io
docker pull wultra.jfrog.io/wultra-docker/powerauth-test-server:1.4.0
```

2. Setup a PostgreSQL database and create the following two tables:

```sql
CREATE TABLE pa_test_config
(
    application_id     VARCHAR(255) NOT NULL PRIMARY KEY, -- Application identifier
    application_name   VARCHAR(255) NOT NULL,             -- Application name
    application_key    VARCHAR(255) NOT NULL,             -- Application key
    application_secret VARCHAR(255) NOT NULL,             -- Application secret
    master_public_key  VARCHAR(255) NOT NULL              -- Master public key in Base64 format
);

CREATE TABLE pa_test_status
(
    activation_id                     VARCHAR(255) NOT NULL PRIMARY KEY, -- Activation identifier
    server_public_key                 VARCHAR(255) NOT NULL,             -- Server public key in Base64 format
    counter                           INTEGER      NOT NULL,             -- Numeric counter
    ctr_data                          VARCHAR(255) NOT NULL,             -- Hashed counter data
    encrypted_device_private_key      VARCHAR(255) NOT NULL,             -- Encrypted device private key in Base64 format
    signature_biometry_key            VARCHAR(255) NOT NULL,             -- Signature biometry key in Base64 format
    signature_knowledge_key_encrypted VARCHAR(255) NOT NULL,             -- Encrypted signature knowledge key in Base64 format
    signature_knowledge_key_salt      VARCHAR(255) NOT NULL,             -- Signature knowledge key in Base64 format
    signature_possession_key          VARCHAR(255) NOT NULL,             -- Signature possession key in Base64 format
    transport_master_key              VARCHAR(255) NOT NULL              -- Transport master key in Base64 format
);
```

3. Insert the per-application config. These are the same values you would give to the app developer. You can obtain the values in the DB schema of PowerAuth Cloud instance, in pa_application_version and pa_master_keypair tables. The values look similarly to this:

```sql
INSERT INTO pa_test_config (application_id, application_key, application_name, application_secret, master_public_key)
VALUES ('mobile-app', 'fP...Ow==', 'Mobile Test App', 'va...MA==', 'BB...0M=');
```

4. Create an env.list file (or any other mechanics to inject environment variables to the running container):

```
POWERAUTH_TEST_SERVER_ENROLLMENT_SERVER_URL=http://localhost:8080/enrollment-server
POWERAUTH_TEST_SERVER_DATASOURCE_URL=jdbc:postgresql://host.docker.internal:5432/powerauth
POWERAUTH_TEST_SERVER_DATASOURCE_USERNAME=powerauth
POWERAUTH_TEST_SERVER_DATASOURCE_PASSWORD=
```

The meaning of the properties is the following:

- POWERAUTH_TEST_SERVER_ENROLLMENT_SERVER_URL - path to the enrollment server component (including the /enrollment-server context)
- POWERAUTH_TEST_SERVER_DATASOURCE_URL - JDBC path to the database
- POWERAUTH_TEST_SERVER_DATASOURCE_USERNAME - JDBC username
- POWERAUTH_TEST_SERVER_DATASOURCE_PASSWORD - JDBC password

4. Start the application via the following command (or similar command using other technology - Docker Compose, Kubernetes, ...):

```sh
docker run --env-file docker/env.list.tmp -d -it -p 8081:8080 --name=pas-cloud-test powerauth-test-server:1.4.0
```
