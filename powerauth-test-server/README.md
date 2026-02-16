# PowerAuth Test Server

PowerAuth Test Server is deployed to simplify testing of PowerAuth backends. The REST API encapsulates PowerAuth actions which require cryptography with an embedded `powerauth-java-cmd-lib` library.


## Docker Image

The released docker images are published to a [Docker Hub](https://hub.docker.com/r/powerauth/powerauth-test-server)

```shell
docker pull powerauth/powerauth-test-server:1.10.0-4f11211005c4175dd9a7f5e06f4d87bd32456700
```

**The container environments variables**:
Mandatory variables
```shell
# URL of an enrollment server, i.e., the public API required for device pairing or operation approvals.
POWERAUTH_TEST_SERVER_ENROLLMENT_SERVER_URL=http://localhost:8080/enrollment-server
# URL of a DB server persisting the emulated SDKs
POWERAUTH_TEST_SERVER_DATASOURCE_URL=jdbc:postgresql://host.docker.internal:5432/powerauth
# Username for the DB 
POWERAUTH_TEST_SERVER_DATASOURCE_USERNAME=powerauth
# Password for the DB
POWERAUTH_TEST_SERVER_DATASOURCE_PASSWORD=
# Toggle Liquibase database migrations in the main application container (true/false, default: true)
LQ_ENABLED=true
```

Optional variables
```shell

# path to a customized logback logging configuration
POWERAUTH_TEST_SERVER_LOGGING=
# The version of a default Wultra crypto protocol used by the test server
POWERAUTH_TEST_SERVER_POWERAUTH_VERSION=4.0
```

## Docker Build Instructions

You can build your own docker image by following these steps to build and run (example commands were run from root) the PowerAuth Test Server Docker image:

### Preparation Steps

1. **Build the WAR File**:
   Execute the following Maven command to package the `powerauth-test-server` application:
    ```shell
    mvn -pl powerauth-test-server clean package
    ```

2. **Liquibase Scripts**:
   Copy the Liquibase migration scripts into the Docker build context. For detailed instructions, refer to [readme.txt](docker/deploy/liquibase/readme.txt).

3. **Environment Configuration**:
   Set up the environment variables using one of the two methods below:

   - **Using an `env.list` File**:
     Duplicate `powerauth-test-server/docker/env.list.tmp` as `powerauth-test-server/env.list` and modify the values accordingly.
   - **Using the `-e` Flag**:
     Directly set environment variables via the Docker run command. For example, to set the database username, you would use:
       ```shell
       docker run -e POWERAUTH_TEST_SERVER_DATASOURCE_USERNAME='powerauth' IMAGE
       ```

4. **Docker Image Build**:
   Build the Docker image using the provided Dockerfile:
    ```shell
    docker build -f powerauth-test-server/Dockerfile -t powerauth-test-server:latest ./powerauth-test-server
    ```

## Running Docker Image

**Run the Docker Image**:
   Deploy the container with the following command:
    ```shell
    docker run -d -p 80:8080 --name powerauth-test-server --env-file ./powerauth-test-server/env.list powerauth-test-server:latest
    ```

**Server Verification**:
   Confirm the server is operational by navigating to [http://localhost/powerauth-test-server/](http://localhost/powerauth-test-server/) in your web browser. You should see the PowerAuth Test Server home page.

## Standalone Test Server Configuration

Test server needs a configured database. H2 can be used for development, PostgreSQL is recommended for a usage in automated tests. The database structure is created automatically on application startup.

Once the database is created, you can connect to it using following URL:

```properties
# The DB configuration
spring.datasource.url=jdbc:postgresql://localhost:5432/powerauth
# Enable liquibase managed by the spring boot, the app should be build with liquibase profile to enable this
spring.liquibase.enabled=${LIQUIBASE_ENABLED:false}
```

## Test Server Application Setup

### Create Application

First the Test server has to be setup for application (appId) used in the PowerAuth backend. This should be done via API call:

```shell
curl --request POST \
--url http://localhost:8080/powerauth-test-server/application/config \
--header 'Content-Type: application/json' \
--data '{
"requestObject": {
        "applicationId": "test-mobile-token",
        "applicationName": "Test application",
        "applicationKey": "GlxZ1Qe70pPAC/ek0BvNXw==",
        "applicationSecret": "Psjvd99yCz3kB8gwYQWCMQ==",
        "masterPublicKey": "BOyFTtFXtbyYHh3XxN3RXQwlNu+sxsMCcc8x/8U6pwzUWn3rD+O7BLHbzwDU4ZsWnDdnhyStuzCXS4nIpmqhTbk=",
        "mobileSdkConfig" : "BOyFTtFXtbyYHh3XxN3RXQwlNu+sxsMCcc8x/8U6pwzUWn3rD+O7BLHbzwDU4ZsWnDdnhyStuzCXS4nIpmqhTbk=...."
    }
}'
```

The `applicationId` value should correspond to the PowerAuth application identifier of the application used for testing.
You can obtain all the other values from PowerAuth Admin application or PowerAuth Server or PowerAuth Cloud REST API.

### Create Activation

The activation needs to be at first initialized using one of the possible ways:
- creating the activation in PowerAuth Admin in the `Activations` tab
- calling the PowerAuth server POST `/rest/v4/activation/init` endpoint
- calling the PowerAuth cloud POST `/registration` endpoint

Once the activation is initialized, you can create the activation using following REST API call.

```shell
curl --request POST \
--url http://localhost:8080/powerauth-test-server/activation/create \
--header 'Content-Type: application/json' \
--data '{
    "requestObject": {
        "applicationId": "test-mobile-token",
        "activationName": "test-activation",
        "password": "1234",
        "activationCode": "3A33O-3XMFZ-ORDKE-XJOYQ",
        "activationOtp": "otp"
    }
}'
```

The following request parameters are used:

| Parameter        | Note                                                                                                                                |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| `applicationId`  | PowerAuth application identifier                                                                                                    |
| `activationName` | PowerAuth application name                                                                                                          |
| `password`       | PIN code for future signature verifications (knowledge factor)                                                                      |
| `activationCode` | Activation code, created using the previous initialization request                                                                  |
| `activationOtp`  | Activation OTP used for the activation initialization. Required if the OTP validation of the activation is set to `ON_KEY_EXCHANGE`.|
| `algorithm`      | Optional. Identifier of the shared-secret algorithm suite. Defaults to `EC_P384_ML_L3`.                                             |

The response contains the `activationId` parameter which is the activation identifier:

```json
{
  "status": "OK",
  "responseObject": { 
    "activationId": "5df48d17-e477-467b-8b93-2d6a0185b642"
  }
}
```

In order for the activation to become `ACTIVE`, the activation needs to be committed, unless auto-commit mode is enabled using one of the possible ways:
- committing the activation in PowerAuth Admin in the `Activations` tab
- calling the PowerAuth server POST `/rest/v4/activation/commit` endpoint
- calling the PowerAuth cloud POST `/registration` endpoint

# License

PowerAuth Test Server is licensed using GNU AGPLv3 license. Please consult us at hello@wultra.com for the software use.
