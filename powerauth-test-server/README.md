# PowerAuth Test Server

PowerAuth Test Server is deployed to simplify testing of PowerAuth backends. The REST API encapsulates PowerAuth actions which require cryptography with an embedded `powerauth-java-cmd-lib` library.

## Docker Build Instructions

Follow these steps to build and run (example commands were run from root) the PowerAuth Test Server Docker image:

### Preparation Steps

1. **Build the WAR File**:
   Execute the following Maven command to package the `powerauth-test-server` application:
    ```shell
    mvn -pl powerauth-test-server clean package
    ```

2. **Liquibase Scripts**:
   Copy the Liquibase migration scripts into the Docker build context. For detailed instructions, refer to [readme.txt](deploy/liquibase/readme.txt).

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

5. **Run the Docker Image**:
   Deploy the container with the following command:
    ```shell
    docker run -d -p 80:8080 --name powerauth-test-server --env-file ./powerauth-test-server/env.list powerauth-test-server:latest
    ```

6. **Server Verification**:
   Confirm the server is operational by navigating to [http://localhost/powerauth-test-server/](http://localhost/powerauth-test-server/) in your web browser. You should see the PowerAuth Test Server home page.

## Test Server Configuration

Test server runs by default with embedded H2 database. The database structure is created automatically on application startup.

Once the database is created, you can connect to it using following URL:

```properties
spring.datasource.url=jdbc:h2:file:~/powerauth-test;DB_CLOSE_ON_EXIT=FALSE;AUTO_SERVER=TRUE
```

The test server configuration is performed using following query:

```sql
insert into PA_TEST_CONFIG (APPLICATION_ID, APPLICATION_NAME, APPLICATION_KEY, APPLICATION_SECRET, MASTER_PUBLIC_KEY)
values  (1, 'test-app', '66arXznJzaEs1k4cNfyWzA==', 'CNtWEvyDyJupKL9n07y+aA==', 'BLWJ8cTWx/LxU8dTC7CiNbWKXExRSG/yMKmR3Iw5ZhlPpMQ9qTvBWhY0DnkFr++53JPEwfJaW6zEdIEdq34z59E=');
```

The `APPLICATION_ID` value should correspond to the PowerAuth application identifier of the application used for testing.
You can obtain all the other values from PowerAuth Admin application.

## Create Activation

The activation needs to be at first initialized using one of the possible ways:
- creating the activation in PowerAuth Admin in the `Activations` tab
- calling the PowerAuth server POST `/rest/v3/activation/init` endpoint
- calling the PowerAuth cloud POST `/registration` endpoint

Once the activation is initialized, you can create the activation using following REST API call.

```shell
curl --request POST \
--url http://localhost:8080/powerauth-test-server/activation/create \
--header 'Content-Type: application/json' \
--data '{
    "requestObject": {
        "applicationId": "1",
        "activationName": "test-activation",
        "password": "1234",
        "activationCode": "3A33O-3XMFZ-ORDKE-XJOYQ"
    }
}'
```

The following request parameters are used:

| Parameter | Note |
|---|---|
| `applicationId` | PowerAuth application identifier |
| `activationName` | PowerAuth application name  |
| `password` | PIN code for future signature verifications (knowledge factor) |
| `activationCode` | Activation code, created using the previous initialization request |

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
- calling the PowerAuth server POST `/rest/v3/activation/commit` endpoint
- calling the PowerAuth cloud POST `/registration` endpoint

# License

PowerAuth Test Server is licensed using GNU AGPLv3 license. Please consult us at hello@wultra.com for the software use.
