# PowerAuth Test Server

PowerAuth TestServer is deployed to simplify testing of PowerAuth backends. The REST API encapsulates PowerAuth actions which require cryptography with an embedded `powerauth-java-cmd-lib` library.

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
- calling the PowerAuth cloud POST `/registration` or POST `/v2/registrations` endpoint

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
- calling the PowerAuth cloud POST `/registration` or POST `/v2/registrations` endpoint

# License

PowerAuth Test Server is licensed using GNU AGPLv3 license. Please consult us at hello@wultra.com for the software use.
