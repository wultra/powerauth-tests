# How to run a load test

## Prepare config file
1. Open PowerAuth admin
2. Create new application
3. Create a `config.json` file according the created application
```
{
  "applicationId": 1,
  "applicationName": "Application Name",
  "applicationKey": "application key in Base64",
  "applicationSecret": "application secret in Base64",
  "masterPublicKey": "master public key in Base64"
}
```

## Clear data in test database
```sql
TRUNCATE pa_activation_history CASCADE;
TRUNCATE pa_signature_audit CASCADE;
TRUNCATE pa_activation CASCADE;
```

## Run a test

```shell
mvn gatling:test -Dgatling.simulationClass=com.wultra.security.powerauth.test.PowerAuthLoadTest \
-DconfigFile="directory_with_the_config_file/config.json" \
-DpowerAuthJavaServerUrl=http://localhost:8080/powerauth-java-server \
-DpowerAuthRestServerUrl=http://localhost:8080/powerauth-restful-server-spring \
-DcountOfDevices=10 \
-DmaxDevicesPerSecond=5
```

Command line parameters:
- `configFile` - file with application configuration, defaults to `./config.json`
- `powerAuthJavaServerUrl` - base url of the PowerAuth Java server
- `powerAuthRestServerUrl` - base url of the PowerAuth REST server
- `countOfDevices` - count of simulated devices, defaults to 100
- `maxDevicesPerSecond` - maximum allowed number of active devices in one second, defaults to 80
- `testDuration` - duration of the load test, defaults to `15 minutes`
- `stepLoggerType` - type of used step logger, defaults to `disabled`, other allowed values (`json`, `object`)
