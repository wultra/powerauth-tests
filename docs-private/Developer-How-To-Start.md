# Developer - How to Start Guide

## PowerAuth Test Server

### Standalone Run

- Use IntelliJ Idea run configuration at `../.run/TestServerApplication.run.xml`
- Open [http://localhost:8081/actuator/health](http://localhost:8081/actuator/health) and you should get `{"status":"UP"}`


### Database

Database changes are driven by Liquibase.

This is an example how to manually check the Liquibase status.
Important and fixed parameter is `changelog-file`.
Others (like URL, username, password) depend on your environment.

```shell
liquibase --changelog-file=./docs/db/changelog/changesets/powerauth-test-server/db.changelog-module.xml --url=jdbc:postgresql://localhost:5432/powerauth --username=powerauth status
```

## PowerAuth FIDO2 Tests

### Standalone Run

- Enable maven profile `standalone`
- Use IntelliJ Idea run configuration at `../.run/PowerAuthFido2TestApplication.run.xml`
- Open [http://localhost:8083/powerauth-fido2-test/actuator/health](http://localhost:8083/powerauth-fido2-test/actuator/health) and you should get `{"status":"UP"}`

