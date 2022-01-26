# PowerAuth End-To-End Tests

PowerAuth backend end-to-end tests cover testing of the PowerAuth protocol using functionality from following components:
- [powerauth-crypto](https://github.com/wultra/powerauth-crypto)
- [powerauth-server](https://github.com/wultra/powerauth-server)
- [powerauth-restful-integration](https://github.com/wultra/powerauth-restful-integration)
- [powerauth-cmd-tool](https://github.com/wultra/powerauth-cmd-tool)
- [enrollment-server](https://github.com/wultra/enrollment-server-wultra)
- [powerauth-webflow](https://github.com/wultra/powerauth-webflow) (optional, can replace `enrollment-server`)

_Note: most of the above listed components contain unit tests, however such low level tests do not cover possible defects found when testing the solution as a whole, which is why this project was introduced._

## Supported Java Versions

We recommend to use one of the LTS releases of Java for running the tests: 8, 11, or 17.

## Building a Release Version of PowerAuth Backends

The release version of PowerAuth stack can be built easily using following commend for each component:

`mvn clean package`

You can find the resulting jar files and war files in the `target` folder. The build succeeds because all necessary libraries are deployed to public Maven repositories through the OSS Sonatype service.

## Building a Development Version of PowerAuth Backends

Things get a bit more complicated when building a development version of the stack, because there are many internal dependencies which need to be satisfied when building the final artifacts.

Clone the following repositories and use the default `develop` branch to build the latest version of the PowerAuth stack.

| Repository | Command | Result |
|---|---|---|
| https://github.com/wultra/lime-java-core | `mvn clean install` | the libraries are installed into local maven repository (.m2 folder) |
| https://github.com/wultra/powerauth-crypto | `mvn clean install` | the libraries are installed into local maven repository (.m2 folder) |
| https://github.com/wultra/powerauth-server | `mvn clean install` | the libraries are installed into local maven repository (.m2 folder) and the PowerAuth server artifact is available in `powerauth-java-server/target` |
| https://github.com/wultra/powerauth-restful-integration | `mvn clean install` | the libraries are installed into local maven repository (.m2 folder) |
| https://github.com/wultra/enrollment-server-wultra | `mvn clean install` | the Enrollment Server artifact is available in `enrollment-server/target` |
| https://github.com/wultra/powerauth-cmd-tool | `mvn clean install` | the libraries are installed into local maven repository (.m2 folder) |
| https://github.com/wultra/powerauth-webflow | `mvn clean install` | the libraries are installed into local maven repository (.m2 folder) and the artifacts are available in `powerauth-nextstep/target` and `powerauth-webflow/target` folders |

## Deploying PowerAuth Components

We assume the tests will run on a local Tomcat instance. If you prefer to use Docker for running the server components, you can use the [PowerAuth Docker project](https://github.com/wultra/powerauth-docker). Do not run the applications directly from command line using `java -jar` command, this is not supported.

1. Copy the previously built war files `powerauth-java-server.war` and `enrollment-server.war` into the `webapps` folder of Tomcat. In case you want to test Web Flow and Next Step (optional), copy the `powerauth-webflow.war` and `powerauth-nextstep.war` files, too.

2. Run the DDL scripts for these two components:
 - [PowerAuth server DDL scripts](https://github.com/wultra/powerauth-server/tree/develop/docs/sql)
 - [Enrollment server DDL scripts](https://github.com/wultra/enrollment-server/tree/develop/docs/sql)
 - (Optional) [Web Flow DDL scripts](https://github.com/wultra/powerauth-webflow/tree/develop/docs/sql) - run the `initial_data.sql` script, too

_Note: if you want to avoid additional configuration, use database, schema and user `powerauth` when setting up the database._ 

3. Configure the components using the `conf/Catalina/localhost` folder of Tomcat:

File `powerauth-java.server.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Context>
    <Parameter name="spring.datasource.url" value="jdbc:postgresql://localhost:5432/powerauth"/>
    <Parameter name="spring.datasource.username" value="powerauth"/>
    <Parameter name="spring.datasource.password" value="[PASSWORD]"/>
    <Parameter name="spring.datasource.driver-class-name" value="org.postgresql.Driver"/>
    <Parameter name="spring.jpa.database-platform" value="org.hibernate.dialect.PostgreSQLDialect"/>
</Context>
```

File `enrollment-server.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Context>
    <Parameter name="spring.datasource.url" value="jdbc:postgresql://localhost:5432/powerauth"/>
    <Parameter name="spring.datasource.username" value="powerauth"/>
    <Parameter name="spring.datasource.password" value="[PASSWORD]"/>
    <Parameter name="spring.datasource.driver-class-name" value="org.postgresql.Driver"/>
    <Parameter name="spring.jpa.database-platform" value="org.hibernate.dialect.PostgreSQLDialect"/>
    <Parameter name="powerauth.service.url" value="http://localhost:8080/powerauth-java-server/rest"/>
    <Parameter name="enrollment-server.activation-spawn.enabled" value="true"/>
    <Parameter name="enrollment-server.onboarding-process.enabled" value="true"/>
    <Parameter name="enrollment-server.identity-verification.enabled" value="true"/>
</Context>
```

Once you start the Tomcat server, you should see both applications up and running. You can check the services on following URLs:

- PowerAuth server URL: [http://localhost:8080/powerauth-java-server]()
- Enrollment server URL: [http://localhost:8080/enrollment-server]()
- PowerAuth Web Flow URL (optional): [http://localhost:8080/powerauth-webflow]()
- PowerAuth Next Step URL (optional): [http://localhost:8080/powerauth-nextstep]()

## Test Configuration

If you are running the tests locally with default configuration, there is no need to change the configuration, it should just work.

When deploying on the server, change the following parameters:

```properties
# PowerAuth service URL
powerauth.rest.url=http://localhost:8080/powerauth-java-server/rest

# Standard RESTful integration service URL
powerauth.integration.service.url=http://localhost:8080/enrollment-server

# Customized enrollment service URL
powerauth.enrollment.service.url=http://localhost:8080/enrollment-server
```

_Note: The standard RESTful integration services are available in vanilla version of enrollment server (repository `https://github.com/wultra/enrollment-server`. The customization of enrollment processes for tests is done in Wultra fork of enrollment server (repository `https://github.com/wultra/enrollment-server-wultra`). You can simply use the Wultra fork for both configuration parameters for enrollment because it also contains the generic functionality from vanilla version of enrollment server._

In case authentication is enabled on the server, you can configure it using following properties (disabled by default):
```properties
powerauth.service.security.clientToken=
powerauth.service.security.clientSecret=
```

In case you want to test Web Flow and Next Step instead of Enrollment server, use the following configuration:
```properties
# URLs used when testing Web Flow and Next Step
#powerauth.integration.service.url=http://localhost:8080/powerauth-webflow
#powerauth.nextstep.service.url=http://localhost:8080/powerauth-nextstep
```

## Running Tests from Console

You can simply run the tests using Maven in folder `powerauth-backend-tests`:

```shell
mvn clean package
```

## Running Tests from IntelliJ IDEA

You can run the tests from IntelliJ IDEA by righ-clicking on the `com.wultra.security.powerauth.test` package in the `test` folder of `powerauth-backend-tests` and choosing the `Run ...` action. In case tests fail because of missing classes, compile them using the `clean` and `compile` actions in the `Maven` window.
