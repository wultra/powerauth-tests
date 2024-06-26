# PowerAuth FIDO2 Tests

PowerAuth FIDO2 Tests is a web application for exploring and testing the FIDO2 integration with PowerAuth Server.
Using PowerAuth FIDO2 Tests you can simulate registration, login, and payment processing scenarios within the PowerAuth
environment with a variety of software and hardware authenticators using WebAuthN protocol. The web application logs
detailed information of each step of a WebAuthN ceremony, conveniently accessible directly within the browser console.

## Requirements

PowerAuth FIDO2 Tests web application communicates with the PowerAuth Server. You can find more details about
the PowerAuth Server on the [Developer Portal](https://developers.wultra.com/components/powerauth-server/develop/documentation/).

> :information_source: FIDO2 support is integrated into PowerAuth Server since version 1.7.0.

## Configuration Properties

### PowerAuth Service Configuration

| Property                                  | Default                                       | Note                                      |
|-------------------------------------------|-----------------------------------------------|-------------------------------------------|
| `powerauth.service.baseUrl`               | `http://localhost:8080/powerauth-java-server` | PowerAuth service REST API base URL.      | 
| `powerauth.service.security.clientToken`  |                                               | PowerAuth REST API authentication token.  | 
| `powerauth.service.security.clientSecret` |                                               | PowerAuth REST API authentication secret. |

### WebAuthN Configuration Properties

| Property                            | Default  | Note                                                                                       |
|-------------------------------------|----------|--------------------------------------------------------------------------------------------|
| `powerauth.webauthn.rpId`           |          | Relying Party ID. Must be equal to the origin's effective domain.                          | 
| `powerauth.webauthn.rpName`         |          | Relying Party display name.                                                                | 
| `powerauth.webauthn.timeout`        | `60s`    | Specifies a duration that the Relying Party is willing to wait for the client to complete. |
| `powerauth.webauthn.allowedOrigins` |          | List of allowed origins.                                                                   |


## Running the Application

### Running from IntelliJ IDEA

By default, the development profile is active, so the application should start without any additional configuration.
It is expected an instance of the PowerAuth Server is listening on `http://localhost:8080/powerauth-java-server`.
The application starts on http://localhost:8083/powerauth-fido2-test with following default configuration:

```properties
# WebAuthn properties configuration
powerauth.webauthn.rpId=localhost
powerauth.webauthn.rpName=Local Development
powerauth.webauthn.allowedOrigins=http://localhost:8083
```

> :information_source: Make sure you visit the application on the `localhost` domain. Ceremonies initiated
> at the address `127.0.0.1` will not be successful.

### Running from terminal

Build the project by running `mvn clean package` in the root directory of the project. Once the build is successful,
navigate to the target directory, from which you can run the war file using `java -jar`. Keep in mind you have to
configure necessary properties using external configuration or by using command line argument `-D`.
