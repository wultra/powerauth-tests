package com.wultra.security.powerauth.test.scenario;


import com.wultra.security.powerauth.test.config.PowerAuthCommon;
import io.gatling.javaapi.core.ScenarioBuilder;
import lombok.extern.slf4j.Slf4j;


import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.http.HttpDsl.status;
import static java.util.UUID.randomUUID;

@Slf4j
public class CreateApplicationScenario extends AbstractScenario {

    private static final String APP_NAME = "TEST_APP" + randomUUID();
    private static final String APP_ROLE = "ROLE_ADMIN";
    public static final ScenarioBuilder createApplicationScenario = scenario(CreateApplicationScenario.class.getName())
            .exec(
                    http("Create Application PowerAuth Cloud")
                            .post(PowerAuthCommon.powerAuthCloudUrl + "admin/applications")
                            /* TODO: Read basic auth params from env variable */
                            .basicAuth("system-admin", "MLUteJ+uvi2EOP/F")
                            .body(StringBody("""
                                    {
                                      "id": "%s",
                                      "roles": [
                                        "%s"
                                      ]
                                    }
                                    """.formatted(APP_NAME, APP_ROLE)))
                            .check(jmesPath("masterServerPublicKey").saveAs("masterServerPublicKey"),
                                    jmesPath("appKey").saveAs("appKey"),
                                    jmesPath("appSecret").saveAs("appSecret"),
                                    jmesPath("mobileSdkConfig").saveAs("mobileSdkConfig"),
                                    jmesPath("id").saveAs("appId"))
            ).exec(
                    http("Add access to app for user PowerAuth Cloud")
                            .post(PowerAuthCommon.powerAuthCloudUrl + "admin/users/system-admin/applications/#{appId}")
                            /* TODO: Read basic auth params from env variable */
                            .basicAuth("system-admin", "MLUteJ+uvi2EOP/F")
                            .check(status().is(200))
            )
            .exec(
                    http("Create application Test Server")
                            .post(PowerAuthCommon.powerAuthTestServerUrl + "application/config")
                            .body(StringBody("""
                                     {
                                        "requestObject": {
                                            "applicationId": "#{appId}",
                                            "applicationName": "%s",
                                            "applicationKey": "#{appKey}",
                                            "applicationSecret": "#{appSecret}",
                                            "masterPublicKey": "#{masterServerPublicKey}",
                                            "mobileSdkConfig": "#{mobileSdkConfig}"
                                        }
                                    }
                                      """.formatted(APP_NAME))))
            .exec(saveSessionData());

}
