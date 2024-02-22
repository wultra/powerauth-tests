package com.wultra.security.powerauth.test.scenario;

import com.wultra.security.powerauth.test.config.PowerAuthCommon;
import io.gatling.javaapi.core.ScenarioBuilder;
import io.gatling.javaapi.core.Session;
import io.gatling.javaapi.http.HttpRequestActionBuilder;
import lombok.extern.slf4j.Slf4j;
import org.checkerframework.checker.units.qual.A;


import java.util.ArrayList;
import java.util.List;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.http.HttpDsl.status;
import static java.util.UUID.randomUUID;

@Slf4j
public class CreateRegistrationScenario extends AbstractScenario {

    public static final ScenarioBuilder createRegistrationScenario = scenario(CreateRegistrationScenario.class.getName())
            .exec(prepareSessionData())
            .exec(session -> session.set("testUserId", generateUserId()))
            .exec(
                    http("Create registration PowerAuth Cloud")
                            .post(PowerAuthCommon.powerAuthCloudUrl + "v2/registrations")
                            .basicAuth("system-admin", "MLUteJ+uvi2EOP/F")
                            .body(StringBody("""
                                      {
                                      "userId": "#{testUserId}",
                                      "appId": "#{appId}"
                                    }
                                    """)
                            )
                            .check(status().is(200))
                            .check((jmesPath("activationCode").saveAs("activationCode")))
            )
            .exec(
                    http("Create activation Test Server")
                            .post(PowerAuthCommon.powerAuthTestServerUrl + "activation/create")
                            .body(StringBody("""
                                      {
                                      "requestObject": {
                                          "applicationId": "#{appId}",
                                          "activationName": "TEST ACTIVATION",
                                          "password": "1234",
                                          "activationCode": "#{activationCode}"
                                      }
                                    }""")
                            )
                            .check(status().is(200))
                            .check((jmesPath("responseObject.activationId").saveAs("activationId")))
            )
            .exec(
                    http("Commit registration PowerAuth Cloud")
                            .post(PowerAuthCommon.powerAuthCloudUrl + "v2/registrations/#{activationId}/commit")
                            .basicAuth("system-admin", "MLUteJ+uvi2EOP/F")
                            .body(StringBody("""
                                     {
                                      "externalUserId": null
                                    }
                                    """))
                            .check(status().is(200))
            ).exec(session -> {
                final List<String> testUserIds = session.contains("testUserIds") && session.get("testUserIds") != null ? session.get("testUserIds") : new ArrayList<>();
                testUserIds.add(session.get("testUserId"));
                return session.set("testUserIds", testUserIds);
            })
            .exec(saveSessionData());

    private static String generateUserId() {
        return "TEST_USER_ID" + randomUUID();
    }

}