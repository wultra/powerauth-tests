package com.wultra.security.powerauth.test.scenario;

import com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon;
import io.gatling.javaapi.core.ScenarioBuilder;
import lombok.extern.slf4j.Slf4j;


import java.util.ArrayList;
import java.util.List;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.http.HttpDsl.status;
import static java.util.UUID.randomUUID;

@Slf4j
public class CreateRegistrationScenario extends SharedSessionScenario {

    public static final ScenarioBuilder createRegistrationScenario = scenario(CreateRegistrationScenario.class.getName())
            .doIf(String.valueOf(PowerAuthLoadTestCommon.isPreparation)).then(exec(prepareSessionData()))
            .doIfEquals(String.valueOf(PowerAuthLoadTestCommon.isPreparation), String.valueOf(Boolean.FALSE))
            .then(feed(PowerAuthLoadTestCommon.powerauthJdbcFeeder("SELECT name as \"appId\" FROM pa_application ORDER BY Id DESC LIMIT 1;").circular()))
            .exec(session -> session.set("testUserId", generateUserId()))
            .exec(
                    http("Create registration PowerAuth Cloud")
                            .post(PowerAuthLoadTestCommon.PAC_URL + "/v2/registrations")
                            .basicAuth(PowerAuthLoadTestCommon.PAC_ADMIN_USER, PowerAuthLoadTestCommon.PAC__ADMIN_PASS)
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
                            .post(PowerAuthLoadTestCommon.TEST_SERVER_URL + "/activation/create")
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
                            .post(PowerAuthLoadTestCommon.PAC_URL + "/v2/registrations/#{activationId}/commit")
                            .basicAuth(PowerAuthLoadTestCommon.PAC_ADMIN_USER, PowerAuthLoadTestCommon.PAC__ADMIN_PASS)
                            .body(StringBody("""
                                     {
                                      "externalUserId": null
                                    }
                                    """))
                            .check(status().is(200))
            ).doIf(String.valueOf(PowerAuthLoadTestCommon.isPreparation)).then(
                    exec(session -> {
                        final List<String> testUserIds = session.contains("testUserIds") && session.get("testUserIds") != null ? session.get("testUserIds") : new ArrayList<>();
                        testUserIds.add(session.get("testUserId"));
                        return session.set("testUserIds", testUserIds);
                    }).exec(saveSessionData()));

    private static String generateUserId() {
        return "TEST_USER_ID" + randomUUID();
    }

}