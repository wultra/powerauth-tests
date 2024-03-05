package com.wultra.security.powerauth.test.scenario;

import com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon;
import io.gatling.javaapi.core.ScenarioBuilder;


import static io.gatling.javaapi.core.CoreDsl.StringBody;
import static io.gatling.javaapi.core.CoreDsl.scenario;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.http.HttpDsl.status;
import static java.util.UUID.randomUUID;

public class CreateCallbackScenario extends SharedSessionScenario {
    private static final String CALLBACK_NAME = "TEST_CALLBACK" + randomUUID();
    public static final ScenarioBuilder createCallbackScenario = scenario(CreateCallbackScenario.class.getName())
            .exec(prepareSessionData())
            .exec(
                    http("Create callback PowerAuth Cloud")
                            .post(PowerAuthLoadTestCommon.PAC_URL + "/v2/admin/operations/#{appId}/callbacks")
                            .basicAuth(PowerAuthLoadTestCommon.PAC_ADMIN_USER, PowerAuthLoadTestCommon.PAC__ADMIN_PASS)
                            .body(StringBody("""
                                      {
                                      "name": "%s",
                                      "type": "OPERATION_STATUS_CHANGE",
                                      "callbackUrl": "http://localhost:8090/mock-callback"
                                    }
                                    """.formatted(CALLBACK_NAME))
                            )
                            .check(status().is(200))
            ).exec(
                    http("Create callback PowerAuth Cloud")
                            .post(PowerAuthLoadTestCommon.PAC_URL + "/v2/admin/operations/#{appId}/callbacks")
                            .basicAuth(PowerAuthLoadTestCommon.PAC_ADMIN_USER, PowerAuthLoadTestCommon.PAC__ADMIN_PASS)
                            .body(StringBody("""
                                      {
                                      "name": "%s",
                                      "type": "REGISTRATION_STATUS_CHANGE",
                                      "callbackUrl": "http://localhost:8090/mock-callback"
                                    }
                                    """.formatted(CALLBACK_NAME))
                            )
                            .check(status().is(200))
            );

}
