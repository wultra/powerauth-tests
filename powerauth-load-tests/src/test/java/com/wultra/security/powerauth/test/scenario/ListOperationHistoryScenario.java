package com.wultra.security.powerauth.test.scenario;

import com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon;
import io.gatling.javaapi.core.ScenarioBuilder;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.http.HttpDsl.status;

public class ListOperationHistoryScenario {

    public static final ScenarioBuilder listOperationHistoryScenario = scenario(ListOperationHistoryScenario.class.getName())
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
            );


}
