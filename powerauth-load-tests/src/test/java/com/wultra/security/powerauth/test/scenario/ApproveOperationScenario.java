package com.wultra.security.powerauth.test.scenario;

import com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon;
import io.gatling.javaapi.core.ScenarioBuilder;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.http.HttpDsl.status;

public class ApproveOperationScenario {

    public static final ScenarioBuilder approveOperationScenario = scenario(ApproveOperationScenario.class.getName())
            .exec(
                    http("Approve Operation Test Server")
                            .post(PowerAuthLoadTestCommon.TEST_SERVER_URL + "/operations/approve")
                            .body(StringBody("""
                                    {
                                      "activationId": "#{testUserId}",
                                      "applicationId": "#{appId},
                                      "password": "#{password},
                                      "operationId": "#{operationId},
                                      "operationData": "#{operationData}
                                    }
                                    """))
                            .check(status().is(200))
            );
}
