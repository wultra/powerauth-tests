package com.wultra.security.powerauth.test.scenario;

import com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon;
import io.gatling.javaapi.core.ScenarioBuilder;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.http.HttpDsl.status;

public class ListOperationHistoryScenario {

    public static final ScenarioBuilder listOperationHistoryScenario = scenario(ListOperationHistoryScenario.class.getName())
            .feed(PowerAuthLoadTestCommon.powerauthJdbcFeeder(
                    """
                            SELECT a.user_id AS "testUserId",
                            a.activation_id AS "activationId",
                            p.name AS "appId"
                            FROM pa_activation a
                            JOIN pa_application p ON a.application_id = p.id
                            WHERE application_id = (
                              SELECT id
                              FROM pa_application
                              ORDER BY Id DESC
                              LIMIT 1
                            );
                            """
            ).random())
            .exec(http("Create Token Test Server")
                    .post(PowerAuthLoadTestCommon.TEST_SERVER_URL + "/token/create")
                    .body(StringBody("""
                              {
                              "activationId": "#{activationId}",
                              "applicationId": "#{appId}",
                              "signatureType": "POSSESSION"
                            }
                            """)
                    )
                    .check(status().is(200))
                    .check((jmesPath("tokenId").saveAs("tokenId")))
                    .check((jmesPath("tokenSecret").saveAs("tokenSecret"))))
            .exec(
                    http("List Operation History Test Server")
                            .post(PowerAuthLoadTestCommon.TEST_SERVER_URL + "/operations/pending")
                            .body(StringBody("""
                                      {
                                      "activationId": "#{activationId}",
                                      "tokenId": "#{tokenId}",
                                      "tokenSecret": "#{tokenSecret}"
                                    }
                                    """)
                            )
                            .check(status().is(200)));

}
