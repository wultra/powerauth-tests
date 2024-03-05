package com.wultra.security.powerauth.test.scenario;

import com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon;
import io.gatling.javaapi.core.ScenarioBuilder;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.http.HttpDsl.status;

public class ApproveOperationScenario extends SharedSessionScenario {

    public static final ScenarioBuilder approveOperationScenario = scenario(ApproveOperationScenario.class.getName())
            .feed(PowerAuthLoadTestCommon.powerauthJdbcFeeder(
                    """
                            SELECT
                                a.user_id AS "testUserId",
                                a.activation_id AS "activationId",
                                p.name AS "appId",
                                o.id AS "operationId"
                            FROM
                                pa_activation a
                            JOIN
                                pa_operation o ON a.user_id = o.user_id
                            JOIN
                                pa_application p ON a.application_id = p.id
                            WHERE
                                a.application_id = (
                                    SELECT id
                                    FROM pa_application
                                    ORDER BY id DESC
                                    LIMIT 1
                                );
                           """
            ).random())
            .exec(
                    http("Approve Operation Test Server")
                            .post(PowerAuthLoadTestCommon.TEST_SERVER_URL + "/operations/approve")
                            .body(StringBody("""
                                    {
                                        "requestObject":
                                            {
                                                "activationId": "#{activationId}",
                                                "applicationId": "#{appId}",
                                                "password": "1234",
                                                "operationData": "A2",
                                                "operationId": "#{operationId}"
                                            }
                                        }
                                    }
                                    """))
                            .check(status().is(200))
            );
}
