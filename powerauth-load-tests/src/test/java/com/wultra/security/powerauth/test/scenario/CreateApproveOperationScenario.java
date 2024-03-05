package com.wultra.security.powerauth.test.scenario;

import com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon;
import io.gatling.javaapi.core.ScenarioBuilder;

import java.util.List;
import java.util.Random;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.http.HttpDsl.status;

public class CreateApproveOperationScenario extends SharedSessionScenario {

    private static final Random rand = new Random();

    public static final ScenarioBuilder createApproveOperationScenario = scenario(CreateApproveOperationScenario.class.getName())
            .exec(feed(PowerAuthLoadTestCommon.powerauthJdbcFeeder("SELECT name as \"appId\" FROM pa_application ORDER BY Id DESC LIMIT 1;").circular()))
            .exec(prepareSessionData())
            .exec(session -> {
                final List<String> userIds = session.getList("testUserIds");
                final int index = rand.nextInt(userIds.size());
                final String selectedUserId = userIds.get(index);
                return session.set("testUserId", selectedUserId);
            })
            .exec(
                    /* This works assuming template in pa_operation_template is defined */
                    http("Create operation PowerAuth Cloud")
                            .post(PowerAuthLoadTestCommon.PAC_URL + "/v2/operations")
                            .basicAuth(PowerAuthLoadTestCommon.PAC_ADMIN_USER, PowerAuthLoadTestCommon.PAC__ADMIN_PASS)
                            .body(StringBody("""
                                      {
                                      "userId": "#{testUserId}",
                                      "template": "login",
                                      "language": "en"
                                    }
                                    """)
                            )
                            .check(status().is(200))
            )
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
