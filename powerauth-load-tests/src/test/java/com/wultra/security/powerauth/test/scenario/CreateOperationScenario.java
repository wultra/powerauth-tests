package com.wultra.security.powerauth.test.scenario;

import com.wultra.security.powerauth.test.config.PowerAuthCommon;
import io.gatling.javaapi.core.ScenarioBuilder;
import io.gatling.javaapi.core.Session;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Random;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.core.CoreDsl.StringBody;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.http.HttpDsl.status;

@Slf4j
public class CreateOperationScenario extends AbstractScenario {

    private static final Random rand = new Random();
    public static final ScenarioBuilder createOperationScenario = scenario(CreateOperationScenario.class.getName())
            .exec(prepareSessionData()).
            exec(session -> {
                final List<String> userIds = session.getList("testUserIds");
                final int index = rand.nextInt(userIds.size());
                final String selectedUserId = userIds.get(index);
                return session.set("testUserId", selectedUserId);
            })
            .exec(
                    /* This works assuming template in pa_operation_template is defined*/
                    http("Create operation PowerAuth Cloud")
                            .post(PowerAuthCommon.powerAuthCloudUrl + "v2/operations")
                            .basicAuth("system-admin", "MLUteJ+uvi2EOP/F")
                            .body(StringBody("""
                                      {
                                      "userId": "#{testUserId}",
                                      "template": "login",
                                      "language": "en"
                                    }
                                    """)
                            )
                            .check(status().is(200))
            );
}
