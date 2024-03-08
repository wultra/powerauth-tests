/*
 * PowerAuth test and related software components
 * Copyright (C) 2024 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.wultra.security.powerauth.test.scenario;

import com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon;
import io.gatling.javaapi.core.ScenarioBuilder;

import java.util.List;
import java.util.Random;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.core.CoreDsl.StringBody;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.http.HttpDsl.status;

/**
 * Defines a Gatling scenario for creating operations within the PowerAuth system.
 * This scenario simulates the process of selecting a random user from a pre-defined list and creating an operation
 * for that user in PowerAuth Cloud using a specified template. The selection of the user and the operation creation
 * are performed dynamically during the test execution.
 * <p>
 * It requires the presence of a valid operation template in the PowerAuth system and utilizes user IDs
 * collected in previous test scenarios.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
public class CreateOperationScenario extends SharedSessionScenario {

    private static final Random rand = new Random();
    public static final ScenarioBuilder createOperationScenario = scenario(CreateOperationScenario.class.getName())
            .exec(prepareSessionData())
            .exec(session -> {
                final List<String> userIds = session.getList("testUserIds");
                final int index = rand.nextInt(userIds.size());
                final String selectedUserId = userIds.get(index);
                return session.set("testUserId", selectedUserId);
            })
            .exec(
                    http("Create operation PowerAuth Cloud")
                            .post(PowerAuthLoadTestCommon.PAC_URL + "/v2/operations")
                            .basicAuth(PowerAuthLoadTestCommon.PAC_ADMIN_USER, PowerAuthLoadTestCommon.PAC_ADMIN_PASS)
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
