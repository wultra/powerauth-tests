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
import lombok.extern.slf4j.Slf4j;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.http.HttpDsl.status;

/**
 * Defines a scenario for creating and approving operations in PowerAuth.
 * Utilizes predefined user and application data to simulate operation creation and approval
 * against both PowerAuth Cloud and a Test Server. It randomizes user selection for operation
 * initiation.
 * <p>
 * This scenario is part of the suite to evaluate the performance and robustness of the PowerAuth solution.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
@Slf4j
public class CreateApproveOperationScenario extends SharedSessionScenario {

    public static final ScenarioBuilder createApproveOperationScenario = scenario(CreateApproveOperationScenario.class.getName())
            .feed(PowerAuthLoadTestCommon.getUserDataFeed().circular())
            .exec(
                    /* This works assuming template in pa_operation_template is defined */
                    http("Create operation PowerAuth Cloud")
                            .post(PowerAuthLoadTestCommon.PAC_URL + "/v2/operations")
                            .basicAuth("#{integrationUser}", "#{integrationUserPass}")
                            .body(StringBody("""
                                      {
                                      "userId": "#{testUserId}",
                                      "template": "login",
                                      "language": "en"
                                    }
                                    """)
                            )
                            .check(status().is(200))
                            .check((jmesPath("operationId").saveAs("operationId")))
            )
            .exec(
                    http("Approve Operation Test Server")
                            .post(PowerAuthLoadTestCommon.TEST_SERVER_URL + "/operations/approve")
                            .body(StringBody("""
                                    {
                                        "requestObject":
                                            {
                                                "activationId": "#{registrationId}",
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
