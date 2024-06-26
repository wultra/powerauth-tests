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


import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.http.HttpDsl.status;
import static java.util.UUID.randomUUID;

/**
 * Defines a Gatling scenario for creating callback configurations in PowerAuth Cloud.
 * This scenario focuses on setting up callbacks for both operation status changes and registration status changes.
 * Each callback is associated with a randomly generated name and is configured to post
 * notifications to a mock callback URL.
 * <p>
 * Successful creation of callbacks is validated by checking the HTTP response status.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */

public class CreateCallbackScenario {
    private static final String CALLBACK_NAME = "TEST_CALLBACK_" + randomUUID();
    public static final ScenarioBuilder createCallbackScenario = scenario(CreateCallbackScenario.class.getName())
            .feed(PowerAuthLoadTestCommon.getUserDataFeed().shuffle())
            .exec(
                    http("Create callback PowerAuth Cloud - Operations")
                            .post(PowerAuthLoadTestCommon.PAC_URL + "/v2/admin/applications/#{appId}/callbacks")
                            .basicAuth("#{integrationUser}", "#{integrationUserPass}")
                            .body(StringBody("""
                                      {
                                      "name": "%s",
                                      "type": "OPERATION_STATUS_CHANGE",
                                      "callbackUrl": "%s"
                                    }
                                    """.formatted(CALLBACK_NAME, PowerAuthLoadTestCommon.CALLBACK_URL))
                            )
                            .check(status().is(200))
            ).exec(
                    http("Create callback PowerAuth Cloud - Registrations")
                            .post(PowerAuthLoadTestCommon.PAC_URL + "/v2/admin/applications/#{appId}/callbacks")
                            .basicAuth("#{integrationUser}", "#{integrationUserPass}")
                            .body(StringBody("""
                                      {
                                      "name": "%s",
                                      "type": "REGISTRATION_STATUS_CHANGE",
                                      "callbackUrl": "%s"
                                    }
                                    """.formatted(CALLBACK_NAME, PowerAuthLoadTestCommon.CALLBACK_URL))
                            )
                            .check(status().is(200))
            );

}
