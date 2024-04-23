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

/**
 * Defines the Gatling scenario for listing operation history.
 * <p>
 * This scenario simulates the process of creating a token on the test server and
 * then using it to list pending operations. It utilizes a circular feeder from
 * {@link PowerAuthLoadTestCommon} to ensure a continuous flow of user data.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
public class ListOperationHistoryScenario {

    public static final ScenarioBuilder listOperationHistoryScenario = scenario(ListOperationHistoryScenario.class.getName())
            .exec(feed(PowerAuthLoadTestCommon.getUserDataFeed().circular()))
            .exec(http("Create Token Test Server")
                    .post(PowerAuthLoadTestCommon.TEST_SERVER_URL + "/token/create")
                    .body(StringBody("""
                               {
                                "requestObject":
                              {
                              "activationId": "#{registrationId}",
                              "applicationId": "#{appId}",
                              "signatureType": "POSSESSION"
                            }}
                            """)
                    )
                    .check(status().is(200))
                    .check((jmesPath("responseObject.tokenId").saveAs("tokenId")))
                    .check((jmesPath("responseObject.tokenSecret").saveAs("tokenSecret"))))
            .exec(
                    http("List Operation History Test Server")
                            .post(PowerAuthLoadTestCommon.TEST_SERVER_URL + "/operations/pending")
                            .body(StringBody("""
                                          {
                                    "requestObject":
                                          {
                                          "activationId": "#{registrationId}",
                                          "tokenId": "#{tokenId}",
                                          "tokenSecret": "#{tokenSecret}"
                                        }}
                                        """)
                            )
                            .check(status().is(200)));

}
