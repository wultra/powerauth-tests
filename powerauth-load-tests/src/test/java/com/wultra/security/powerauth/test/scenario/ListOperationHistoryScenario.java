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
                                "requestObject":
                              {
                              "activationId": "#{activationId}",
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
                                          "activationId": "#{activationId}",
                                          "tokenId": "#{tokenId}",
                                          "tokenSecret": "#{tokenSecret}"
                                        }}
                                        """)
                            )
                            .check(status().is(200)));

}
