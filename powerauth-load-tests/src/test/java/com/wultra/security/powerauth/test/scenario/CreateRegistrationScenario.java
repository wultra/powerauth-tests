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
 * Implements a scenario for testing user registration, activation, and commitment in PowerAuth.
 * This scenario simulates the complete lifecycle of a user's registration and activation process
 * by dynamically generating a unique user ID, creating a registration in PowerAuth Cloud, initiating
 * an activation on the Test Server, and committing the registration.
 * <p>
 * The scenario includes checks for successful HTTP responses at each step and utilizes session management
 * to pass necessary data between requests. It also adds the generated test user ID to a list of user IDs
 * for potential use in subsequent scenarios.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
public class CreateRegistrationScenario extends SharedSessionScenario {

    public static final ScenarioBuilder createRegistrationScenario = scenario(CreateRegistrationScenario.class.getName())
            .exec(prepareSessionData())
            .doIfOrElse(String.valueOf(PowerAuthLoadTestCommon.isPrep()))
            .then(repeat((PowerAuthLoadTestCommon.PERF_TEST_PREP_N_REG / PowerAuthLoadTestCommon.MAX_CONCURRENT_USERS)).on(
                    feed(PowerAuthLoadTestCommon.getUserDataFeed().shuffle())
                            .exec(
                                    http("Create registration PowerAuth Cloud")
                                            .post(PowerAuthLoadTestCommon.PAC_URL + "/v2/registrations")
                                            .basicAuth("#{pac-int-user}", "#{pac-int-user-pass}")
                                            .body(StringBody("""
                                                      {
                                                      "userId": "#{testUserId}",
                                                      "appId": "#{appId}"
                                                    }
                                                    """)
                                            )
                                            .check(status().is(200))
                                            .check((jmesPath("activationCode").saveAs("activationCode")))
                            )
                            .exec(
                                    http("Create activation Test Server")
                                            .post(PowerAuthLoadTestCommon.TEST_SERVER_URL + "/activation/create")
                                            .body(StringBody("""
                                                      {
                                                      "requestObject": {
                                                          "applicationId": "#{appId}",
                                                          "activationName": "TEST ACTIVATION",
                                                          "password": "1234",
                                                          "activationCode": "#{activationCode}"
                                                      }
                                                    }""")
                                            )
                                            .check(status().is(200))
                                            .check((jmesPath("responseObject.activationId").saveAs("activationId")))
                            )
                            .exec(
                                    http("Commit registration PowerAuth Cloud")
                                            .post(PowerAuthLoadTestCommon.PAC_URL + "/v2/registrations/#{activationId}/commit")
                                            .basicAuth("#{pac-int-user}", "#{pac-int-user-pass}")
                                            .body(StringBody("""
                                                     {
                                                      "externalUserId": null
                                                    }
                                                    """))
                                            .check(status().is(200))
                            )
                            .exec(saveSessionData())
                            .exec(saveRegistrationData())))

            .orElse(
                    feed(PowerAuthLoadTestCommon.getUserDataFeed().shuffle())
                            .exec(
                                    http("Create registration PowerAuth Cloud")
                                            .post(PowerAuthLoadTestCommon.PAC_URL + "/v2/registrations")
                                            .basicAuth("#{integrationUser}", "#{integrationUserPass}")
                                            .body(StringBody("""
                                                      {
                                                      "userId": "#{testUserId}",
                                                      "appId": "#{appId}"
                                                    }
                                                    """)
                                            )
                                            .check(status().is(200))
                                            .check((jmesPath("activationCode").saveAs("activationCode")))
                            )
                            .exec(
                                    http("Create activation Test Server")
                                            .post(PowerAuthLoadTestCommon.TEST_SERVER_URL + "/activation/create")
                                            .body(StringBody("""
                                                      {
                                                      "requestObject": {
                                                          "applicationId": "#{appId}",
                                                          "activationName": "TEST ACTIVATION",
                                                          "password": "1234",
                                                          "activationCode": "#{activationCode}"
                                                      }
                                                    }""")
                                            )
                                            .check(status().is(200))
                                            .check((jmesPath("responseObject.activationId").saveAs("activationId")))
                            )
                            .exec(
                                    http("Commit registration PowerAuth Cloud")
                                            .post(PowerAuthLoadTestCommon.PAC_URL + "/v2/registrations/#{activationId}/commit")
                                            .basicAuth("#{integrationUser}", "#{integrationUserPass}")
                                            .body(StringBody("""
                                                     {
                                                      "externalUserId": null
                                                    }
                                                    """))
                                            .check(status().is(200))
                            )
                            .exec(saveSessionData()));

}