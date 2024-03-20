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
import static java.util.UUID.randomUUID;

/**
 * Defines a Gatling scenario for creating a new application in the PowerAuth system.
 * The scenario includes making HTTP requests to the PowerAuth Cloud to create an application,
 * adding user access to the newly created application, and configuring the application on the Test Server.
 * Utilizes dynamic values for application name and roles, and stores important response details for future steps.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
public class CreateApplicationScenario extends SharedSessionScenario {

    private static final String APP_NAME = "TEST_APP_" + randomUUID();
    private static final String INTEGRATION_USER_NAME = "integration-user-" + randomUUID();
    private static final String APP_ROLE = "ROLE_ADMIN";

    public static final ScenarioBuilder createApplicationScenario = scenario(CreateApplicationScenario.class.getName())
            .exec(
                    http("Create Application PowerAuth Cloud")
                            .post(PowerAuthLoadTestCommon.PAC_URL + "/admin/applications")
                            .basicAuth(PowerAuthLoadTestCommon.PAC_ADMIN_USER, PowerAuthLoadTestCommon.PAC_ADMIN_PASS)
                            .body(StringBody("""
                                    {
                                      "id": "%s",
                                      "roles": [
                                        "%s"
                                      ]
                                    }
                                    """.formatted(APP_NAME, APP_ROLE)))
                            .check(jmesPath("masterServerPublicKey").saveAs("masterServerPublicKey"),
                                    jmesPath("appKey").saveAs("appKey"),
                                    jmesPath("appSecret").saveAs("appSecret"),
                                    jmesPath("mobileSdkConfig").saveAs("mobileSdkConfig"),
                                    jmesPath("id").saveAs("appId"))
            )
            .exec(http("Create new integration user")
                    .post(PowerAuthLoadTestCommon.PAC_URL + "/admin/users")
                    .basicAuth(PowerAuthLoadTestCommon.PAC_ADMIN_USER, PowerAuthLoadTestCommon.PAC_ADMIN_PASS)
                    .body(StringBody("""
                             {
                                "username": "%s"
                                }
                            }
                              """.formatted(INTEGRATION_USER_NAME)))
                    .check(jmesPath("username").saveAs("pac-int-user"))
                    .check(jmesPath("password").saveAs("pac-int-user-pass")))
            .exec(
                    http("Add app access to integration user")
                            .post(PowerAuthLoadTestCommon.PAC_URL + "/admin/users/#{pac-int-user}/applications/#{appId}")
                            .basicAuth(PowerAuthLoadTestCommon.PAC_ADMIN_USER, PowerAuthLoadTestCommon.PAC_ADMIN_PASS)
            )
            .exec(
                    http("Create application Test Server")
                            .post(PowerAuthLoadTestCommon.TEST_SERVER_URL + "/application/config")
                            .body(StringBody("""
                                     {
                                        "requestObject": {
                                            "applicationId": "#{appId}",
                                            "applicationName": "%s",
                                            "applicationKey": "#{appKey}",
                                            "applicationSecret": "#{appSecret}",
                                            "masterPublicKey": "#{masterServerPublicKey}",
                                            "mobileSdkConfig": "#{mobileSdkConfig}"
                                        }
                                    }
                                      """.formatted(APP_NAME))))
            .exec(saveSessionData());
}
