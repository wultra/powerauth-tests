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
package com.wultra.security.powerauth.test.simulation;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon;
import com.wultra.security.powerauth.test.scenario.CreateApproveOperationScenario;
import com.wultra.security.powerauth.test.scenario.CreateCallbackScenario;
import com.wultra.security.powerauth.test.scenario.CreateRegistrationScenario;
import com.wultra.security.powerauth.test.scenario.ListOperationHistoryScenario;
import io.gatling.javaapi.core.Simulation;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.core.OpenInjectionStep.atOnceUsers;

@Slf4j
public class PerformanceTestSimulation extends Simulation {

    private final WireMockServer wireMockServer = new WireMockServer(8090);

    @Override
    public void before() {
        wireMockServer.stubFor(get(urlEqualTo("/mock-callback")).willReturn(aResponse().withBody("Callback ok")));
        wireMockServer.start();
        logger.info("Execution phase is about to start!");
    }

    @Override
    public void after() {
        logger.info("Execution phase is finished!");
        wireMockServer.stop();
    }

    public PerformanceTestSimulation() {
        setUp(
                /* Load test  - constant user engagement */
                CreateCallbackScenario.createCallbackScenario
                        .injectOpen(atOnceUsers(1))
                        .protocols(PowerAuthLoadTestCommon.commonProtocol).andThen(
                                CreateRegistrationScenario.createRegistrationScenario
                                        .injectOpen(constantUsersPerSec(PowerAuthLoadTestCommon.PERF_TEST_EXE_X_REG).during(Duration.ofMinutes(PowerAuthLoadTestCommon.PERF_TEST_EXE_MIN)).randomized())
                                        .protocols(PowerAuthLoadTestCommon.commonProtocol),
                                CreateApproveOperationScenario.createApproveOperationScenario
                                        .injectOpen(constantUsersPerSec(PowerAuthLoadTestCommon.PERF_TEST_EXE_Y_OP).during(Duration.ofMinutes(PowerAuthLoadTestCommon.PERF_TEST_EXE_MIN)).randomized())
                                        .protocols(PowerAuthLoadTestCommon.commonProtocol),
                                ListOperationHistoryScenario.listOperationHistoryScenario
                                        .injectOpen(constantUsersPerSec(PowerAuthLoadTestCommon.PERF_TEST_EXE_Y_OP * 0.1).during(Duration.ofMinutes(PowerAuthLoadTestCommon.PERF_TEST_EXE_MIN)).randomized())
                                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
                        ).andThen(
                                /* Stress test  - ramping user engagement */
                                CreateRegistrationScenario.createRegistrationScenario
                                        .injectOpen(stressPeakUsers(100).during(Duration.ofSeconds(10)))
                                        .protocols(PowerAuthLoadTestCommon.commonProtocol),
                                CreateApproveOperationScenario.createApproveOperationScenario
                                        .injectOpen(stressPeakUsers(100).during(Duration.ofSeconds(10)))
                                        .protocols(PowerAuthLoadTestCommon.commonProtocol),
                                ListOperationHistoryScenario.listOperationHistoryScenario
                                        .injectOpen(stressPeakUsers(100).during(Duration.ofSeconds(10)))
                                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
                        ));
    }
}
