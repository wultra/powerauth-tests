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

import com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon;
import com.wultra.security.powerauth.test.scenario.CreateApproveOperationScenario;
import com.wultra.security.powerauth.test.scenario.CreateCallbackScenario;
import com.wultra.security.powerauth.test.scenario.CreateRegistrationScenario;
import com.wultra.security.powerauth.test.scenario.ListOperationHistoryScenario;
import io.gatling.javaapi.core.PopulationBuilder;
import io.gatling.javaapi.core.Simulation;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;

import static io.gatling.javaapi.core.CoreDsl.*;

/**
 * Orchestrates the execution of performance testing scenarios for PowerAuth components.
 * This simulation includes steps for creating callbacks, registering users, approving operations,
 * and listing operation history to evaluate the performance under various conditions.
 * <p>
 * It utilizes WireMock for mocking external service responses during local testing. The simulation sequence
 * is designed to mimic realistic user behavior and system interactions to identify potential bottlenecks and
 * performance issues.
 * </p>
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
@Slf4j
public class PerformanceTestSimulation extends Simulation {

    @Override
    public void before() {
        logger.info("Execution phase is about to start!");
    }

    @Override
    public void after() {
        logger.info("Execution phase is finished!");
    }


    public PerformanceTestSimulation() {
        PowerAuthLoadTestCommon.prepareFeedDataUsers();
        setUp(prepareSimulationRun());
    }


    private PopulationBuilder[] prepareSimulationRun() {
        if (PowerAuthLoadTestCommon.PERF_TEST_USE_CALLBACKS) {
            return new PopulationBuilder[]{
                    CreateCallbackScenario.createCallbackScenario
                            .injectOpen(atOnceUsers(1))
                            .protocols(PowerAuthLoadTestCommon.commonProtocol).andThen(
                            CreateRegistrationScenario.createRegistrationScenario
                                    .injectOpen(constantUsersPerSec(PowerAuthLoadTestCommon.PERF_TEST_EXE_X_REG).during(Duration.ofMinutes(PowerAuthLoadTestCommon.PERF_TEST_EXE_MIN)))
                                    .protocols(PowerAuthLoadTestCommon.commonProtocol),
                            CreateApproveOperationScenario.createApproveOperationScenario
                                    .injectOpen(constantUsersPerSec(PowerAuthLoadTestCommon.PERF_TEST_EXE_Y_OP).during(Duration.ofMinutes(PowerAuthLoadTestCommon.PERF_TEST_EXE_MIN)))
                                    .protocols(PowerAuthLoadTestCommon.commonProtocol),
                            ListOperationHistoryScenario.listOperationHistoryScenario
                                    .injectOpen(constantUsersPerSec(PowerAuthLoadTestCommon.PERF_TEST_PREP_N_REG * PowerAuthLoadTestCommon.PERF_TEST_EXE_PENDING_OP_POOLING).during(Duration.ofMinutes(PowerAuthLoadTestCommon.PERF_TEST_EXE_MIN)).randomized())
                                    .protocols(PowerAuthLoadTestCommon.commonProtocol))
            };
        } else {
            return new PopulationBuilder[]{
                    CreateRegistrationScenario.createRegistrationScenario
                            .injectOpen(constantUsersPerSec(PowerAuthLoadTestCommon.PERF_TEST_EXE_X_REG)
                                    .during(Duration.ofMinutes(PowerAuthLoadTestCommon.PERF_TEST_EXE_MIN)))
                            .protocols(PowerAuthLoadTestCommon.commonProtocol),
                    CreateApproveOperationScenario.createApproveOperationScenario
                            .injectOpen(constantUsersPerSec(PowerAuthLoadTestCommon.PERF_TEST_EXE_Y_OP)
                                    .during(Duration.ofMinutes(PowerAuthLoadTestCommon.PERF_TEST_EXE_MIN)))
                            .protocols(PowerAuthLoadTestCommon.commonProtocol),
                    ListOperationHistoryScenario.listOperationHistoryScenario
                            .injectOpen(constantUsersPerSec(PowerAuthLoadTestCommon.PERF_TEST_PREP_N_REG * PowerAuthLoadTestCommon.PERF_TEST_EXE_PENDING_OP_POOLING)
                                    .during(Duration.ofMinutes(PowerAuthLoadTestCommon.PERF_TEST_EXE_MIN)).randomized())
                            .protocols(PowerAuthLoadTestCommon.commonProtocol)
            };
        }
    }
}
