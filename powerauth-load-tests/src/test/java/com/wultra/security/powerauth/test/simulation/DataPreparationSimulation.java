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
import com.wultra.security.powerauth.test.scenario.CreateApplicationScenario;
import com.wultra.security.powerauth.test.scenario.CreateOperationScenario;
import com.wultra.security.powerauth.test.scenario.CreateRegistrationScenario;
import io.gatling.javaapi.core.Simulation;
import lombok.extern.slf4j.Slf4j;

import static io.gatling.javaapi.core.OpenInjectionStep.atOnceUsers;

/**
 * Prepares the data environment for PowerAuth load testing by simulating application creation,
 * user registrations, and operation creation processes.
 * <p>
 * This simulation sequence is critical for setting up a realistic test environment
 * that mimics actual user and transactional activity. It executes the following steps:
 * <ol>
 *     <li>Creates a single application instance.</li>
 *     <li>Registers multiple users concurrently based on the maximum number of concurrent users defined.</li>
 *     <li>Creates multiple operations concurrently for the registered users.</li>
 * </ol>
 * Each step is crucial for ensuring the subsequent load tests have the necessary data setup for execution.
 * <p>
 * The {@code before()} and {@code after()} methods provide logging information to track the start and end of the preparation phase.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
@Slf4j
public class DataPreparationSimulation extends Simulation {

    @Override
    public void before() {
        logger.info("Preparation phase is about to start!");
    }

    @Override
    public void after() {
        PowerAuthLoadTestCommon.saveGeneratedData();
        logger.info("Preparation phase is finished!");
    }

    public DataPreparationSimulation() {
        PowerAuthLoadTestCommon.setPreparationPhase(true);
        PowerAuthLoadTestCommon.prepareFeedDataUsers();

        setUp(
                CreateApplicationScenario.createApplicationScenario
                        .injectOpen(atOnceUsers(1))
                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
                        .andThen(
                                CreateRegistrationScenario.createRegistrationScenario
                                        .injectOpen(atOnceUsers(PowerAuthLoadTestCommon.MAX_CONCURRENT_USERS))
                                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
                                        .disablePauses()
                                        .andThen(
                                                CreateOperationScenario.createOperationScenario
                                                        .injectOpen(atOnceUsers(PowerAuthLoadTestCommon.MAX_CONCURRENT_USERS))
                                                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
                                                        .disablePauses()
                                        )
                        )

        );
    }
}
