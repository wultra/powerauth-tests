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

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.core.OpenInjectionStep.atOnceUsers;
import static java.util.UUID.randomUUID;

@Slf4j
public class DataPreparationSimulation extends Simulation {

    @Override
    public void before() {
        logger.info("Preparation phase is about to start!");
    }

    @Override
    public void after() {
        logger.info("Preparation phase is finished!");
    }

    public static final List<Map<String, Object>> feedData = Stream.generate(() -> {
                Map<String, Object> stringObjectMap = new HashMap<>();
                stringObjectMap.put("testUserId", generateUserId());
                return stringObjectMap;
            })
            .limit(PowerAuthLoadTestCommon.PERF_TEST_PREP_N_REG)
            .collect(Collectors.toList());


    public DataPreparationSimulation() {
        setUp(
                CreateApplicationScenario.createApplicationScenario
                        .injectOpen(atOnceUsers(1))
                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
                        .andThen(
                                CreateRegistrationScenario.createRegistrationScenario
                                        .feed(listFeeder(feedData))
                                        .injectClosed(constantConcurrentUsers(PowerAuthLoadTestCommon.MAX_CONCURRENT_USERS).during(Duration.ofSeconds(PowerAuthLoadTestCommon.PERF_TEST_PREP_N_REG / PowerAuthLoadTestCommon.MAX_CONCURRENT_USERS)))
                                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
                                        .andThen(
                                                CreateOperationScenario.createOperationScenario
                                                        .feed(listFeeder(feedData))
                                                        .injectClosed(constantConcurrentUsers(PowerAuthLoadTestCommon.MAX_CONCURRENT_USERS).during(
                                                                Duration.ofSeconds((PowerAuthLoadTestCommon.PERF_TEST_PREP_M_OP * PowerAuthLoadTestCommon.PERF_TEST_PREP_N_REG) / PowerAuthLoadTestCommon.MAX_CONCURRENT_USERS)))
                                                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
                                        )
                        )

        );
    }

    /**
     * Generates a unique user ID using a UUID for testing purposes.
     *
     * @return A string representing a unique test user ID.
     */
    private static String generateUserId() {
        return "TEST_USER_ID" + randomUUID();
    }
}
