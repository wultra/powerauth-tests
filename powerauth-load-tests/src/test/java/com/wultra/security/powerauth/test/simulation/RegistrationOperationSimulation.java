package com.wultra.security.powerauth.test.simulation;


import com.wultra.security.powerauth.test.config.PowerAuthCommon;
import com.wultra.security.powerauth.test.scenario.CreateApplicationScenario;
import com.wultra.security.powerauth.test.scenario.CreateOperationScenario;
import com.wultra.security.powerauth.test.scenario.CreateRegistrationScenario;
import io.gatling.javaapi.core.Simulation;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;

import static io.gatling.javaapi.core.CoreDsl.rampUsers;
import static io.gatling.javaapi.core.OpenInjectionStep.atOnceUsers;

@Slf4j
public class RegistrationOperationSimulation extends Simulation {

    private static final int NUM_OF_PREPARED_REGISTRATIONS = 5;
    private static final int NUM_OF_PREPARED_OPERATIONS = 10;

    private static final int NUM_OF_EXECUTED_REGISTRATIONS_TOTAL = 10;
    private static final int NUM_OF_EXECUTED_REGISTRATIONS_MINS = 2;

    @Override
    public void before() {
        logger.info("Simulation is about to start!");
    }

    @Override
    public void after() {
        logger.info("Simulation is finished!");
    }


    public RegistrationOperationSimulation() {
        setUp(
                /* Preparation phase */
                CreateApplicationScenario.createApplicationScenario
                        .injectOpen(atOnceUsers(1))
                        .protocols(PowerAuthCommon.commonProtocol)
                        .andThen(
                                CreateRegistrationScenario.createRegistrationScenario
                                        .injectOpen(rampUsers(NUM_OF_PREPARED_REGISTRATIONS).during(Duration.ofSeconds(1)))
                                        .protocols(PowerAuthCommon.commonProtocol)
                                        .andThen(
                                                CreateOperationScenario.createOperationScenario
                                                        .injectOpen(rampUsers(NUM_OF_PREPARED_OPERATIONS).during(Duration.ofSeconds(10)))
                                                        .protocols(PowerAuthCommon.commonProtocol)
                                                        .andThen(
                                                                /* Execution phase */
                                                                CreateRegistrationScenario.createRegistrationScenario
                                                                        .injectOpen(rampUsers(NUM_OF_EXECUTED_REGISTRATIONS_TOTAL).during(Duration.ofMinutes(NUM_OF_EXECUTED_REGISTRATIONS_MINS)))
                                                                        .protocols(PowerAuthCommon.commonProtocol),
                                                                CreateOperationScenario.createOperationScenario
                                                                        .injectOpen(rampUsers(NUM_OF_EXECUTED_REGISTRATIONS_TOTAL).during(Duration.ofMinutes(NUM_OF_EXECUTED_REGISTRATIONS_MINS)))
                                                                        .protocols(PowerAuthCommon.commonProtocol)
                                                        )
                                        )
                        )

        );
    }
}
