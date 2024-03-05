package com.wultra.security.powerauth.test.simulation;

import com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon;
import com.wultra.security.powerauth.test.scenario.CreateApplicationScenario;
import com.wultra.security.powerauth.test.scenario.CreateCallbackScenario;
import com.wultra.security.powerauth.test.scenario.CreateOperationScenario;
import com.wultra.security.powerauth.test.scenario.CreateRegistrationScenario;
import io.gatling.javaapi.core.Simulation;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;

import static com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon.NUM_OF_PREPARED_OPERATIONS;
import static com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon.NUM_OF_PREPARED_REGISTRATIONS;
import static io.gatling.javaapi.core.CoreDsl.rampUsers;
import static io.gatling.javaapi.core.OpenInjectionStep.atOnceUsers;

@Slf4j
public class DataPreparationSimulation extends Simulation {

    @Override
    public void before() {
        logger.info("Simulation is about to start!");
    }

    @Override
    public void after() {
        logger.info("Simulation is finished!");
    }

    public DataPreparationSimulation() {
        PowerAuthLoadTestCommon.isPreparation = true;
        setUp(
                CreateApplicationScenario.createApplicationScenario
                        .injectOpen(atOnceUsers(1))
                        .protocols(PowerAuthLoadTestCommon.commonProtocol).andThen(
                                CreateCallbackScenario.createCallbackScenario
                                        .injectOpen()
                                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
                        )
                        .andThen(
                                CreateRegistrationScenario.createRegistrationScenario
                                        .injectOpen(rampUsers(NUM_OF_PREPARED_REGISTRATIONS).during(Duration.ofSeconds(1)))
                                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
                                        .andThen(
                                                CreateOperationScenario.createOperationScenario
                                                        .injectOpen(rampUsers(NUM_OF_PREPARED_OPERATIONS).during(Duration.ofSeconds(10)))
                                                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
                                        )
                        )

        );
    }
}
