package com.wultra.security.powerauth.test.simulation;

import com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon;
import com.wultra.security.powerauth.test.scenario.CreateApplicationScenario;
import com.wultra.security.powerauth.test.scenario.CreateCallbackScenario;
import com.wultra.security.powerauth.test.scenario.CreateOperationScenario;
import com.wultra.security.powerauth.test.scenario.CreateRegistrationScenario;
import io.gatling.javaapi.core.Simulation;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;

import static io.gatling.javaapi.core.CoreDsl.rampUsers;
import static io.gatling.javaapi.core.OpenInjectionStep.atOnceUsers;

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

    /*
     * N reg = 1000 0000
     * M op  = 10
     *
     * */

    public DataPreparationSimulation() {
        setUp(
                CreateApplicationScenario.createApplicationScenario
                        .injectOpen(atOnceUsers(1))
                        .protocols(PowerAuthLoadTestCommon.commonProtocol).andThen(
                                CreateCallbackScenario.createCallbackScenario
                                        .injectOpen(atOnceUsers(1))
                                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
                        )
                        .andThen(
                                CreateRegistrationScenario.createRegistrationScenario
                                        .injectOpen(rampUsers(Integer.getInteger(PowerAuthLoadTestCommon.PERF_TEST_PREP_N_REG)).during(Duration.ofMinutes(5)))
                                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
                                        .andThen(
                                                CreateOperationScenario.createOperationScenario
                                                        .injectOpen(rampUsers(Integer.getInteger(PowerAuthLoadTestCommon.PREP_TEST_PREP_M_OP)).during(Duration.ofMinutes(5)))
                                                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
                                        )
                        )

        );
    }
}
