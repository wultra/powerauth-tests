package com.wultra.security.powerauth.test.simulation;

import com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon;
import com.wultra.security.powerauth.test.scenario.ApproveOperationScenario;
import com.wultra.security.powerauth.test.scenario.CreateRegistrationScenario;
import com.wultra.security.powerauth.test.scenario.ListOperationHistoryScenario;
import io.gatling.javaapi.core.Simulation;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import static io.gatling.javaapi.core.CoreDsl.rampUsers;

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
        PowerAuthLoadTestCommon.isPreparation = false;
        setUp(
                /* Load test */
                CreateRegistrationScenario.createRegistrationScenario
                        .injectOpen(rampUsers(1).during(Duration.ofSeconds(1)))
                        .protocols(PowerAuthLoadTestCommon.commonProtocol),
                ApproveOperationScenario.approveOperationScenario
                        .injectOpen(rampUsers(1).during(Duration.ofSeconds(1)))
                        .protocols(PowerAuthLoadTestCommon.commonProtocol),
                ListOperationHistoryScenario.listOperationHistoryScenario
                        .injectOpen(rampUsers(1).during(Duration.ofSeconds(1)))
                        .protocols(PowerAuthLoadTestCommon.commonProtocol).andThen(
                                /* Stress Test */
            /* TODO: specify stress test and other params*/
                        )
        );
    }
}
