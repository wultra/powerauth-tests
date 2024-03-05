package com.wultra.security.powerauth.test.simulation;

import com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon;
import com.wultra.security.powerauth.test.scenario.CreateApproveOperationScenario;
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

    /*
     * X = 10/min
     * Y = 100/s
     * Z = (Y*0.1)/s
     * */

    public PerformanceTestSimulation() {
        setUp(
                /* Load test */
                CreateRegistrationScenario.createRegistrationScenario
                        .injectOpen(rampUsers(Integer.getInteger(PowerAuthLoadTestCommon.PERF_TEST_EXE_X_REG)).during(Duration.ofMinutes(Long.parseLong(PowerAuthLoadTestCommon.PERF_TEST_EXE_MIN))))
                        .protocols(PowerAuthLoadTestCommon.commonProtocol),
                CreateApproveOperationScenario.createApproveOperationScenario
                        .injectOpen(
                                rampUsers(Integer.getInteger(PowerAuthLoadTestCommon.PERF_TEST_EXE_Y_REG))
                                        .during(Duration.ofMinutes(Long.parseLong(PowerAuthLoadTestCommon.PERF_TEST_EXE_MIN))))
                        .protocols(PowerAuthLoadTestCommon.commonProtocol),
                ListOperationHistoryScenario.listOperationHistoryScenario
                        .injectOpen(rampUsers(Integer.getInteger(PowerAuthLoadTestCommon.PERF_TEST_EXE_Y_REG) / 10).during(Duration.ofMinutes(Long.parseLong(PowerAuthLoadTestCommon.PERF_TEST_EXE_MIN))))
                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
        );


    }
}
