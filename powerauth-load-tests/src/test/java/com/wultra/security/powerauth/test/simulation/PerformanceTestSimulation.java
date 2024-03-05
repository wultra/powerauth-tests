package com.wultra.security.powerauth.test.simulation;

import com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon;
import com.wultra.security.powerauth.test.scenario.ApproveOperationScenario;
import com.wultra.security.powerauth.test.scenario.CreateRegistrationScenario;
import com.wultra.security.powerauth.test.scenario.ListOperationHistoryScenario;
import io.gatling.javaapi.core.Simulation;

import java.time.Duration;

import static com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon.NUM_OF_EXECUTED_REGISTRATIONS_MINS;
import static com.wultra.security.powerauth.test.config.PowerAuthLoadTestCommon.NUM_OF_EXECUTED_REGISTRATIONS_TOTAL;
import static io.gatling.javaapi.core.CoreDsl.rampUsers;

public class PerformanceTestSimulation extends Simulation {
    public PerformanceTestSimulation() {
        PowerAuthLoadTestCommon.isPreparation = false;
        setUp(
                CreateRegistrationScenario.createRegistrationScenario
                        .feed(PowerAuthLoadTestCommon.powerauthJdbcFeeder("SELECT name as \"appId\" FROM pa_application ORDER BY Id DESC LIMIT 1;").circular())
                        .injectOpen(rampUsers(NUM_OF_EXECUTED_REGISTRATIONS_TOTAL).during(Duration.ofMinutes(NUM_OF_EXECUTED_REGISTRATIONS_MINS)))
                        .protocols(PowerAuthLoadTestCommon.commonProtocol),
                ApproveOperationScenario.approveOperationScenario
                        .feed(PowerAuthLoadTestCommon.powerauthJdbcFeeder(
                                """
                                        SELECT user_id as "testUserId"
                                        FROM pa_activation
                                        WHERE application_id = (
                                          SELECT id
                                          FROM pa_application
                                          ORDER BY Id DESC
                                          LIMIT 1
                                        );
                                        """
                        ).random())
                        .injectOpen(rampUsers(NUM_OF_EXECUTED_REGISTRATIONS_TOTAL).during(Duration.ofMinutes(NUM_OF_EXECUTED_REGISTRATIONS_MINS)))
                        .protocols(PowerAuthLoadTestCommon.commonProtocol),
                ListOperationHistoryScenario.listOperationHistoryScenario
                        .feed(PowerAuthLoadTestCommon.powerauthJdbcFeeder(
                                """
                                        SELECT user_id as "testUserId"
                                        FROM pa_activation
                                        WHERE application_id = (
                                          SELECT id
                                          FROM pa_application
                                          ORDER BY Id DESC
                                          LIMIT 1
                                        );
                                        """
                        ).random())
                        .injectOpen(rampUsers(NUM_OF_EXECUTED_REGISTRATIONS_TOTAL).during(Duration.ofMinutes(NUM_OF_EXECUTED_REGISTRATIONS_MINS)))
                        .protocols(PowerAuthLoadTestCommon.commonProtocol)
        );
    }
}
