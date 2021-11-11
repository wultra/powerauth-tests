/*
 * Copyright 2021 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.wultra.security.powerauth.test

import com.wultra.security.powerauth.test.PowerAuthCommon.{httpProtocolPowerAuthJavaServer, httpProtocolPowerAuthRestServer}
import com.wultra.security.powerauth.test.scenario.ActivationInitScenario
import com.wultra.security.powerauth.test.scenario.v3.{ActivationPrepareV3Scenario, SignatureVerifyV3Scenario, TokenCreateV3Scenario, TokenVerifyV3Scenario}
import io.gatling.core.Predef._

import scala.concurrent.duration._

/**
 * PowerAuth load test
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
class PowerAuthLoadTest extends Simulation {

  println(s"Load testing PowerAuth")

  val activationCreateTime: FiniteDuration = Math.max((TestDevices.DEVICES_COUNT.floatValue() / 100).intValue(), 2).seconds

  val maxUsersPerSec: Int = Math.min(TestDevices.DEVICES_COUNT, TestDevices.DEVICES_MAX_CONCURRENT_PER_SECOND).intValue()

  setUp(
    // Init activation for all devices
    ActivationInitScenario.scnActivationInit.inject(
      rampUsers(TestDevices.DEVICES_COUNT).during(activationCreateTime./(2))
    ).protocols(httpProtocolPowerAuthJavaServer)
      // Create activation for all devices
      .andThen(
        ActivationPrepareV3Scenario.scnActivationCreate.inject(
          rampUsers(TestDevices.DEVICES_COUNT).during(activationCreateTime)
        ).protocols(httpProtocolPowerAuthRestServer)
          // Run in parallel scenarios for TokenCreate and SignatureVerify on all devices (sequenced)
          .andThen(
            TokenCreateV3Scenario.scnTokenCreate.exec(TokenVerifyV3Scenario.scnTokenVerify).inject(
              rampUsersPerSec(1).to(maxUsersPerSec).during(TestDevices.TEST_DURATION)
            ).protocols(httpProtocolPowerAuthRestServer),
            SignatureVerifyV3Scenario.scnSignatureVerify.inject(
              rampUsersPerSec(1).to(maxUsersPerSec).during(TestDevices.TEST_DURATION)
            ).protocols(httpProtocolPowerAuthRestServer)
          )
      )
  )

}
