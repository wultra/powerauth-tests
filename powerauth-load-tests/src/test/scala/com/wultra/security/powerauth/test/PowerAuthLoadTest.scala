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

import com.wultra.security.powerauth.test.PowerAuthCommon.{httpProtocolPowerAuthRestServer, httpProtocolPowerAuthServer}
import com.wultra.security.powerauth.test.scenario.ActivationInitScenario
import com.wultra.security.powerauth.test.scenario.v3.{ActivationPrepareV3Scenario, SignatureVerifyV3Scenario, TokenCreateV3Scenario}
import io.gatling.core.Predef._

import scala.concurrent.duration._

/**
 * PowerAuth load test
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
class PowerAuthLoadTest extends Simulation {

  println(s"Load testing PowerAuth")

  setUp(
    ActivationInitScenario.scnActivationInit.inject(
      rampUsers(TestDevices.NUMBER_OF_DEVICES).during(Math.max((TestDevices.NUMBER_OF_DEVICES.floatValue() / 200).intValue(), 1).seconds)
    ).protocols(httpProtocolPowerAuthServer).andThen(
      ActivationPrepareV3Scenario.scnActivationCreate.inject(
        rampUsers(TestDevices.NUMBER_OF_DEVICES).during(Math.max((TestDevices.NUMBER_OF_DEVICES.floatValue() / 100).intValue() , 1).seconds)
      ).protocols(httpProtocolPowerAuthRestServer)
        .andThen(
          TokenCreateV3Scenario.scnTokenCreate.inject(
            rampUsersPerSec(1).to(80).during(15.minutes)
          ).protocols(httpProtocolPowerAuthRestServer),
          SignatureVerifyV3Scenario.scnSignatureVerify.inject(
            rampUsersPerSec(1).to(80).during(15.minutes)
          ).protocols(httpProtocolPowerAuthRestServer)
        )
    )
  )

}
