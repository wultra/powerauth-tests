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
package com.wultra.security.powerauth.test.scenario.v3

import com.wultra.security.powerauth.test.{Device, TestDevices}
import io.gatling.core.Predef.{Session, _}
import io.gatling.core.body.Body
import io.gatling.core.session
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext
import io.getlime.security.powerauth.lib.cmd.util.HttpUtil

/**
 * Abstract scenario with common expressions
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
abstract class AbstractScenario {

  /**
   * Creates the step context with a prepared request for a device
   * @param device Device
   * @return Step context with a prepared request
   */
  def createStepContext(device: Device): StepContext[_,_]

  /**
   * Prepares session data
   * @return Session with prepared data
   */
  def prepareSessionData: session.Expression[Session] = {
    session: Session => {
      val device = TestDevices.nextDevice(TestDevices.devicesInitialized, TestDevices.indexInitialized)
      val stepContext = createStepContext(device)
      session
        .set("device", device)
        .set("httpPowerAuthHeader", stepContext.getRequestContext.getAuthorizationHeader)
        .set("requestObject", stepContext.getRequestContext.getRequestObject)
        .set("stepContext", stepContext)
    }
  }

  def requestBody() : Body = {
    ByteArrayBody(session => {
      val objectRequest = session("requestObject").as[Object]
      HttpUtil.toRequestBytes(objectRequest)
    })
  }

}
