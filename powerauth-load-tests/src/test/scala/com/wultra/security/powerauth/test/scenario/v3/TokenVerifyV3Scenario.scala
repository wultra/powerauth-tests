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

import com.wultra.security.powerauth.test.{ClientConfig, Device, PowerAuthCommon}
import io.gatling.core.Predef.{scenario, _}
import io.gatling.core.structure.ScenarioBuilder
import io.gatling.http.Predef.{http, _}
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader
import io.getlime.security.powerauth.lib.cmd.consts.{PowerAuthStep, PowerAuthVersion}
import io.getlime.security.powerauth.lib.cmd.steps.VerifyTokenStep
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext
import io.getlime.security.powerauth.lib.cmd.steps.model.{CreateTokenStepModel, VerifyTokenStepModel}
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse
import org.springframework.http.HttpMethod

import java.util
import java.util.Map

/**
 * Scenario to verify created token (v3)
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
object TokenVerifyV3Scenario extends AbstractScenario {

  val POWER_AUTH_TOKEN_VERIFY_URL: String = System.getProperty("powerAuthTokenVerifyUrl", "http://localhost:8080/powerauth-webflow/api/auth/token/app/operation/list")

  val tokenVerifyStep: VerifyTokenStep =
    PowerAuthCommon.stepProvider.getStep(PowerAuthStep.TOKEN_VALIDATE, PowerAuthVersion.V3_1).asInstanceOf[VerifyTokenStep]

  def prepareVerifyTokenStepModel(device: Device, session: Session): VerifyTokenStepModel = {
    val model = new VerifyTokenStepModel
    model.setResultStatus(device.resultStatusObject)
    model.setVersion(ClientConfig.modelVersion)
    model.setHttpMethod(HttpMethod.POST.name())
    model.setUriString(POWER_AUTH_TOKEN_VERIFY_URL)
    model.setTokenId(session(TokenCreateV3Scenario.SESSION_TOKEN_ID).as[String])
    model.setTokenSecret(session(TokenCreateV3Scenario.SESSION_TOKEN_SECRET).as[String])
    model
  }

  override def createStepContext(device: Device, session: Session): StepContext[_, _] = {
    val model = prepareVerifyTokenStepModel(device, session)
    tokenVerifyStep.prepareStepContext(PowerAuthCommon.stepLogger, model.toMap)
  }

  val scnTokenVerify: ScenarioBuilder = scenario("scnTokenVerify")
    .exec(prepareSessionData)
    .exec(http("PowerAuth - token verify")
      .post(POWER_AUTH_TOKEN_VERIFY_URL)
      .header(PowerAuthSignatureHttpHeader.HEADER_NAME, "${httpPowerAuthHeader}")
      .body(requestBody())
      .check(status.is(200))
      .check(bodyBytes.saveAs("responseBodyBytes"))
    )
    .exec(session => {
      val device: Device = session("device").as[Device]
      val stepContext = session("stepContext").as[StepContext[VerifyTokenStepModel, util.Map[String, AnyRef]]]

      device.resultStatusObject = stepContext.getModel.getResultStatus

      session
    })

}
