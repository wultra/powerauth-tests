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
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes
import com.wultra.security.powerauth.http.PowerAuthSignatureHttpHeader
import com.wultra.security.powerauth.lib.cmd.consts.{PowerAuthStep, PowerAuthVersion}
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext
import com.wultra.security.powerauth.lib.cmd.steps.model.CreateTokenStepModel
import com.wultra.security.powerauth.lib.cmd.steps.v3.CreateTokenStep
import com.wultra.security.powerauth.rest.api.model.entity.TokenResponsePayload
import com.wultra.security.powerauth.rest.api.model.response.EciesEncryptedResponse

/**
 * Scenario to check token creation (v3)
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
object TokenCreateV3Scenario extends AbstractScenario {

  val SESSION_TOKEN_ID: String = "tokenId"

  val SESSION_TOKEN_SECRET: String = "tokenSecret"

  val tokenCreateStep: CreateTokenStep =
    PowerAuthCommon.stepProvider.getStep(PowerAuthStep.TOKEN_CREATE, PowerAuthVersion.V3_1).asInstanceOf[CreateTokenStep]

  def prepareCreateTokenStepModel(device: Device): CreateTokenStepModel = {
    val model = new CreateTokenStepModel
    model.setApplicationKey(ClientConfig.applicationKey)
    model.setApplicationSecret(ClientConfig.applicationSecret)
    model.setPassword(device.password)
    model.setResultStatus(device.resultStatusObject)
    model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE)
    model.setVersion(ClientConfig.modelVersion)

    model
  }

  override def createStepContext(device: Device, session: Session): StepContext[_, _] = {
    val model = prepareCreateTokenStepModel(device)
    tokenCreateStep.prepareStepContext(PowerAuthCommon.stepLogger, model.toMap)
  }

  val scnTokenCreate: ScenarioBuilder = scenario("scnTokenCreate")
    .exec(prepareSessionData)
    .exec(http("PowerAuth - token create")
      .post("/pa/v3/token/create")
      .header(PowerAuthSignatureHttpHeader.HEADER_NAME, "${httpPowerAuthHeader}")
      .body(requestBody())
      .check(status.is(200))
      .check(bodyBytes.saveAs("responseBodyBytes"))
    )
    .exec(session => {
      val device: Device = session("device").as[Device]
      val stepContext = session("stepContext").as[StepContext[CreateTokenStepModel, EciesEncryptedResponse]]

      tokenCreateStep.processResponse(stepContext, session("responseBodyBytes").as[Array[Byte]], classOf[EciesEncryptedResponse])

      val tokenResponsePayload = stepContext.getResponseContext.getResponsePayloadDecrypted.asInstanceOf[TokenResponsePayload]
      val resultSession = session.set(SESSION_TOKEN_ID, tokenResponsePayload.getTokenId)
                                 .set(SESSION_TOKEN_SECRET, tokenResponsePayload.getTokenSecret)

      device.resultStatusObject = stepContext.getModel.getResultStatus

      resultSession
    })

}
