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

import com.wultra.security.powerauth.test.{ClientConfig, Device, PowerAuthCommon, TestDevices}
import io.gatling.core.Predef.{ByteArrayBody, jsonPath, scenario, _}
import io.gatling.core.structure.ScenarioBuilder
import io.gatling.http.Predef.{http, _}
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader
import io.getlime.security.powerauth.lib.cmd.consts.{PowerAuthStep, PowerAuthVersion}
import io.getlime.security.powerauth.lib.cmd.steps.context.{ResponseContext, StepContext}
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateTokenStepModel
import io.getlime.security.powerauth.lib.cmd.steps.v3.CreateTokenStep
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse

/**
 * Scenario to check token creation (v3)
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
object TokenCreateV3Scenario {

  val tokenCreateStep: CreateTokenStep =
    PowerAuthCommon.stepProvider.getStep(PowerAuthStep.TOKEN_CREATE, PowerAuthVersion.V3_1).asInstanceOf[CreateTokenStep]

  def prepareCreateTokenStepModel(device: Device): CreateTokenStepModel = {
    val model = new CreateTokenStepModel
    model.setApplicationKey(ClientConfig.applicationKey)
    model.setApplicationSecret(ClientConfig.applicationSecret)
    model.setPassword(device.password)
    model.setResultStatusObject(device.resultStatusObject)
    model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE)
    model.setVersion(ClientConfig.modelVersion)

    model
  }

  val scnTokenCreate: ScenarioBuilder = scenario("scnTokenCreate")
    .exec(session => {
      val device = TestDevices.nextDevice(TestDevices.devicesActivated, TestDevices.indexDevice)
      val model = prepareCreateTokenStepModel(device)
      val stepContext = tokenCreateStep.prepareStepContext(model.toMap)
      session
        .set("device", device)
        .set("powerAuthHeader", stepContext.getRequestContext.getAuthorizationHeader)
        .set("request", stepContext.getRequestContext.getRequestObject)
        .set("stepContext", stepContext)
    })
    .exec(http("PowerAuth - token create")
      .post("/pa/v3/token/create")
      .header(PowerAuthSignatureHttpHeader.HEADER_NAME, "${powerAuthHeader}")
      .body(ByteArrayBody(session => {
        RestClientConfiguration.defaultMapper.writeValueAsBytes(session("request").as[EciesEncryptedRequest])
      }))
      .check(jsonPath("$.encryptedData").saveAs("encryptedData"))
      .check(jsonPath("$.mac").saveAs("mac"))
    )
    .exec(session => {
      val device: Device = session("device").as[Device]
      val response = new EciesEncryptedResponse(session("encryptedData").as[String], session("mac").as[String])
      val stepContext = session("stepContext").as[StepContext[CreateTokenStepModel, EciesEncryptedResponse]]
      stepContext.setResponseContext(
        ResponseContext.builder[EciesEncryptedResponse]()
          .responseBodyObject(response)
          .build()
      )
      tokenCreateStep.processResponse(stepContext)
      device.resultStatusObject = stepContext.getModel.getResultStatus

      session
    })

}
