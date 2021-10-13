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
import io.gatling.core.Predef.{scenario, _}
import io.gatling.core.structure.ScenarioBuilder
import io.gatling.http.Predef.{http, _}
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader
import io.getlime.security.powerauth.lib.cmd.consts.{PowerAuthStep, PowerAuthVersion}
import io.getlime.security.powerauth.lib.cmd.steps.context.StepContext
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse

import java.util.Collections

/**
 * Scenario to check activation of devices (v3)
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
object ActivationPrepareV3Scenario extends AbstractScenario {

  val activationPrepareStep: PrepareActivationStep =
    PowerAuthCommon.stepProvider.getStep(PowerAuthStep.ACTIVATION_CREATE, PowerAuthVersion.V3_1).asInstanceOf[PrepareActivationStep]

  def createActivationPrepareStepModel(device: Device): PrepareActivationStepModel = {
    val model: PrepareActivationStepModel = new PrepareActivationStepModel()
    model.setActivationCode(device.activationCode)
    model.setActivationName(ClientConfig.activationName)
    model.setApplicationKey(ClientConfig.applicationKey)
    model.setApplicationSecret(ClientConfig.applicationSecret)
    model.setDeviceInfo(s"Device Info ${device.userId}")
    model.setHeaders(Collections.emptyMap())
    model.setMasterPublicKey(ClientConfig.masterPublicKey)
    model.setPassword(device.password)
    model.setPlatform("devicePlatform")
    model.setResultStatus(device.resultStatusObject)
    model.setVersion(ClientConfig.modelVersion)

    model
  }

  override def createStepContext(device: Device): StepContext[_, _] = {
    val model = createActivationPrepareStepModel(device)
    activationPrepareStep.prepareStepContext(PowerAuthCommon.stepLogger, model.toMap)
  }

  val scnActivationCreate: ScenarioBuilder = scenario("scnActivationCreate")
    .exec(prepareSessionData)
    .exec(http("PowerAuth - activation create")
      .post("/pa/v3/activation/create")
      .header(PowerAuthEncryptionHttpHeader.HEADER_NAME, "${httpPowerAuthHeader}")
      .body(requestBody())
      .check(status.is(200))
      .check(bodyBytes.saveAs("responseBodyBytes"))
    )
    .exec(session => {
      val device: Device = session("device").as[Device]
      val stepContext = session("stepContext").as[StepContext[PrepareActivationStepModel, EciesEncryptedResponse]]

      activationPrepareStep.processResponse(stepContext, session("responseBodyBytes").as[Array[Byte]], classOf[EciesEncryptedResponse])

      val deviceActivated: Device = device.copy()
      deviceActivated.resultStatusObject = stepContext.getModel.getResultStatus

      synchronized {
        TestDevices.devicesActivated += deviceActivated
      }
      session
    })

}
