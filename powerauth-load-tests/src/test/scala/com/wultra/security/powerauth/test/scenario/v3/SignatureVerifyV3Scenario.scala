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
import io.gatling.core.Predef.{jsonPath, scenario, _}
import io.gatling.core.structure.ScenarioBuilder
import io.gatling.http.Predef.{http, _}
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes
import com.wultra.security.powerauth.http.PowerAuthSignatureHttpHeader
import com.wultra.security.powerauth.lib.cmd.consts.{PowerAuthStep, PowerAuthVersion}
import com.wultra.security.powerauth.lib.cmd.steps.VerifyAuthenticationStep
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyAuthenticationStepModel

import java.nio.charset.StandardCharsets
import java.util.Collections

/**
 * Scenario to check signature verification (v3)
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
object SignatureVerifyV3Scenario extends AbstractScenario {

  val signatureVerifyStep: VerifyAuthenticationStep =
    PowerAuthCommon.stepProvider.getStep(PowerAuthStep.SIGNATURE_VERIFY, PowerAuthVersion.V3_1).asInstanceOf[VerifyAuthenticationStep]

  def prepareVerifyAuthenticationStepModel(device: Device): VerifyAuthenticationStepModel = {
    val model = new VerifyAuthenticationStepModel
    model.setApplicationKey(ClientConfig.applicationKey)
    model.setApplicationSecret(ClientConfig.applicationSecret)
    model.setHeaders(Collections.emptyMap())
    model.setHttpMethod("POST")
    model.setPassword(device.password)
    model.setResourceId("/pa/signature/validate")
    model.setResultStatus(device.resultStatusObject)
    model.setAuthenticationCodeType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE)
    model.setUriString(s"${PowerAuthCommon.POWER_AUTH_REST_SERVER_URL}/pa/v3/signature/validate")
    model.setVersion(ClientConfig.modelVersion)
    model.setDryRun(false)

    val dataFileBytes = "TEST_DATA".getBytes(StandardCharsets.UTF_8)
    model.setData(dataFileBytes)

    model
  }

  override def createStepContext(device: Device, session: Session): StepContext[_, _] = {
    val model = prepareVerifyAuthenticationStepModel(device)
    signatureVerifyStep.prepareStepContext(PowerAuthCommon.stepLogger, model.toMap)
  }

  val scnSignatureVerify: ScenarioBuilder = scenario("scnSignatureVerify")
    .exec(prepareSessionData)
    .exec(http("PowerAuth - signature verify")
      .post("/pa/v3/signature/validate")
      .header(PowerAuthSignatureHttpHeader.HEADER_NAME, "${httpPowerAuthHeader}")
      .body(requestBody())
      .check(status.is(200))
      .check(jsonPath("$.status").is("OK"))
    )

}
