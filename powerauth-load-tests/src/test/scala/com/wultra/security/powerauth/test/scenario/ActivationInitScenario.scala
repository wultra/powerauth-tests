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
package com.wultra.security.powerauth.test.scenario

import com.wultra.security.powerauth.test.{ClientConfig, Device, TestDevices}
import io.gatling.core.Predef.{StringBody, jsonPath, scenario, _}
import io.gatling.core.structure.ScenarioBuilder
import io.gatling.http.Predef.{http, _}
import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject

/**
 * Scenario to initialize devices for registrations
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
object ActivationInitScenario {

  val devicesToInit: Array[Device] = (1 to TestDevices.DEVICES_COUNT).toList
    .map(index => {
      val device = new Device()
      device.userId = s"loadTestUser_$index"
      device
    }).toArray

  val scnActivationInit: ScenarioBuilder = scenario("scnActivationInit")
    .feed(devicesToInit.map(device => Map("device" -> device, "userId" -> device.userId)).circular)
    .exec(http("PowerAuth - activation init")
      .post("/rest/v3/activation/init")
      .body(StringBody(session => {
        s"""{
			    "requestObject": {
					  "activationOtpValidation": "NONE",
						"applicationId": "${ClientConfig.applicationId}",
						"userId": "${session("userId").as[String]}"
					}
				}"""
      }
      ))
      .check(status.is(200))
      .check(jsonPath("$.status").is("OK"))
      .check(jsonPath("$.responseObject.activationCode").saveAs("activationCode"))
      .check(jsonPath("$.responseObject.activationId").saveAs("activationId"))
      .check(jsonPath("$.responseObject.activationSignature").saveAs("activationSignature"))
    )
    .exec(session => {
      val deviceToInit = session("device").as[Device]

      val device: Device = deviceToInit.copy()
      device.activationCode = session("activationCode").as[String]
      device.activationId = session("activationId").as[String]
      device.activationSignature = session("activationSignature").as[String]
      device.password = s"Password_${deviceToInit.userId}"
      device.resultStatusObject = new ResultStatusObject()

      synchronized {
        TestDevices.devicesInitialized += device
      }
      session
    })

}
