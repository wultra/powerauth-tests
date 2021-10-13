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

import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion
import io.getlime.security.powerauth.lib.cmd.logging.{ObjectStepLogger, StepLogger}
import io.getlime.security.powerauth.lib.cmd.util.ConfigurationUtil
import org.json.simple.{JSONObject, JSONValue}

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import java.security.interfaces.ECPublicKey

/**
 * PowerAuth client configuration
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
object ClientConfig {

  val stepLogger: StepLogger = new ObjectStepLogger(System.out)

  val clientConfigObject: JSONObject = {
    try {
      val configFileBytes: Array[Byte] = Files.readAllBytes(Paths.get(System.getProperty("configFile", "./config.json")))
      JSONValue.parse(new String(configFileBytes, StandardCharsets.UTF_8)).asInstanceOf[JSONObject]
    } catch {
      case e: Throwable =>
        stepLogger.writeItem("generic-error-config-file-invalid", "Invalid config file", "Does the file exist and is it in a correct JSON format?", "ERROR", e)
        throw e
    }
  }

  val activationName: String = ConfigurationUtil.getApplicationName(clientConfigObject)

  val applicationId: Long = clientConfigObject.get("applicationId").asInstanceOf[Long]

  val applicationKey: String = ConfigurationUtil.getApplicationKey(clientConfigObject)

  val applicationSecret: String = ConfigurationUtil.getApplicationSecret(clientConfigObject)

  val masterPublicKey: ECPublicKey = ConfigurationUtil.getMasterKey(clientConfigObject, stepLogger).asInstanceOf[ECPublicKey]

  val modelVersion: PowerAuthVersion = PowerAuthVersion.V3_1

}
