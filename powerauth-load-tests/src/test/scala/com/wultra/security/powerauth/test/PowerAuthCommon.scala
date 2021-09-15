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

import io.gatling.core.Predef.{Simulation, _}
import io.gatling.http.Predef.http
import io.gatling.http.protocol.HttpProtocolBuilder
import io.getlime.security.powerauth.lib.cmd.CmdLibApplication
import io.getlime.security.powerauth.lib.cmd.logging.StepLogger
import io.getlime.security.powerauth.lib.cmd.steps.StepProvider
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.boot.WebApplicationType
import org.springframework.boot.builder.SpringApplicationBuilder
import org.springframework.context.ConfigurableApplicationContext

import java.security.Security

/**
 * Class with common parts useful for any simulation:
 * <ul>
 *   <li>Configuration of HTTP clients to PowerAuth servers</li>
 *   <li>Spring Boot application initialization</li>
 *   <li>Providing common beans</li>
 * </ul>
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
object PowerAuthCommon {

  // Add Bouncy Castle Security Provider
  Security.addProvider(new BouncyCastleProvider)

  val POWER_AUTH_SERVER_URL: String = System.getProperty("powerAuthServerUrl", "http://localhost:8080")

  val httpProtocolPowerAuthServer: HttpProtocolBuilder = http
    .baseUrl(POWER_AUTH_SERVER_URL)
    .inferHtmlResources()
    .acceptHeader("application/json")
    .contentTypeHeader("application/json")
    .userAgentHeader("PowerAuth-LoadTest/gatling com.wultra.powerauth/1.2.0-SNAPSHOT")

  val POWER_AUTH_REST_SERVER_URL: String = System.getProperty("powerAuthRestServerUrl", "http://localhost:8081")

  val httpProtocolPowerAuthRestServer: HttpProtocolBuilder = http
    .baseUrl(POWER_AUTH_REST_SERVER_URL)
    .inferHtmlResources()
    .acceptHeader("application/json")
    .contentTypeHeader("application/json")
    .userAgentHeader("PowerAuth-LoadTest/gatling com.wultra.powerauth/1.2.0-SNAPSHOT")

  val appContext: ConfigurableApplicationContext = new SpringApplicationBuilder(classOf[CmdLibApplication])
    .web(WebApplicationType.NONE)
    .run("--resultstatus.persistenceType=memory", "--steplogger.type=json")

  val stepLogger: StepLogger = appContext.getBeanFactory.getBean(classOf[StepLogger])

  val stepProvider: StepProvider = appContext.getBeanFactory.getBean(classOf[StepProvider])

}
