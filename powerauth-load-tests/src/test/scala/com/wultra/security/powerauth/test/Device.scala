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

import io.getlime.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject

/**
 * Representation of a test device
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
class Device {

  var activationCode: String = _
  var activationId: String = _
  var activationSignature: String = _
  var password: String = _
  var resultStatusObject: ResultStatusObject = _
  var userId: String = _

  def copy(): Device = {
    val device = new Device()
    device.activationCode = this.activationCode
    device.activationId = this.activationId
    device.activationSignature = this.activationSignature
    device.password = this.password
    device.resultStatusObject = this.resultStatusObject
    device.userId = this.userId

    device
  }

}
