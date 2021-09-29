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

import java.util.concurrent.atomic.AtomicInteger
import scala.collection.mutable.ListBuffer

/**
 * Simulated devices to run the tests on
 *
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
object TestDevices {

  val MAX_USERS_PER_SECOND: Integer = Integer.getInteger("maxUsersPerSecond", 80)

  val NUMBER_OF_DEVICES: Integer = Integer.getInteger("numberOfDevices", 100)

  val devicesActivated: ListBuffer[Device] = ListBuffer.empty[Device]

  val devicesInitialized: ListBuffer[Device] = ListBuffer.empty[Device]

  val indexDevice: AtomicInteger = new AtomicInteger(0)

  val indexInitialized: AtomicInteger = new AtomicInteger(0)

  def nextDevice(devices: ListBuffer[Device], indexCounter: AtomicInteger): Device = {
    var index = indexCounter.incrementAndGet()
    if (index >= devices.size) {
      indexCounter.set(0)
      index = 0
    }
    devices(index)
  }

}
