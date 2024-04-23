/*
 * PowerAuth test and related software components
 * Copyright (C) 2024 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.wultra.security.powerauth.test.shared;

import com.wultra.security.powerauth.test.model.UserRegistrationInfo;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages shared session data for Gatling performance testing scenarios within PowerAuth systems.
 * Utilizes thread-safe collections to facilitate the consistent transfer and access of critical
 * test data across various testing scenarios and simulation steps.
 *
 * <p>This class contains two main storage structures:</p>
 *
 * <ul>
 *   <li><b>transferVariable:</b> A {@link ConcurrentHashMap} designed to safely store and transfer
 *   session-related variables, such as user IDs and activation codes, between different parts of
 *   the simulation. This ensures data consistency and thread safety throughout the test execution.</li>
 *
 *   <li><b>registrationData:</b> A synchronized {@link List} of {@link UserRegistrationInfo} objects
 *   which accumulates detailed registration data gathered during the simulations. This list allows
 *   for the collection and later analysis of user registration flows, including the capture of user,
 *   application, and authentication details.</li>
 * </ul>
 *
 * <p>By providing centralized access to shared data, {@code SharedSessionData} plays a crucial role
 * in orchestrating complex simulation scenarios, enabling the reuse of test data and ensuring the
 * integrity of performance testing workflows.</p>
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
public class SharedSessionData {
    public static ConcurrentHashMap<String, Object> transferVariable = new ConcurrentHashMap<>();
    public static List<UserRegistrationInfo> registrationData = Collections.synchronizedList(new ArrayList<>());
}

