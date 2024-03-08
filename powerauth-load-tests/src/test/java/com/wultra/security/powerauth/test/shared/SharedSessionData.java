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

import java.util.concurrent.ConcurrentHashMap;

/**
 * Provides a shared storage mechanism for preserving session data across different simulation scenarios
 * in PowerAuth load testing. This class leverages a thread-safe {@link ConcurrentHashMap} to store and
 * retrieve variables that need to be consistent and accessible throughout the execution of various Gatling simulations.
 * <p>
 * The static {@code transferVariable} map is used to hold any necessary data (e.g., user IDs, activation codes)
 * that must be passed between scenarios.
 * <p>
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
public class SharedSessionData {
    public static ConcurrentHashMap<String, Object> transferVariable = new ConcurrentHashMap<>();
}

