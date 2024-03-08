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
package com.wultra.security.powerauth.test.scenario;

import com.wultra.security.powerauth.test.shared.SharedSessionData;
import io.gatling.javaapi.core.ChainBuilder;

import static io.gatling.javaapi.core.CoreDsl.exec;

import scala.collection.JavaConverters;

import java.util.Map;

/**
 * Provides shared session management functionalities for Gatling simulations in PowerAuth Gatling testing.
 * Facilitates the transfer and reuse of session data between different simulation scenarios.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
abstract class SharedSessionScenario {

    /**
     * Prepares the Gatling session with pre-stored data from {@link SharedSessionData}.
     * This method iterates over a static map and sets each key-value pair into the Gatling session.
     * Useful for initializing session variables at the beginning of a simulation scenario.
     *
     * @return A Gatling {@link ChainBuilder} with session variables set for further execution.
     */
    public static ChainBuilder prepareSessionData() {
        return exec(session -> {
            for (final Map.Entry<String, Object> entry : SharedSessionData.transferVariable.entrySet()) {
                session = session.set(entry.getKey(), entry.getValue());
            }
            return session;
        });
    }

    /**
     * Saves session data back to a static map in {@link SharedSessionData} at the end of a simulation scenario.
     * This allows for the persistence of certain session variables across different Gatling simulation scenarios.
     * Only non-null values and keys not containing "gatling" are saved to avoid overwriting internal Gatling data.
     *
     * @return A Gatling {@link ChainBuilder} that saves session variables for future use.
     */
    public static ChainBuilder saveSessionData() {
        return exec(session -> {
            JavaConverters.mapAsJavaMapConverter(session.asScala().attributes()).asJava()
                    .forEach((key, value) -> {
                        if (value != null && !key.contains("gatling")) {
                            SharedSessionData.transferVariable.put(key, value);
                        }
                    });
            return session;
        });
    }
}