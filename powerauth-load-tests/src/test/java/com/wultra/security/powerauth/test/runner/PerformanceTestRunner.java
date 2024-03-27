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
package com.wultra.security.powerauth.test.runner;

import com.wultra.security.powerauth.test.simulation.PerformanceTestSimulation;
import io.gatling.app.Gatling;
import io.gatling.core.config.GatlingPropertiesBuilder;

/**
 * Executes the PerformanceTestSimulation for conducting performance tests on PowerAuth applications, useful for debugging.
 * Utilizes Gatling to run specified simulation, focusing on evaluating the performance under various load conditions.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
public class PerformanceTestRunner {
    public static void main(String[] args) {
        GatlingPropertiesBuilder props = new GatlingPropertiesBuilder()
                .simulationClass(PerformanceTestSimulation.class.getName());
        Gatling.fromMap(props.build());
    }
}
