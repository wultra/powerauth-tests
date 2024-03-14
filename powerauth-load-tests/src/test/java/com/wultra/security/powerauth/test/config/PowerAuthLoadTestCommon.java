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
package com.wultra.security.powerauth.test.config;

import io.gatling.javaapi.core.FeederBuilder;
import io.gatling.javaapi.http.HttpProtocolBuilder;
import lombok.extern.slf4j.Slf4j;

import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.jdbc.JdbcDsl.jdbcFeeder;

/**
 * Provides common configurations and utilities for performing load testing on PowerAuth applications.
 * This class contains configurations for maximum concurrent users, preparation and execution phase settings,
 * and credentials for PowerAuth administration. It also provides methods to fetch environment variable values
 * and to create JDBC feeders for Gatling tests.
 * <p>
 * All configuration values can be customized via environment variables. Defaults are provided for ease of use
 * and quick setup.
 * </p>
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
@Slf4j
public class PowerAuthLoadTestCommon {

    /* Empirical value from testing */
    public static final int MAX_CONCURRENT_USERS = 10;

    /* Total number of registrations to prepare during preparation phase */
    public static final int PERF_TEST_PREP_N_REG = getIntEnv("PERF_TEST_PREP_N_REG", 10);

    /* Total number of operations per registration to prepare during preparation phase */
    public static final int PERF_TEST_PREP_M_OP = getIntEnv("PERF_TEST_PREP_M_OP", 10);

    /* Number of registrations to add during execution phase per sec */
    public static final int PERF_TEST_EXE_X_REG = getIntEnv("PERF_TEST_EXE_X_REG", 1);

    /* Number of operations to add during execution phase per sec */
    public static final int PERF_TEST_EXE_Y_OP = getIntEnv("PERF_TEST_EXE_Y_OP", 10);

    /* The length of the execution phase in minutes */
    public static final int PERF_TEST_EXE_MIN = getIntEnv("PERF_TEST_EXE_MIN", 5);

    public static final String PAC_ADMIN_USER = getStringEnv("PAC_ADMIN_USER", "system-admin");
    public static final String PAC_ADMIN_PASS = getStringEnv("PAC_ADMIN_PASS", "");
    public static final String PAC_URL = getStringEnv("PAC_URL", "http://localhost:8089/powerauth-cloud");
    public static final String TEST_SERVER_URL = getStringEnv("TEST_SERVER_URL", "http://localhost:8081");
    public static final String DB_HOST = getStringEnv("DB_HOST", "localhost:5432/powerauth");

    /**
     * Common HTTP protocol configuration for Gatling tests.
     */
    public final static HttpProtocolBuilder commonProtocol = http
            .contentTypeHeader("application/json")
            .acceptHeader("application/json")
            .userAgentHeader("PowerAuth-LoadTest/gatling").check();

    /**
     * Creates a JDBC feeder for Gatling tests using a provided SQL query.
     *
     * @param query The SQL query to execute.
     * @return A feeder builder for Gatling tests.
     */
    public static FeederBuilder<Object> powerauthJdbcFeeder(final String query) {
        return jdbcFeeder("jdbc:postgresql://" + DB_HOST, "powerauth", "", query);
    }

    /**
     * Fetches an integer environment variable by name, or returns the default value if not found or invalid.
     *
     * @param name         The name of the environment variable.
     * @param defaultValue The default value to use if the environment variable is not found or invalid.
     * @return The environment variable value as an integer, or the default value.
     */
    private static int getIntEnv(final String name, final int defaultValue) {
        final String value = System.getenv(name);
        if (value != null && !value.isEmpty()) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                logger.warn("Environment variable {} is not a valid integer: {}. Using default value.", name, defaultValue);
            }
        }
        return defaultValue;
    }

    /**
     * Fetches a string environment variable by name, or returns the default value if not found.
     *
     * @param name         The name of the environment variable.
     * @param defaultValue The default value to use if the environment variable is not found.
     * @return The environment variable value as a string, or the default value.
     */
    private static String getStringEnv(final String name, final String defaultValue) {
        final String value = System.getenv(name);
        if (value != null && !value.isEmpty()) {
            return value;
        } else {
            logger.warn("Environment variable {} is not set correctly: {}. Using default value.", name, defaultValue);
            return defaultValue;
        }
    }

}
