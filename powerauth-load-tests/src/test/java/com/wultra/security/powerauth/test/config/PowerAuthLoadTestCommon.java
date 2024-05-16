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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.test.shared.SharedSessionData;
import io.gatling.javaapi.core.FeederBuilder;
import io.gatling.javaapi.http.HttpProtocolBuilder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static io.gatling.javaapi.core.CoreDsl.*;
import static io.gatling.javaapi.http.HttpDsl.http;
import static java.util.UUID.randomUUID;

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

    @Setter
    @Getter
    private static boolean isPreparationPhase = false;

    private static FeederBuilder<Object> userDataFeedList;

    private static FeederBuilder.FileBased<Object> userDataFeedJson;

    private static final String DATA_DUMP_FILE = "registrationDataFeed.json";

    /* Empirical value from testing */
    public static final int MAX_CONCURRENT_USERS = 20;

    /* Total number of registrations to prepare during preparation phase */
    public static final int PERF_TEST_PREP_N_REG = getIntEnv("PERF_TEST_PREP_N_REG", 100);

    /* Total number of operations per registration to prepare during preparation phase */
    public static final int PERF_TEST_PREP_M_OP = getIntEnv("PERF_TEST_PREP_M_OP", 1000);

    /* Number of registrations to add during execution phase per sec */
    public static final int PERF_TEST_EXE_X_REG = getIntEnv("PERF_TEST_EXE_X_REG", 1);

    /* Number of operations to add during execution phase per sec */
    public static final int PERF_TEST_EXE_Y_OP = getIntEnv("PERF_TEST_EXE_Y_OP", 50);

    /* The length of the execution phase in minutes */
    public static final int PERF_TEST_EXE_MIN = getIntEnv("PERF_TEST_EXE_MIN", 1);

    /* Percentage of registered users that each second request the pending operation list. It is dependent on number of created registrations during prep phase */
    public static final double PERF_TEST_EXE_PENDING_OP_POOLING = getDoubleEnv("PERF_TEST_EXE_PENDING_OP_POOLING", 0.1);

    public static final String PAC_ADMIN_USER = getStringEnv("PAC_ADMIN_USER", "system-admin");
    public static final String PAC_ADMIN_PASS = getStringEnv("PAC_ADMIN_PASS", "");
    public static final String PAC_URL = getStringEnv("PAC_URL", "http://localhost:8089/powerauth-cloud");
    public static final String TEST_SERVER_URL = getStringEnv("TEST_SERVER_URL", "http://localhost:8081");
    public static final String CALLBACK_URL = getStringEnv("PERF_TEST_CALLBACK_URL", "http://localhost:8090/mock-callback");

    /**
     * Common HTTP protocol configuration for Gatling tests.
     */
    public final static HttpProtocolBuilder commonProtocol = http
            .contentTypeHeader("application/json")
            .acceptHeader("application/json")
            .userAgentHeader("PowerAuth-LoadTest/gatling").check();

    /**
     * Fetches an integer environment variable by name, or returns the default value if not found or invalid.
     *
     * @param name         The name of the environment variable.
     * @param defaultValue The default value to use if the environment variable is not found or invalid.
     * @return The environment variable value as an integer, or the default value.
     */
    private static int getIntEnv(final String name, final int defaultValue) {
        final String value = System.getenv(name);
        if (StringUtils.isNotBlank(value)) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                logger.warn("Environment variable {} is not a valid integer: {}. Using default value.", name, defaultValue);
            }
        }
        return defaultValue;
    }

    /**
     * Fetches a double environment variable by name, or returns the default value if not found or invalid.
     *
     * @param name         The name of the environment variable.
     * @param defaultValue The default value to use if the environment variable is not found or invalid.
     * @return The environment variable value as a double, or the default value.
     */
    private static double getDoubleEnv(final String name, final double defaultValue) {
        final String value = System.getenv(name);
        if (StringUtils.isNotBlank(value)) {
            try {
                return Double.parseDouble(value);
            } catch (NumberFormatException e) {
                logger.warn("Environment variable {} is not a valid double: {}. Using default value.", name, defaultValue);
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
        if (StringUtils.isNotBlank(value)) {
            return value;
        } else {
            logger.warn("Environment variable {} is not set correctly: {}. Using default value.", name, defaultValue);
            return defaultValue;
        }
    }

    /**
     * Generates a unique user ID using a UUID for testing purposes.
     *
     * @return A string representing a unique test user ID.
     */
    private static String generateUserId() {
        return "TEST_USER_ID" + randomUUID();
    }

    /**
     * Prepares user data feed for simulations. If in preparation phase, generates a list of users with unique IDs.
     * Otherwise, loads user data from a JSON file. This method ensures that user data is available for testing,
     * regardless of the phase of the test.
     */
    public static void prepareFeedDataUsers() {
        if (isPreparationPhase()) {
            final List<Map<String, Object>> userList = Stream.generate(() -> {
                        final Map<String, Object> stringObjectMap = new HashMap<>();
                        stringObjectMap.put("testUserId", generateUserId());
                        return stringObjectMap;
                    })
                    .limit(PERF_TEST_PREP_N_REG)
                    .toList();

            userDataFeedList = listFeeder(userList);
        } else {
            userDataFeedJson = jsonFile(DATA_DUMP_FILE);
        }
    }

    /**
     * Returns the appropriate user data feeder for simulations based on the current phase.
     * If in preparation phase, returns a feeder with generated user data. Otherwise, returns a feeder
     * with user data loaded from a JSON file.
     *
     * @return A {@link FeederBuilder} object containing user data for the simulation.
     */
    public static FeederBuilder<Object> getUserDataFeed() {
        if (isPreparationPhase()) {
            return userDataFeedList;
        } else {
            return userDataFeedJson;
        }
    }

    /**
     * Saves generated user registration data into a JSON file for later use. This method is called
     * after data preparation phase to persist the generated data, making it available for subsequent
     * execution phases or future test runs.
     */
    public static void saveGeneratedData() {
        final ObjectMapper objectMapper = new ObjectMapper();
        try {
            objectMapper.writeValue(new File("src/test/resources/" + DATA_DUMP_FILE), SharedSessionData.registrationData);
        } catch (IOException e) {
            logger.warn("Unable to save generated user data, due to : {}", e.getMessage());
        }
    }
}
