/*
 * PowerAuth test and related software components
 * Copyright (C) 2019 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.v32;

import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthTokenShared;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.model.CreateTokenStepModel;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PowerAuth token tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthTokenTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V3_2;

    private PowerAuthTestConfiguration config;
    private PowerAuthClient powerAuthClient;
    private CreateTokenStepModel model;
    private ObjectStepLogger stepLogger;

    private static File dataFile;

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @BeforeAll
    static void setUpBeforeClass() throws IOException {
        dataFile = File.createTempFile("data", ".json");
        FileWriter fw = new FileWriter(dataFile);
        fw.write("All your base are belong to us!");
        fw.close();
    }

    @AfterAll
    static void tearDownAfterClass() {
        assertTrue(dataFile.delete());
    }

    @BeforeEach
    void setUp() {
        model = new CreateTokenStepModel();
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setResultStatusObject(config.getResultStatusObject(VERSION));
        model.setStatusFileName(config.getStatusFile(VERSION).getAbsolutePath());
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE);
        model.setVersion(VERSION);

        stepLogger = new ObjectStepLogger(System.out);
    }

    @Test
    void tokenCreateAndVerifyTest() throws Exception {
        PowerAuthTokenShared.tokenCreateAndVerifyTest(config, model, dataFile, VERSION);
    }

    @Test
    void tokenCreateInvalidPasswordTest() throws Exception {
        PowerAuthTokenShared.tokenCreateInvalidPasswordTest(config, model, stepLogger);
    }

    @Test
    void tokenVerifyInvalidTokenTest() throws Exception {
        PowerAuthTokenShared.tokenVerifyInvalidTokenTest(config, dataFile, VERSION);
    }

    @Test
    void tokenVerifyRemovedTokenTest() throws Exception {
        PowerAuthTokenShared.tokenVerifyRemovedTokenTest(powerAuthClient, config, model, dataFile, VERSION);
    }

    @Test
    void tokenCreateBlockedActivationTest() throws Exception {
        PowerAuthTokenShared.tokenCreateBlockedActivationTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void tokenUnsupportedApplicationTest() throws Exception {
        PowerAuthTokenShared.tokenUnsupportedApplicationTest(powerAuthClient, config, model);
    }

    @Test
    void tokenCounterIncrementTest() throws Exception {
        PowerAuthTokenShared.tokenCounterIncrementTest(model, stepLogger, VERSION);
    }

}
