/*
 * PowerAuth test and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.v30;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthTokenShared;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateTokenStepModel;
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

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthTokenTest {

    private static final String VERSION = "3.0";

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
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setPassword(config.getPassword());
        model.setResultStatusObject(config.getResultStatusObjectV3());
        model.setStatusFileName(config.getStatusFileV3().getAbsolutePath());
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
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
        PowerAuthTokenShared.tokenCounterIncrementTest(model, stepLogger);
    }

}
