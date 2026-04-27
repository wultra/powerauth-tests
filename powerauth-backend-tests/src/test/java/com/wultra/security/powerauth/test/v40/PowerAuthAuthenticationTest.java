/*
 * PowerAuth test and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.v40;

import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyAuthenticationStepModel;
import com.wultra.security.powerauth.test.shared.v4.PowerAuthAuthenticationShared;
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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PowerAuth signature tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthAuthenticationTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V4_0;

    private PowerAuthTestConfiguration config;
    private static File dataFile;
    private VerifyAuthenticationStepModel model;
    private ObjectStepLogger stepLogger;

    private PowerAuthClient powerAuthClient;

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
        dataFile = File.createTempFile("data", ".txt");
        FileWriter fw = new FileWriter(dataFile);
        fw.write("Confidential test message used for testing");
        fw.close();
    }

    @AfterAll
    static void tearDownAfterClass() {
        assertTrue(dataFile.delete());
    }

    @BeforeEach
    void setUp() throws IOException {
        model = new VerifyAuthenticationStepModel();
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));
        model.setHeaders(new HashMap<>());
        model.setHttpMethod("POST");
        model.setPassword(config.getPassword());
        model.setResourceId("/pa/auth/validate");
        model.setResultStatusObject(config.getResultStatusObject(VERSION));
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE);
        model.setStatusFileName(config.getStatusFile(VERSION).getAbsolutePath());
        model.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v4/auth/validate");
        model.setVersion(VERSION);

        stepLogger = new ObjectStepLogger(System.out);
    }

    @Test
    void authValidTest() throws Exception {
        PowerAuthAuthenticationShared.authValidTest(model, stepLogger);
    }

    @Test
    void authInvalidPasswordTest() throws Exception {
        PowerAuthAuthenticationShared.authInvalidPasswordTest(config, model, stepLogger);
    }

    @Test
    void authIncorrectPasswordFormatTest() throws Exception {
        PowerAuthAuthenticationShared.authIncorrectPasswordFormatTest(config, model, stepLogger);
    }

    @Test
    void authCounterLookAheadTest() throws Exception {
        PowerAuthAuthenticationShared.authCounterLookAheadTest(config, model);
    }

    @Test
    void authBlockedActivationTest() throws Exception {
        PowerAuthAuthenticationShared.authBlockedActivationTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void authSingleFactorTest() throws Exception {
        PowerAuthAuthenticationShared.authSingleFactorTest(model, stepLogger);
    }

    @Test
    void authBiometryTest() throws Exception {
        PowerAuthAuthenticationShared.authBiometryTest(model, stepLogger);
    }

    @Test
    void authEmptyDataTest() throws Exception {
        PowerAuthAuthenticationShared.authEmptyDataTest(model, stepLogger, VERSION);
    }

    @Test
    void authValidGetTest() throws Exception {
        PowerAuthAuthenticationShared.authValidGetTest(config, model, stepLogger);
    }

    @Test
    void authValidGetNoParamTest() throws Exception {
        PowerAuthAuthenticationShared.authValidGetNoParamTest(model, stepLogger);
    }

    @Test
    void authGetInvalidPasswordTest() throws Exception {
        PowerAuthAuthenticationShared.authGetInvalidPasswordTest(config, model, stepLogger);
    }

    @Test
    void authUnsupportedApplicationTest() throws Exception {
        PowerAuthAuthenticationShared.authUnsupportedApplicationTest(powerAuthClient, config, model);
    }

    @Test
    void authMaxFailedAttemptsTest() throws Exception {
        PowerAuthAuthenticationShared.authMaxFailedAttemptsTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void authLookAheadTest() throws Exception {
        PowerAuthAuthenticationShared.authLookAheadTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void authCounterIncrementTest() throws Exception {
        PowerAuthAuthenticationShared.authCounterIncrementTest(model, stepLogger, VERSION);
    }

    @Test
    void authLargeDataTest() throws Exception {
        PowerAuthAuthenticationShared.authLargeDataTest(model, stepLogger, VERSION);
    }

    @Test
    void authSwappedKeyTest() throws Exception {
        PowerAuthAuthenticationShared.authSwappedKeyTest(config, model, stepLogger);
    }

    @Test
    void authInvalidResourceIdTest() throws Exception {
        PowerAuthAuthenticationShared.authInvalidResourceIdTest(config, model, stepLogger);
    }

    @Test
    void authV3UsingV4EndpointTest() throws Exception {
        final PowerAuthVersion version = PowerAuthVersion.V3_3;
        final byte[] data = Files.readAllBytes(Paths.get(dataFile.getAbsolutePath()));
        final VerifyAuthenticationStepModel model = new VerifyAuthenticationStepModel();
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setData(data);
        model.setHeaders(new HashMap<>());
        model.setHttpMethod("POST");
        model.setPassword(config.getPassword());
        model.setResourceId("/pa/auth/validate");
        model.setResultStatusObject(config.getResultStatusObject(version));
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE);
        model.setStatusFileName(config.getStatusFile(version).getAbsolutePath());
        model.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v4/auth/validate");
        model.setDryRun(true);
        model.setVersion(version);
        PowerAuthAuthenticationShared.authV3UsingV4EndpointTest(powerAuthClient, model, stepLogger);
    }


    @Test
    void authOfflinePersonalizedValidTest() throws Exception {
        PowerAuthAuthenticationShared.authOfflinePersonalizedValidTest(powerAuthClient, config, model, stepLogger, VERSION);
    }

    @Test
    void authOfflinePersonalizedInvalidTest() throws Exception {
        PowerAuthAuthenticationShared.authOfflinePersonalizedInvalidTest(powerAuthClient, config, model, stepLogger, VERSION);
    }

    @Test
    void authOfflineNonPersonalizedValidTest() throws Exception {
        PowerAuthAuthenticationShared.authOfflineNonPersonalizedValidTest(powerAuthClient, config, model, stepLogger, VERSION);
    }

    @Test
    void authOfflineNonPersonalizedInvalidTest() throws Exception {
        PowerAuthAuthenticationShared.authOfflineNonPersonalizedInvalidTest(powerAuthClient, config, model, stepLogger, VERSION);
    }

    @Test
    void testSignatureOfflinePersonalizedProximityCheckValid() throws Exception {
        PowerAuthAuthenticationShared.testAuthOfflinePersonalizedProximityCheckValid(powerAuthClient, config, model, stepLogger, VERSION);
    }

    @Test
    void testSignatureOfflinePersonalizedProximityCheckInvalid() throws Exception {
        PowerAuthAuthenticationShared.testAuthOfflinePersonalizedProximityCheckInvalid(powerAuthClient, config, model, stepLogger, VERSION);
    }

}
