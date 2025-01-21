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
package com.wultra.security.powerauth.test.v31;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthSignatureShared;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
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
class PowerAuthSignatureTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V3_1;

    private PowerAuthTestConfiguration config;
    private static File dataFile;
    private VerifySignatureStepModel model;
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
    void setUp() throws IOException {
        model = new VerifySignatureStepModel();
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));
        model.setHeaders(new HashMap<>());
        model.setHttpMethod("POST");
        model.setPassword(config.getPassword());
        model.setResourceId("/pa/signature/validate");
        model.setResultStatusObject(config.getResultStatusObject(VERSION));
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        model.setStatusFileName(config.getStatusFile(VERSION).getAbsolutePath());
        model.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate");
        model.setVersion(VERSION);

        stepLogger = new ObjectStepLogger(System.out);
    }

    @Test
    void signatureValidTest() throws Exception {
        PowerAuthSignatureShared.signatureValidTest(model, stepLogger);
    }

    @Test
    void signatureInvalidPasswordTest() throws Exception {
        PowerAuthSignatureShared.signatureInvalidPasswordTest(config, model, stepLogger);
    }

    @Test
    void signatureIncorrectPasswordFormatTest() throws Exception {
        PowerAuthSignatureShared.signatureIncorrectPasswordFormatTest(config, model, stepLogger);
    }

    @Test
    void signatureCounterLookAheadTest() throws Exception {
        PowerAuthSignatureShared.signatureCounterLookAheadTest(config, model);
    }

    @Test
    void signatureBlockedActivationTest() throws Exception {
        PowerAuthSignatureShared.signatureBlockedActivationTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void signatureSingleFactorTest() throws Exception {
        PowerAuthSignatureShared.signatureSingleFactorTest(model, stepLogger);
    }

    @Test
    void signatureBiometryTest() throws Exception {
        PowerAuthSignatureShared.signatureBiometryTest(model, stepLogger);
    }

    @Test
    void signatureThreeFactorTest() throws Exception {
        PowerAuthSignatureShared.signatureThreeFactorTest(model, stepLogger);
    }

    @Test
    void signatureEmptyDataTest() throws Exception {
        PowerAuthSignatureShared.signatureEmptyDataTest(model, stepLogger, VERSION);
    }

    @Test
    void signatureValidGetTest() throws Exception {
        PowerAuthSignatureShared.signatureValidGetTest(config, model, stepLogger);
    }

    @Test
    void signatureValidGetNoParamTest() throws Exception {
        PowerAuthSignatureShared.signatureValidGetNoParamTest(config, model, stepLogger);
    }

    @Test
    void signatureGetInvalidPasswordTest() throws Exception {
        PowerAuthSignatureShared.signatureGetInvalidPasswordTest(config, model, stepLogger);
    }

    @Test
    void signatureUnsupportedApplicationTest() throws Exception {
        PowerAuthSignatureShared.signatureUnsupportedApplicationTest(powerAuthClient, config, model);
    }

    @Test
    void signatureMaxFailedAttemptsTest() throws Exception {
        PowerAuthSignatureShared.signatureMaxFailedAttemptsTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void signatureLookAheadTest() throws Exception {
        PowerAuthSignatureShared.signatureLookAheadTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void signatureCounterIncrementTest() throws Exception {
        PowerAuthSignatureShared.signatureCounterIncrementTest(model, stepLogger);
    }

    @Test
    void signatureLargeDataTest() throws Exception {
        PowerAuthSignatureShared.signatureLargeDataTest(model, stepLogger, VERSION);
    }

    @Test
    void signatureOfflinePersonalizedValidTest() throws Exception {
        PowerAuthSignatureShared.signatureOfflinePersonalizedValidTest(powerAuthClient, config, model, stepLogger, VERSION);
    }

    @Test
    void signatureOfflinePersonalizedInvalidTest() throws Exception {
        PowerAuthSignatureShared.signatureOfflinePersonalizedInvalidTest(powerAuthClient, config, model, stepLogger, VERSION);
    }

    @Test
    void signatureOfflineNonPersonalizedValidTest() throws Exception {
        PowerAuthSignatureShared.signatureOfflineNonPersonalizedValidTest(powerAuthClient, config, model, stepLogger, VERSION);
    }

    @Test
    void signatureOfflineNonPersonalizedInvalidTest() throws Exception {
        PowerAuthSignatureShared.signatureOfflineNonPersonalizedInvalidTest(powerAuthClient, config, model, stepLogger, VERSION);
    }

    @Test
    void signatureSwappedKeyTest() throws Exception {
        PowerAuthSignatureShared.signatureSwappedKeyTest(config, model, stepLogger);
    }

    @Test
    void signatureInvalidResourceIdTest() throws Exception {
        PowerAuthSignatureShared.signatureInvalidResourceIdTest(config, model, stepLogger);
    }

    @Test
    void testSignatureOfflinePersonalizedProximityCheckValid() throws Exception {
        PowerAuthSignatureShared.testSignatureOfflinePersonalizedProximityCheckValid(powerAuthClient, config, model, stepLogger, VERSION);
    }

    @Test
    void testSignatureOfflinePersonalizedProximityCheckInvalid() throws Exception {
        PowerAuthSignatureShared.testSignatureOfflinePersonalizedProximityCheckInvalid(powerAuthClient, config, model, stepLogger, VERSION);
    }

}
