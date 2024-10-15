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
package com.wultra.security.powerauth.test.v33;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthEncryptionShared;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.EnabledIf;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PowerAuth encryption tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
@EnabledIf(expression = "${powerauth.test.includeCustomTests}", loadContext = true)
class PowerAuthEncryptionTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V3_3;

    private PowerAuthTestConfiguration config;
    private static File dataFile;
    private EncryptStepModel encryptModel;
    private VerifySignatureStepModel signatureModel;
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
        fw.write("{\"data\": \"hello\"}");
        fw.close();
    }

    @AfterAll
    static void tearDownAfterClass() {
        assertTrue(dataFile.delete());
    }

    @BeforeEach
    void setUp() throws IOException {
        encryptModel = new EncryptStepModel();
        encryptModel.setApplicationKey(config.getApplicationKey());
        encryptModel.setApplicationSecret(config.getApplicationSecret());
        encryptModel.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));
        encryptModel.setMasterPublicKey(config.getMasterPublicKey());
        encryptModel.setHeaders(new HashMap<>());
        encryptModel.setResultStatusObject(config.getResultStatusObject(VERSION));
        encryptModel.setVersion(VERSION);

        signatureModel = new VerifySignatureStepModel();
        signatureModel.setApplicationKey(config.getApplicationKey());
        signatureModel.setApplicationSecret(config.getApplicationSecret());
        signatureModel.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));
        signatureModel.setHeaders(new HashMap<>());
        signatureModel.setHttpMethod("POST");
        signatureModel.setPassword(config.getPassword());
        signatureModel.setResultStatusObject(config.getResultStatusObject(VERSION));
        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        signatureModel.setStatusFileName(config.getStatusFile(VERSION).getAbsolutePath());
        signatureModel.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate");
        signatureModel.setVersion(VERSION);

        stepLogger = new ObjectStepLogger(System.out);
    }

    @Test
    void encryptInActivationScopeTest() throws Exception {
        PowerAuthEncryptionShared.encryptInActivationScopeTest(config, encryptModel, stepLogger);
    }

    @Test
    void encryptInApplicationScopeTest() throws Exception {
        PowerAuthEncryptionShared.encryptInApplicationScopeTest(config, encryptModel, stepLogger);
    }

    @Test
    void encryptInInvalidScope1Test() throws Exception {
        PowerAuthEncryptionShared.encryptInInvalidScope1Test(config, encryptModel, stepLogger);
    }

    @Test
    void encryptInInvalidScope2Test() throws Exception {
        PowerAuthEncryptionShared.encryptInInvalidScope2Test(config, encryptModel, stepLogger);
    }

    @Test
    void encryptEmptyDataTest() throws Exception {
        PowerAuthEncryptionShared.encryptEmptyDataTest(config, encryptModel, stepLogger);
    }

    @Test
    void encryptBlockedActivationTest() throws Exception {
        PowerAuthEncryptionShared.encryptBlockedActivationTest(powerAuthClient, config, encryptModel, stepLogger, VERSION);
    }

    @Test
    void signAndEncryptTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptTest(config, signatureModel, stepLogger, VERSION);
    }

    @Test
    void signAndEncryptWeakSignatureTypeTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptWeakSignatureTypeTest(config, signatureModel, stepLogger);
    }

    @Test
    void signAndEncryptInvalidPasswordTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptInvalidPasswordTest(config, signatureModel, stepLogger);
    }

    @Test
    void signAndEncryptEmptyDataTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptEmptyDataTest(config, signatureModel, encryptModel, stepLogger);
    }

    @Test
    void signAndEncryptLargeDataTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptLargeDataTest(config, signatureModel, stepLogger, VERSION);
    }

    @Test
    void signAndEncryptStringDataTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptStringDataTest(config, signatureModel, stepLogger, VERSION);
    }

    @Test
    void signAndEncryptRawDataTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptRawDataTest(config, signatureModel, stepLogger, VERSION);
    }

    @Test
    void signAndEncryptGenerifiedDataTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptGenerifiedDataTest(config, signatureModel, stepLogger);
    }

    @Test
    void signAndEncryptInvalidResourceIdTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptInvalidResourceIdTest(config, signatureModel, stepLogger);
    }

    @Test
    void signAndEncryptBlockedActivationTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptBlockedActivationTest(powerAuthClient, config, signatureModel, stepLogger, VERSION);
    }

    @Test
    void signAndEncryptUnsupportedApplicationTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptUnsupportedApplicationTest(powerAuthClient, config, signatureModel, VERSION);
    }

    @Test
    void signAndEncryptCounterIncrementTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptCounterIncrementTest(config, signatureModel, stepLogger);
    }

    @Test
    void signAndEncryptLookAheadTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptLookAheadTest(config, signatureModel);
    }

    @Test
    void signAndEncryptSingleFactorTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptSingleFactorTest(config, signatureModel, stepLogger);
    }

    @Test
    void signAndEncryptBiometryTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptBiometryTest(config, signatureModel, stepLogger);
    }

    @Test
    void signAndEncryptThreeFactorTest() throws Exception {
        PowerAuthEncryptionShared.signAndEncryptThreeFactorTest(config, signatureModel, stepLogger);
    }

    @Test
    void replayAttackEciesDecryptorTest() throws Exception {
        PowerAuthEncryptionShared.replayAttackEciesDecryptorTest(powerAuthClient, config, VERSION);
    }

    @Test
    void encryptedResponseTest() throws Exception {
        PowerAuthEncryptionShared.encryptedResponseTest(config, encryptModel, stepLogger, VERSION);
    }

}
