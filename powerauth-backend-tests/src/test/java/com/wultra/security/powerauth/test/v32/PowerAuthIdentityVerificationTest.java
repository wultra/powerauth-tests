/*
 * PowerAuth test and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthIdentityVerificationShared;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.*;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.EnabledIf;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
@EnabledIf(expression = "${powerauth.test.includeCustomTests}", loadContext = true)
class PowerAuthIdentityVerificationTest {

    private static final String VERSION = "3.2";

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private PowerAuthIdentityVerificationShared.TestContext ctx;

    private final ObjectMapper objectMapper = new ObjectMapper().disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @BeforeEach
    void setUp() throws IOException {
        // Create temp status file
        File tempStatusFile = File.createTempFile("pa_status_v" + VERSION.replace(".", ""), ".json");

        // Create result status object
        JSONObject resultStatusObject = new JSONObject();

        EncryptStepModel encryptModel = new EncryptStepModel();
        encryptModel.setApplicationKey(config.getApplicationKey());
        encryptModel.setApplicationSecret(config.getApplicationSecret());
        encryptModel.setMasterPublicKey(config.getMasterPublicKey());
        encryptModel.setHeaders(new HashMap<>());
        encryptModel.setResultStatusObject(resultStatusObject);
        encryptModel.setVersion(VERSION);

        VerifySignatureStepModel signatureModel = new VerifySignatureStepModel();
        signatureModel.setApplicationKey(config.getApplicationKey());
        signatureModel.setApplicationSecret(config.getApplicationSecret());
        signatureModel.setHeaders(new HashMap<>());
        signatureModel.setHttpMethod("POST");
        signatureModel.setPassword(config.getPassword());
        signatureModel.setResultStatusObject(resultStatusObject);
        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION);
        signatureModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        signatureModel.setVersion(VERSION);

        TokenAndEncryptStepModel tokenAndEncryptModel = new TokenAndEncryptStepModel();
        tokenAndEncryptModel.setApplicationKey(config.getApplicationKey());
        tokenAndEncryptModel.setApplicationSecret(config.getApplicationSecret());
        tokenAndEncryptModel.setHeaders(new HashMap<>());
        tokenAndEncryptModel.setHttpMethod("POST");
        tokenAndEncryptModel.setResultStatusObject(resultStatusObject);
        tokenAndEncryptModel.setVersion(VERSION);

        VerifyTokenStepModel tokenModel = new VerifyTokenStepModel();
        tokenModel.setHeaders(new HashMap<>());
        tokenModel.setResultStatusObject(resultStatusObject);
        tokenModel.setHttpMethod("POST");
        tokenModel.setVersion(VERSION);

        // Model shared among tests
        CreateActivationStepModel activationModel = new CreateActivationStepModel();
        activationModel.setActivationName("test v3.1 document verification");
        activationModel.setApplicationKey(config.getApplicationKey());
        activationModel.setApplicationSecret(config.getApplicationSecret());
        activationModel.setMasterPublicKey(config.getMasterPublicKey());
        activationModel.setHeaders(new HashMap<>());
        activationModel.setPassword(config.getPassword());
        activationModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        activationModel.setResultStatusObject(resultStatusObject);
        activationModel.setUriString(config.getEnrollmentServiceUrl());
        activationModel.setVersion(VERSION);
        activationModel.setDeviceInfo("backend-tests");

        CreateTokenStepModel createTokenModel = new CreateTokenStepModel();
        createTokenModel.setApplicationKey(config.getApplicationKey());
        createTokenModel.setApplicationSecret(config.getApplicationSecret());
        createTokenModel.setHeaders(new HashMap<>());
        createTokenModel.setMasterPublicKey(config.getMasterPublicKey());
        createTokenModel.setPassword(config.getPassword());
        createTokenModel.setResultStatusObject(resultStatusObject);
        createTokenModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        createTokenModel.setUriString(config.getEnrollmentServiceUrl());
        createTokenModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION);
        createTokenModel.setVersion(VERSION);

        ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        ctx = new PowerAuthIdentityVerificationShared.TestContext(powerAuthClient, config, activationModel, encryptModel, signatureModel, createTokenModel, tokenAndEncryptModel, tokenModel, objectMapper, stepLogger);
    }

    @Test
    void testSuccessfulIdentityVerification() throws Exception {
        PowerAuthIdentityVerificationShared.testSuccessfulIdentityVerification(ctx);
    }

    @Test
    void testScaFailedPresenceCheck() throws Exception {
        PowerAuthIdentityVerificationShared.testScaFailedPresenceCheck(ctx);
    }

    @Test
    void testScaFailedOtpCheck() throws Exception {
        PowerAuthIdentityVerificationShared.testScaFailedOtpCheck(ctx);
    }

    @Test
    void testSuccessfulIdentityVerificationWithRestarts() throws Exception {
        PowerAuthIdentityVerificationShared.testSuccessfulIdentityVerificationWithRestarts(ctx);
    }

    @Test
    void testSuccessfulIdentityVerificationMultipleDocSubmits() throws Exception {
        PowerAuthIdentityVerificationShared.testSuccessfulIdentityVerificationMultipleDocSubmits(ctx);
    }

    @Test
    void testDocSubmitDifferentDocumentType() throws Exception {
        PowerAuthIdentityVerificationShared.testDocSubmitDifferentDocumentType(ctx);
    }

    @Test
    void testDocSubmitDifferentCardSide() throws Exception {
        PowerAuthIdentityVerificationShared.testDocSubmitDifferentCardSide(ctx);
    }

    @Test
    void testDocSubmitMaxAttemptsLimit() throws Exception {
        PowerAuthIdentityVerificationShared.testDocSubmitMaxAttemptsLimit(ctx);
    }

    @Test
    void testIdentityVerificationNotDocumentPhotos() throws Exception {
        PowerAuthIdentityVerificationShared.testIdentityVerificationNotDocumentPhotos(ctx);
    }

    @Test
    void testIdentityVerificationCleanup() throws Exception {
        PowerAuthIdentityVerificationShared.testIdentityVerificationCleanup(ctx);
    }

    @Test
    void testIdentityVerificationMaxAttemptLimit() throws Exception {
        PowerAuthIdentityVerificationShared.testIdentityVerificationMaxAttemptLimit(ctx);
    }

    @Test
    void largeUploadTest() throws Exception {
        PowerAuthIdentityVerificationShared.largeUploadTest(ctx);
    }

    @Test
    void initDocumentVerificationSdkTest() throws Exception {
        PowerAuthIdentityVerificationShared.initDocumentVerificationSdkTest(ctx);
    }

    @Test
    void testFailedScaOtpMaxFailedAttemptsIdentityRestart() throws Exception {
        PowerAuthIdentityVerificationShared.testFailedScaOtpMaxFailedAttemptsIdentityRestart(ctx);
    }

    @Test
    void testErrorScoreLimit() throws Exception {
        PowerAuthIdentityVerificationShared.testErrorScoreLimit(ctx);
    }

}
