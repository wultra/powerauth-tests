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
package com.wultra.security.powerauth.test.v3;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.response.VerifyECDSASignatureResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.VaultUnlockStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.VaultUnlockStep;
import io.getlime.security.powerauth.lib.cmd.util.CounterUtil;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthVaultUnlockTest {

    private PowerAuthTestConfiguration config;
    private PowerAuthClient powerAuthClient;
    private VaultUnlockStepModel model;
    private ObjectStepLogger stepLogger;

    private final SignatureUtils signatureUtils = new SignatureUtils();

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @BeforeEach
    void setUp() {
        model = new VaultUnlockStepModel();
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setResultStatusObject(config.getResultStatusObjectV3());
        model.setStatusFileName(config.getStatusFileV3().getAbsolutePath());
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setReason("TEST_3.0");
        model.setVersion("3.0");

        stepLogger = new ObjectStepLogger(System.out);
    }

    @Test
    void vaultUnlockTest() throws Exception {
        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        boolean keyDecryptionSuccessful = false;
        for (StepItem item: stepLogger.getItems()) {
            if (item.name().equals("Vault Unlocked")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                assertEquals("true", responseMap.get("privateKeyDecryptionSuccessful"));
                keyDecryptionSuccessful = true;
            }
        }
        assertTrue(keyDecryptionSuccessful);
    }

    @Test
    void vaultUnlockInvalidPasswordTest() throws Exception {
        model.setPassword("1111");

        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);
    }

    @Test
    void vaultUnlockSingleFactorTest() throws Exception {
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION);

        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        // Verify BAD_REQUEST status code
        assertEquals(400, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_SECURE_VAULT", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_SECURE_VAULT_INVALID", errorResponse.getResponseObject().getMessage());
    }

    @Test
    void vaultUnlockBiometryFactorTest() throws Exception {
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_BIOMETRY);

        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());
    }

    @Test
    void vaultUnlockThreeFactorTest() throws Exception {
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY);

        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());
    }

    @Test
    void vaultUnlockBlockedActivationTest() throws Exception {
        powerAuthClient.blockActivation(config.getActivationIdV3(), "test", "test");

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new VaultUnlockStep().execute(stepLogger1, model.toMap());
        assertFalse(stepLogger1.getResult().success());
        assertEquals(401, stepLogger1.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);

        powerAuthClient.unblockActivation(config.getActivationIdV3(), "test");

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VaultUnlockStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());
    }

    @Test
    void vaultUnlockUnsupportedApplicationTest() throws Exception {
        powerAuthClient.unsupportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new VaultUnlockStep().execute(stepLogger1, model.toMap());
        assertFalse(stepLogger1.getResult().success());
        assertEquals(401, stepLogger1.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);

        powerAuthClient.supportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        ObjectStepLogger stepLogger2 = new ObjectStepLogger(System.out);
        new VaultUnlockStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        final EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger2.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());
    }

    @Test
    void vaultUnlockCounterIncrementTest() throws Exception {
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        // Verify counter after createToken - in version 3.0 the counter is incremented once
        byte[] ctrDataExpected = new HashBasedCounter().next(ctrData);
        assertArrayEquals(ctrDataExpected, CounterUtil.getCtrData(model, this.stepLogger));
    }

    @Test
    void vaultUnlockTooLongReasonTest() throws Exception {
        model.setReason("vt39nW6ZM963PJ8qxiREICZqK5medvUN8YizLDaLYTlMUtXyvdkqG3fMda29eCRHwAeAUsB415HqUlYZoDeEkvCOQzhu8ZpTGahAZVROi0YcNNGizecpzLDQUzRPbzVbHfJRd5zUasU3npS7FE9WZSqVfpLEthrPRN40efWxmKHxTzCUbHkk11odipkavelkG64mUgrdX0STh22vL4hE8jMjOM86HIT0rZHx2EhC1muJvtdDxWK3pz3Z9s2GHKj0");

        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_SECURE_VAULT", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_SECURE_VAULT_INVALID", errorResponse.getResponseObject().getMessage());
    }

    @Test
    void vaultUnlockAndECDSASignatureValidTest() throws Exception {
        byte[] dataBytes = "test_data_v3".getBytes(StandardCharsets.UTF_8);
        String data = Base64.getEncoder().encodeToString(dataBytes);

        // Obtain the device private key using vault unlock
        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        boolean keyDecryptionSuccessful = false;
        String devicePrivateKeyBase64 = null;
        for (StepItem item: stepLogger.getItems()) {
            if (item.name().equals("Vault Unlocked")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                assertEquals("true", responseMap.get("privateKeyDecryptionSuccessful"));
                keyDecryptionSuccessful = true;
                devicePrivateKeyBase64 = (String) responseMap.get("devicePrivateKey");
            }
        }
        assertTrue(keyDecryptionSuccessful);

        PrivateKey devicePrivateKey = config.getKeyConvertor().convertBytesToPrivateKey(Base64.getDecoder().decode(devicePrivateKeyBase64));

        byte[] signature = signatureUtils.computeECDSASignature(dataBytes, devicePrivateKey);

        final VerifyECDSASignatureResponse verifyResponse = powerAuthClient.verifyECDSASignature(config.getActivationIdV3(), data, Base64.getEncoder().encodeToString(signature));
        assertTrue(verifyResponse.isSignatureValid());
    }

    @Test
    void vaultUnlockAndECDSASignatureInvalidTest() throws Exception {
        byte[] dataBytes = "test_data_v3".getBytes(StandardCharsets.UTF_8);
        String data = Base64.getEncoder().encodeToString(dataBytes);

        // Obtain the device private key using vault unlock
        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        boolean keyDecryptionSuccessful = false;
        String devicePrivateKeyBase64 = null;
        for (StepItem item: stepLogger.getItems()) {
            if (item.name().equals("Vault Unlocked")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                assertEquals("true", responseMap.get("privateKeyDecryptionSuccessful"));
                keyDecryptionSuccessful = true;
                devicePrivateKeyBase64 = (String) responseMap.get("devicePrivateKey");
            }
        }
        assertTrue(keyDecryptionSuccessful);

        PrivateKey devicePrivateKey = config.getKeyConvertor().convertBytesToPrivateKey(Base64.getDecoder().decode(devicePrivateKeyBase64));

        byte[] signature = signatureUtils.computeECDSASignature("test_data_crippled".getBytes(StandardCharsets.UTF_8), devicePrivateKey);

        VerifyECDSASignatureResponse verifyResponse = powerAuthClient.verifyECDSASignature(config.getActivationIdV3(), data, Base64.getEncoder().encodeToString(signature));
        assertFalse(verifyResponse.isSignatureValid());
    }

    @Test
    void vaultUnlockAndECDSASignatureInvalidActivationTest() throws Exception {
        byte[] dataBytes = "test_data_v3".getBytes(StandardCharsets.UTF_8);
        String data = Base64.getEncoder().encodeToString(dataBytes);

        // Obtain the device private key using vault unlock
        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        boolean keyDecryptionSuccessful = false;
        String devicePrivateKeyBase64 = null;
        for (StepItem item: stepLogger.getItems()) {
            if (item.name().equals("Vault Unlocked")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                assertEquals("true", responseMap.get("privateKeyDecryptionSuccessful"));
                keyDecryptionSuccessful = true;
                devicePrivateKeyBase64 = (String) responseMap.get("devicePrivateKey");
            }
        }
        assertTrue(keyDecryptionSuccessful);

        PrivateKey devicePrivateKey = config.getKeyConvertor().convertBytesToPrivateKey(Base64.getDecoder().decode(devicePrivateKeyBase64));

        byte[] signature = signatureUtils.computeECDSASignature(dataBytes, devicePrivateKey);

        VerifyECDSASignatureResponse verifyResponse = powerAuthClient.verifyECDSASignature(config.getActivationIdV31(), data, Base64.getEncoder().encodeToString(signature));
        assertFalse(verifyResponse.isSignatureValid());
    }

    @Test
    void vaultUnlockAndECDSASignatureNonExistentActivationTest() throws Exception {
        byte[] dataBytes = "test_data_v3".getBytes(StandardCharsets.UTF_8);
        String data = Base64.getEncoder().encodeToString(dataBytes);

        // Obtain the device private key using vault unlock
        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        boolean keyDecryptionSuccessful = false;
        String devicePrivateKeyBase64 = null;
        for (StepItem item: stepLogger.getItems()) {
            if (item.name().equals("Vault Unlocked")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                assertEquals("true", responseMap.get("privateKeyDecryptionSuccessful"));
                keyDecryptionSuccessful = true;
                devicePrivateKeyBase64 = (String) responseMap.get("devicePrivateKey");
            }
        }
        assertTrue(keyDecryptionSuccessful);

        PrivateKey devicePrivateKey = config.getKeyConvertor().convertBytesToPrivateKey(Base64.getDecoder().decode(devicePrivateKeyBase64));

        byte[] signature = signatureUtils.computeECDSASignature(dataBytes, devicePrivateKey);

        VerifyECDSASignatureResponse verifyResponse = powerAuthClient.verifyECDSASignature("AAAAA-BBBBB-CCCCC-DDDDD", data, Base64.getEncoder().encodeToString(signature));
        assertFalse(verifyResponse.isSignatureValid());
    }

    private void checkSignatureError(ErrorResponse errorResponse) {
        // Errors differ when Web Flow is used because of its Exception handler
        assertTrue("POWERAUTH_AUTH_FAIL".equals(errorResponse.getResponseObject().getCode()) || "ERR_AUTHENTICATION".equals(errorResponse.getResponseObject().getCode()));
        assertTrue("Signature validation failed".equals(errorResponse.getResponseObject().getMessage()) || "POWER_AUTH_SIGNATURE_INVALID".equals(errorResponse.getResponseObject().getMessage()));
    }
}
