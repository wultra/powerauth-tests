/*
 * PowerAuth test and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.shared;

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

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth vault unlock test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthVaultUnlockShared {

    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();

    public static void vaultUnlockTest(final VaultUnlockStepModel model, final ObjectStepLogger stepLogger) throws Exception {
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

    public static void vaultUnlockInvalidPasswordTest(final PowerAuthTestConfiguration config, final VaultUnlockStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setPassword("1111");

        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);
    }

    public static void vaultUnlockSingleFactorTest(final PowerAuthTestConfiguration config, final VaultUnlockStepModel model, final ObjectStepLogger stepLogger) throws Exception {
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

    public static void vaultUnlockBiometryFactorTest(final VaultUnlockStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_BIOMETRY);

        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());
    }

    public static void vaultUnlockThreeFactorTest(final VaultUnlockStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY);

        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());
    }

    public static void vaultUnlockBlockedActivationTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VaultUnlockStepModel model, final String version) throws Exception {
        powerAuthClient.blockActivation(config.getActivationId(version), "test", "test");

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new VaultUnlockStep().execute(stepLogger1, model.toMap());
        assertFalse(stepLogger1.getResult().success());
        assertEquals(401, stepLogger1.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);

        powerAuthClient.unblockActivation(config.getActivationId(version), "test");

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VaultUnlockStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());
    }

    public static void vaultUnlockUnsupportedApplicationTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VaultUnlockStepModel model) throws Exception {
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

    public static void vaultUnlockCounterIncrementTest(final VaultUnlockStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        // Verify counter after createToken - in version 3.0 the counter is incremented once
        byte[] ctrDataExpected = new HashBasedCounter().next(ctrData);
        assertArrayEquals(ctrDataExpected, CounterUtil.getCtrData(model, stepLogger));
    }

    public static void vaultUnlockTooLongReasonTest(final PowerAuthTestConfiguration config, final VaultUnlockStepModel model, final ObjectStepLogger stepLogger) throws Exception {
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

    public static void vaultUnlockAndECDSASignatureValidTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VaultUnlockStepModel model, final ObjectStepLogger stepLogger, final String version) throws Exception {
        byte[] dataBytes = ("test_data_v" + version).getBytes(StandardCharsets.UTF_8);
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

        byte[] signature = SIGNATURE_UTILS.computeECDSASignature(dataBytes, devicePrivateKey);

        final VerifyECDSASignatureResponse verifyResponse = powerAuthClient.verifyECDSASignature(config.getActivationId(version), data, Base64.getEncoder().encodeToString(signature));
        assertTrue(verifyResponse.isSignatureValid());
    }

    public static void vaultUnlockAndECDSASignatureInvalidTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VaultUnlockStepModel model, final ObjectStepLogger stepLogger, final String version) throws Exception {
        byte[] dataBytes = ("test_data_v" + version).getBytes(StandardCharsets.UTF_8);
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

        byte[] signature = SIGNATURE_UTILS.computeECDSASignature("test_data_crippled".getBytes(StandardCharsets.UTF_8), devicePrivateKey);

        VerifyECDSASignatureResponse verifyResponse = powerAuthClient.verifyECDSASignature(config.getActivationIdV32(), data, Base64.getEncoder().encodeToString(signature));
        assertFalse(verifyResponse.isSignatureValid());
    }

    public static void vaultUnlockAndECDSASignatureInvalidActivationTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VaultUnlockStepModel model, final ObjectStepLogger stepLogger, final String version) throws Exception {
        byte[] dataBytes = ("test_data_v" + version).getBytes(StandardCharsets.UTF_8);
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

        byte[] signature = SIGNATURE_UTILS.computeECDSASignature(dataBytes, devicePrivateKey);

        String activationIdInvalid = switch (version) {
            case "3.0" -> config.getActivationIdV31();
            case "3.1" -> config.getActivationIdV32();
            case "3.2" -> config.getActivationIdV3();
            default -> null;
        };

        VerifyECDSASignatureResponse verifyResponse = powerAuthClient.verifyECDSASignature(activationIdInvalid, data, Base64.getEncoder().encodeToString(signature));
        assertFalse(verifyResponse.isSignatureValid());
    }

    public static void vaultUnlockAndECDSASignatureNonExistentActivationTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VaultUnlockStepModel model, final ObjectStepLogger stepLogger, final String version) throws Exception {
        byte[] dataBytes = ("test_data_v" + version).getBytes(StandardCharsets.UTF_8);
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

        byte[] signature = SIGNATURE_UTILS.computeECDSASignature(dataBytes, devicePrivateKey);

        VerifyECDSASignatureResponse verifyResponse = powerAuthClient.verifyECDSASignature("AAAAA-BBBBB-CCCCC-DDDDD", data, Base64.getEncoder().encodeToString(signature));
        assertFalse(verifyResponse.isSignatureValid());
    }

    private static void checkSignatureError(ErrorResponse errorResponse) {
        // Errors differ when Web Flow is used because of its Exception handler
        assertTrue("POWERAUTH_AUTH_FAIL".equals(errorResponse.getResponseObject().getCode()) || "ERR_AUTHENTICATION".equals(errorResponse.getResponseObject().getCode()));
        assertTrue("Signature validation failed".equals(errorResponse.getResponseObject().getMessage()) || "POWER_AUTH_SIGNATURE_INVALID".equals(errorResponse.getResponseObject().getMessage()));
    }
}
