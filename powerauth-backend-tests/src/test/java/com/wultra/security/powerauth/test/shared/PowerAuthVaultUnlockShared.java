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
import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.client.model.response.v3.VerifyECDSASignatureResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.core.rest.model.base.response.ErrorResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.model.VaultUnlockStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.v3.VaultUnlockStep;
import com.wultra.security.powerauth.lib.cmd.util.CounterUtil;
import org.junit.jupiter.api.AssertionFailureBuilder;

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

        final boolean keyDecryptionSuccessful = stepLogger.getItems().stream()
                .filter(item -> item.name().equals("Vault Unlocked"))
                .map(item -> (Map<String, Object>) item.object())
                .map(item -> (String) item.get("privateKeyDecryptionSuccessful"))
                .map(Boolean::valueOf)
                .findAny()
                .orElse(false);

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

    public static void vaultUnlockBlockedActivationTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VaultUnlockStepModel model, final PowerAuthVersion version) throws Exception {
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
        if (model.getVersion().useTemporaryKeys()) {
            assertEquals(400, stepLogger1.getResponse().statusCode());
        } else {
            assertEquals(401, stepLogger1.getResponse().statusCode());
        }

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

    public static void vaultUnlockCounterIncrementTest(final VaultUnlockStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        // Verify counter after createToken - in version 3.0 the counter is incremented once
        byte[] ctrDataExpected = new HashBasedCounter(version.value()).next(ctrData);
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

    public static void vaultUnlockAndECDSASignatureValidTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VaultUnlockStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        final byte[] dataBytes = ("test_data" + version).getBytes(StandardCharsets.UTF_8);
        final String data = Base64.getEncoder().encodeToString(dataBytes);

        final PrivateKey devicePrivateKey = obtainDevicePrivateKeyUsingVaultUnlock(stepLogger, model, config);

        final byte[] signature = SIGNATURE_UTILS.computeECDSASignature(EcCurve.P256, dataBytes, devicePrivateKey);

        final VerifyECDSASignatureResponse verifyResponse = powerAuthClient.verifyECDSASignature(config.getActivationId(version), data, Base64.getEncoder().encodeToString(signature));
        assertTrue(verifyResponse.isSignatureValid());
    }

    public static void vaultUnlockAndECDSASignatureInvalidTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VaultUnlockStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        final byte[] dataBytes = ("test_data" + version).getBytes(StandardCharsets.UTF_8);
        final String data = Base64.getEncoder().encodeToString(dataBytes);

        final PrivateKey devicePrivateKey = obtainDevicePrivateKeyUsingVaultUnlock(stepLogger, model, config);

        final byte[] signature = SIGNATURE_UTILS.computeECDSASignature(EcCurve.P256, "test_data_crippled".getBytes(StandardCharsets.UTF_8), devicePrivateKey);

        final VerifyECDSASignatureResponse verifyResponse = powerAuthClient.verifyECDSASignature(config.getActivationId(version), data, Base64.getEncoder().encodeToString(signature));
        assertFalse(verifyResponse.isSignatureValid());
    }

    public static void vaultUnlockAndECDSASignatureInvalidActivationTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VaultUnlockStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        final byte[] dataBytes = ("test_data" + version).getBytes(StandardCharsets.UTF_8);
        final String data = Base64.getEncoder().encodeToString(dataBytes);

        final PrivateKey devicePrivateKey = obtainDevicePrivateKeyUsingVaultUnlock(stepLogger, model, config);

        final byte[] signature = SIGNATURE_UTILS.computeECDSASignature(EcCurve.P256, dataBytes, devicePrivateKey);

        final String activationIdInvalid = switch (version) {
            case V3_0 -> config.getActivationId(PowerAuthVersion.V3_3);
            case V3_1 -> config.getActivationId(PowerAuthVersion.V3_2);
            case V3_2 -> config.getActivationId(PowerAuthVersion.V3_1);
            case V3_3 -> config.getActivationId(PowerAuthVersion.V3_0);
            default -> null;
        };

        final VerifyECDSASignatureResponse verifyResponse = powerAuthClient.verifyECDSASignature(activationIdInvalid, data, Base64.getEncoder().encodeToString(signature));
        assertFalse(verifyResponse.isSignatureValid());
    }

    public static void vaultUnlockAndECDSASignatureNonExistentActivationTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VaultUnlockStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        final byte[] dataBytes = ("test_data" + version).getBytes(StandardCharsets.UTF_8);
        final String data = Base64.getEncoder().encodeToString(dataBytes);

        final PrivateKey devicePrivateKey = obtainDevicePrivateKeyUsingVaultUnlock(stepLogger, model, config);
        final byte[] signature = SIGNATURE_UTILS.computeECDSASignature(EcCurve.P256, dataBytes, devicePrivateKey);

        final VerifyECDSASignatureResponse verifyResponse = powerAuthClient.verifyECDSASignature("AAAAA-BBBBB-CCCCC-DDDDD", data, Base64.getEncoder().encodeToString(signature));
        assertFalse(verifyResponse.isSignatureValid());
    }

    private static PrivateKey obtainDevicePrivateKeyUsingVaultUnlock(final ObjectStepLogger stepLogger, final VaultUnlockStepModel model, final PowerAuthTestConfiguration config) throws Exception {
        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Map<String, Object> responseMap = stepLogger.getItems().stream()
                .filter(item -> item.name().equals("Vault Unlocked"))
                .map(item -> (Map<String, Object>) item.object())
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure()
                        .message("Key decryption has not been successful")
                        .build());

        assertEquals("true", responseMap.get("privateKeyDecryptionSuccessful"));
        final String devicePrivateKeyBase64 = (String) responseMap.get("devicePrivateKey");

        return config.getKeyConvertor().convertBytesToPrivateKey(EcCurve.P256, Base64.getDecoder().decode(devicePrivateKeyBase64));
    }

    private static void checkSignatureError(ErrorResponse errorResponse) {
        // Errors differ when Web Flow is used because of its Exception handler, for protocol version 3.3 temporary key error is present
        assertTrue("POWERAUTH_AUTH_FAIL".equals(errorResponse.getResponseObject().getCode()) || "ERR_AUTHENTICATION".equals(errorResponse.getResponseObject().getCode()) || "ERR_TEMPORARY_KEY".equals(errorResponse.getResponseObject().getCode()));
        assertTrue("Signature validation failed".equals(errorResponse.getResponseObject().getMessage()) || "POWER_AUTH_SIGNATURE_INVALID".equals(errorResponse.getResponseObject().getMessage()) || "POWER_AUTH_TEMPORARY_KEY_FAILURE".equals(errorResponse.getResponseObject().getMessage()));
    }
}
