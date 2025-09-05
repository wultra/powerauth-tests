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
package com.wultra.security.powerauth.test.shared.v4;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.core.rest.model.base.response.ErrorResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.VaultUnlockStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.VaultUnlockStepModel;
import com.wultra.security.powerauth.lib.cmd.util.CounterUtil;

import java.util.Map;
import java.util.Objects;

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
                .map(item -> (String) item.get("vaultEncryptionKey"))
                .map(Objects::nonNull)
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
        checkAuthenticationError(errorResponse);
    }

    public static void vaultUnlockSingleFactorTest(final PowerAuthTestConfiguration config, final VaultUnlockStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION);

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
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_BIOMETRY);

        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());
    }

    public static void vaultUnlockThreeFactorTest(final VaultUnlockStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY);

        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());
    }

    public static void vaultUnlockBlockedActivationTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VaultUnlockStepModel model, final PowerAuthVersion version) throws Exception {
        powerAuthClient.blockActivation(config.getActivationId(version), "test", "test");

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new VaultUnlockStep().execute(stepLogger1, model.toMap());
        assertFalse(stepLogger1.getResult().success());
        assertEquals(400, stepLogger1.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSecureVaultError(errorResponse);

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
        checkTemporaryKeyError(errorResponse);

        powerAuthClient.supportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        ObjectStepLogger stepLogger2 = new ObjectStepLogger(System.out);
        new VaultUnlockStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        final AeadEncryptedResponse responseOK = (AeadEncryptedResponse) stepLogger2.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getTimestamp());
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

    private static void checkAuthenticationError(ErrorResponse errorResponse) {
        assertTrue("ERR_AUTHENTICATION".equals(errorResponse.getResponseObject().getCode()));
    }

    private static void checkTemporaryKeyError(ErrorResponse errorResponse) {
        assertTrue("ERR_TEMPORARY_KEY".equals(errorResponse.getResponseObject().getCode()));
    }

    private static void checkSecureVaultError(ErrorResponse errorResponse) {
        assertTrue("ERR_SECURE_VAULT".equals(errorResponse.getResponseObject().getCode()));
    }

}
