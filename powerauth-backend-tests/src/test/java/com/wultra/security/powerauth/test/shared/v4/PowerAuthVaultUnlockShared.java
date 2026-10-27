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

import com.wultra.core.rest.model.base.response.ErrorResponse;
import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.request.GetActivationListForUserRequest;
import com.wultra.security.powerauth.client.model.request.LookupActivationsRequest;
import com.wultra.security.powerauth.client.model.request.v4.GetActivationStatusRequest;
import com.wultra.security.powerauth.client.model.response.v4.GetActivationStatusResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.ActivationVersion;
import com.wultra.security.powerauth.crypto.lib.util.HybridPublicKeyFingerprint;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsa;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsa;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.SignAsymmetricStep;
import com.wultra.security.powerauth.lib.cmd.steps.VaultUnlockStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.SignAsymmetricStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.VaultUnlockStepModel;
import com.wultra.security.powerauth.util.TestCounterUtil;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
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
    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC = new MlDsaKeyConvertor();
    private static final PqcDsa PQC_DSA = new MlDsa();
    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

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

        // Biometry can be used for vault unlock unlike in v3:
        // KEK_DEVICE_PRIVATE - biometry is enabled by default (can be disabled)
        // KDK_APP_VAULT_2FA - biometry is enabled
        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void vaultUnlockBiometryFactorFailTest(final VaultUnlockStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_BIOMETRY);

        // Biometry test for disabled biometry key identifier KDK_APP_VAULT_KNOWLEDGE
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
        byte[] ctrData = TestCounterUtil.getCtrData(model.getResultStatus());
        new VaultUnlockStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        // Verify counter after createToken - in version 3.0 the counter is incremented once
        byte[] ctrDataExpected = new HashBasedCounter(version.value()).next(ctrData);
        assertArrayEquals(ctrDataExpected, TestCounterUtil.getCtrData(model.getResultStatus()));
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

    public static void vaultUnlockDevicePrivateKeyAndSignTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final SignAsymmetricStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        new SignAsymmetricStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final String signatureEc = stepLogger.getItems().stream()
                .filter(item -> item.name().equals("Sign Asymmetric Succeeded"))
                .map(item -> (Map<String, Object>) item.object())
                .map(item -> (String) item.get("signatureEc"))
                .findAny()
                .orElse(null);
        assertNotNull(signatureEc);
        final byte[] signatureEcBytes = Base64.getDecoder().decode(signatureEc);

        // Verify EC signature
        final byte[] requestBytes = "Confidential test message used for testing".getBytes(StandardCharsets.UTF_8);
        final String ecDevicePublicKeyBase64 = model.getResultStatus().getEcDevicePublicKey();
        assertNotNull(ecDevicePublicKeyBase64);
        final byte[] ecDevicePublicKeyBytes = Base64.getDecoder().decode(ecDevicePublicKeyBase64);
        final PublicKey ecDevicePublicKey = KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P384, ecDevicePublicKeyBytes);
        assertTrue(SIGNATURE_UTILS.validateECDSASignature(EcCurve.P384, requestBytes, signatureEcBytes, ecDevicePublicKey));

        final String signaturePqc = stepLogger.getItems().stream()
                .filter(item -> item.name().equals("Sign Asymmetric Succeeded"))
                .map(item -> (Map<String, Object>) item.object())
                .map(item -> (String) item.get("signaturePqc"))
                .findAny()
                .orElse(null);
        assertNotNull(signaturePqc);
        final byte[] signaturePqcBytes = Base64.getDecoder().decode(signaturePqc);

        final String pqcDevicePublicKeyBase64 = model.getResultStatus().getPqcDevicePublicKey();
        assertNotNull(pqcDevicePublicKeyBase64);
        final byte[] pqcDevicePublicKeyBytes = Base64.getDecoder().decode(pqcDevicePublicKeyBase64);
        final PublicKey pqcDevicePublicKey = KEY_CONVERTOR_PQC.convertBytesToPublicKey(pqcDevicePublicKeyBytes);
        assertTrue(PQC_DSA.verify(pqcDevicePublicKey, requestBytes, signaturePqcBytes));

        // Device public keys are opt-in: the default (no-flag) convenience calls must not return them
        final String activationId = config.getActivationId(version);
        final String userId = config.getUser(version);
        final String applicationId = config.getApplicationId();

        assertDeviceKeysEmpty(powerAuthClient.getActivationStatusWithoutBlob(activationId).getDevicePublicKeys());
        assertDeviceKeysEmpty(findActivation(powerAuthClient.getActivationListForUser(userId), activationId).getDevicePublicKeys());
        final List<Activation> defaultLookup = powerAuthClient.lookupActivations(List.of(userId), List.of(applicationId), null, null, ActivationStatus.ACTIVE, null);
        assertDeviceKeysEmpty(findActivation(defaultLookup, activationId).getDevicePublicKeys());

        // With includeDevicePublicKeys=true the server returns the device public keys on all three surfaces.
        // On the status surface the keys must be returned regardless of whether the status blob is requested.
        final GetActivationStatusRequest statusRequestWithBlob = new GetActivationStatusRequest();
        statusRequestWithBlob.setActivationId(activationId);
        statusRequestWithBlob.setIncludeStatusBlob(true);
        statusRequestWithBlob.setIncludeDevicePublicKeys(true);
        final GetActivationStatusResponse statusResponseWithBlob = powerAuthClient.getActivationStatus(statusRequestWithBlob);
        assertServerDeviceKeysV4(statusResponseWithBlob.getDevicePublicKeys(), model, requestBytes, signatureEcBytes, signaturePqcBytes);

        // The activation fingerprint reported by the server must be reproducible from the returned device keys
        final String expectedFingerprint = statusResponseWithBlob.getDevicePublicKeyFingerprint();
        assertDeviceKeysFingerprintV4(statusResponseWithBlob.getDevicePublicKeys(), model, activationId, expectedFingerprint);
        final GetActivationStatusRequest statusRequestWithoutBlob = new GetActivationStatusRequest();
        statusRequestWithoutBlob.setActivationId(activationId);
        statusRequestWithoutBlob.setIncludeStatusBlob(false);
        statusRequestWithoutBlob.setIncludeDevicePublicKeys(true);
        final GetActivationStatusResponse statusResponseWithoutBlob = powerAuthClient.getActivationStatus(statusRequestWithoutBlob);
        assertServerDeviceKeysV4(statusResponseWithoutBlob.getDevicePublicKeys(), model, requestBytes, signatureEcBytes, signaturePqcBytes);
        assertDeviceKeysFingerprintV4(statusResponseWithoutBlob.getDevicePublicKeys(), model, activationId, expectedFingerprint);

        final GetActivationListForUserRequest listRequest = new GetActivationListForUserRequest();
        listRequest.setUserId(userId);
        listRequest.setIncludeDevicePublicKeys(true);
        final Activation listActivation = findActivation(powerAuthClient.getActivationListForUser(listRequest).getActivations(), activationId);
        assertServerDeviceKeysV4(listActivation.getDevicePublicKeys(), model, requestBytes, signatureEcBytes, signaturePqcBytes);
        assertDeviceKeysFingerprintV4(listActivation.getDevicePublicKeys(), model, activationId, expectedFingerprint);

        final LookupActivationsRequest lookupRequest = new LookupActivationsRequest();
        lookupRequest.setUserIds(List.of(userId));
        lookupRequest.setApplicationIds(List.of(applicationId));
        lookupRequest.setActivationStatus(ActivationStatus.ACTIVE);
        lookupRequest.setIncludeDevicePublicKeys(true);
        final Activation lookupActivation = findActivation(powerAuthClient.lookupActivations(lookupRequest).getActivations(), activationId);
        assertServerDeviceKeysV4(lookupActivation.getDevicePublicKeys(), model, requestBytes, signatureEcBytes, signaturePqcBytes);
        assertDeviceKeysFingerprintV4(lookupActivation.getDevicePublicKeys(), model, activationId, expectedFingerprint);

        // Negative check: a different device public key must not verify the signatures
        assertServerDeviceKeysRejectWrongKeyV4(requestBytes, signatureEcBytes, signaturePqcBytes);
    }

    private static void assertDeviceKeysEmpty(final Map<String, String> serverDeviceKeys) {
        assertTrue(serverDeviceKeys == null || serverDeviceKeys.isEmpty());
    }

    private static void assertServerDeviceKeysRejectWrongKeyV4(final byte[] requestBytes, final byte[] signatureEcBytes, final byte[] signaturePqcBytes) throws Exception {
        final PublicKey wrongEcPublicKey = KEY_GENERATOR.generateKeyPair(EcCurve.P384).getPublic();
        assertFalse(SIGNATURE_UTILS.validateECDSASignature(EcCurve.P384, requestBytes, signatureEcBytes, wrongEcPublicKey));

        final PublicKey wrongPqcPublicKey = PQC_DSA.generateKeyPair().getPublic();
        assertFalse(PQC_DSA.verify(wrongPqcPublicKey, requestBytes, signaturePqcBytes));
    }

    private static void assertServerDeviceKeysV4(final Map<String, String> serverDeviceKeys, final SignAsymmetricStepModel model, final byte[] requestBytes, final byte[] signatureEcBytes, final byte[] signaturePqcBytes) throws Exception {
        assertNotNull(serverDeviceKeys);
        assertEquals(2, serverDeviceKeys.size());

        // EC (ECDSA_P384): server key equals the client device key and verifies the EC signature
        final String ecServerKeyBase64 = serverDeviceKeys.get("ECDSA_P384");
        assertNotNull(ecServerKeyBase64);
        final byte[] ecServerKeyBytes = Base64.getDecoder().decode(ecServerKeyBase64);
        assertArrayEquals(Base64.getDecoder().decode(model.getResultStatus().getEcDevicePublicKey()), ecServerKeyBytes);
        final PublicKey ecServerPublicKey = KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P384, ecServerKeyBytes);
        assertTrue(SIGNATURE_UTILS.validateECDSASignature(EcCurve.P384, requestBytes, signatureEcBytes, ecServerPublicKey));

        // ML-DSA (MLDSA_65): server key equals the client device key and verifies the PQC signature
        final String pqcServerKeyBase64 = serverDeviceKeys.get("MLDSA_65");
        assertNotNull(pqcServerKeyBase64);
        final byte[] pqcServerKeyBytes = Base64.getDecoder().decode(pqcServerKeyBase64);
        assertArrayEquals(Base64.getDecoder().decode(model.getResultStatus().getPqcDevicePublicKey()), pqcServerKeyBytes);
        final PublicKey pqcServerPublicKey = KEY_CONVERTOR_PQC.convertBytesToPublicKey(pqcServerKeyBytes);
        assertTrue(PQC_DSA.verify(pqcServerPublicKey, requestBytes, signaturePqcBytes));
    }

    private static void assertDeviceKeysFingerprintV4(final Map<String, String> serverDeviceKeys, final SignAsymmetricStepModel model, final String activationId, final String expectedFingerprint) throws Exception {
        assertNotNull(expectedFingerprint);
        final ECPublicKey ecDevicePublicKey = (ECPublicKey) KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P384, Base64.getDecoder().decode(serverDeviceKeys.get("ECDSA_P384")));
        final MLDSAPublicKey pqcDevicePublicKey = (MLDSAPublicKey) KEY_CONVERTOR_PQC.convertBytesToPublicKey(Base64.getDecoder().decode(serverDeviceKeys.get("MLDSA_65")));
        // Server public keys are not part of the activation API, they are taken from the client activation state
        final ECPublicKey ecServerPublicKey = (ECPublicKey) model.getResultStatus().getEcServerPublicKeyObject();
        final MLDSAPublicKey pqcServerPublicKey = (MLDSAPublicKey) model.getResultStatus().getPqcServerPublicKeyObject();

        final String fingerprint = HybridPublicKeyFingerprint.computeHybridFingerprint(SharedSecretAlgorithm.EC_P384_ML_L3, ecDevicePublicKey, pqcDevicePublicKey, ecServerPublicKey, pqcServerPublicKey, activationId, ActivationVersion.VERSION_4);
        assertEquals(expectedFingerprint, fingerprint);
    }

    private static Activation findActivation(final List<Activation> activations, final String activationId) {
        final Activation activation = activations.stream()
                .filter(item -> activationId.equals(item.getActivationId()))
                .findAny()
                .orElse(null);
        assertNotNull(activation);
        return activation;
    }

    private static void checkAuthenticationError(ErrorResponse errorResponse) {
        assertEquals("ERR_AUTHENTICATION", errorResponse.getResponseObject().getCode());
    }

    private static void checkTemporaryKeyError(ErrorResponse errorResponse) {
        assertEquals("ERR_TEMPORARY_KEY", errorResponse.getResponseObject().getCode());
    }

    private static void checkSecureVaultError(ErrorResponse errorResponse) {
        assertEquals("ERR_SECURE_VAULT", errorResponse.getResponseObject().getCode());
    }

}
