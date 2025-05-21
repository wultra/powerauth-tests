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
import com.wultra.security.powerauth.client.model.entity.SignatureAuditItem;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.model.TemporaryKey;
import com.wultra.security.powerauth.test.shared.util.TemporaryKeyFetchUtil;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.client.token.ClientTokenGenerator;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.config.SignatureConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.*;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ClientEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.steps.model.BaseStepModel;
import io.getlime.security.powerauth.lib.cmd.util.*;
import io.getlime.security.powerauth.rest.api.model.entity.TokenResponsePayload;
import io.getlime.security.powerauth.rest.api.model.request.ActivationLayer2Request;
import io.getlime.security.powerauth.rest.api.model.request.ConfirmRecoveryRequestPayload;
import io.getlime.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.request.VaultUnlockRequestPayload;
import io.getlime.security.powerauth.rest.api.model.response.ActivationLayer2Response;
import io.getlime.security.powerauth.rest.api.model.response.ConfirmRecoveryResponsePayload;
import io.getlime.security.powerauth.rest.api.model.response.VaultUnlockResponsePayload;
import lombok.Data;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth server API test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthApiShared {

    private static final PowerAuthClientActivation CLIENT_ACTIVATION = new PowerAuthClientActivation();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final PowerAuthClientSignature CLIENT_SIGNATURE = new PowerAuthClientSignature();
    private static final PowerAuthClientVault CLIENT_VAULT = new PowerAuthClientVault();
    private static final PowerAuthClientKeyFactory KEY_FACTORY = new PowerAuthClientKeyFactory();
    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();
    private static final ClientTokenGenerator CLIENT_TOKEN_GENERATOR = new ClientTokenGenerator();

    private static final int TIME_SYNCHRONIZATION_WINDOW_SECONDS = 60;

    public static void verifySignatureTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws GenericCryptoException, CryptoProviderException, InvalidKeyException, PowerAuthClientException {
        Calendar before = new GregorianCalendar();
        before.add(Calendar.SECOND, -TIME_SYNCHRONIZATION_WINDOW_SECONDS);
        byte[] nonceBytes = KEY_GENERATOR.generateRandomBytes(16);
        String data = "test_data";
        String normalizedData = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/signature/validate", nonceBytes, data.getBytes(StandardCharsets.UTF_8));
        String normalizedDataWithSecret = normalizedData + "&" + config.getApplicationSecret();
        byte[] ctrData = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "ctrData"));
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "signatureKnowledgeKeyEncrypted"));
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, KEY_GENERATOR);
        SecretKey signaturePossessionKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        String signatureValue = CLIENT_SIGNATURE.signatureForData(normalizedDataWithSecret.getBytes(StandardCharsets.UTF_8), KEY_FACTORY.keysForSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
                signaturePossessionKey, signatureKnowledgeKey, null), ctrData, SignatureConfiguration.base64());
        VerifySignatureResponse signatureResponse = powerAuthClient.verifySignature(config.getActivationId(version), config.getApplicationKey(), normalizedData, signatureValue, SignatureType.POSSESSION_KNOWLEDGE, version.value(), null);
        assertTrue(signatureResponse.isSignatureValid());
        BaseStepModel model = new BaseStepModel();
        model.setResultStatusObject(config.getResultStatusObject(version));
        CounterUtil.incrementCounter(model);
        Calendar after = new GregorianCalendar();
        after.add(Calendar.SECOND, TIME_SYNCHRONIZATION_WINDOW_SECONDS);
        List<SignatureAuditItem> auditItems = powerAuthClient.getSignatureAuditLog(config.getUser(version), config.getApplicationId(), before.getTime(), after.getTime());
        boolean signatureFound = false;
        for (SignatureAuditItem item : auditItems) {
            if (signatureValue.equals(item.getSignature())) {
                assertEquals(config.getActivationId(version), item.getActivationId());
                assertEquals(normalizedDataWithSecret, new String(Base64.getDecoder().decode(item.getDataBase64())));
                assertEquals(SignatureType.POSSESSION_KNOWLEDGE, item.getSignatureType());
                assertEquals(version.value(), item.getSignatureVersion());
                assertEquals(ActivationStatus.ACTIVE, item.getActivationStatus());
                assertEquals(config.getApplicationId(), item.getApplicationId());
                assertEquals(config.getUser(version), item.getUserId());
                assertEquals(3, item.getVersion());
                signatureFound = true;
            }
        }
        assertTrue(signatureFound);
    }

    public static void unlockVaultAndECDSASignatureTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws Exception {
        byte[] transportMasterKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "transportMasterKey"));
        byte[] serverPublicKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "serverPublicKey"));
        byte[] encryptedDevicePrivateKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "encryptedDevicePrivateKey"));
        byte[] nonceBytes = KEY_GENERATOR.generateRandomBytes(16);
        final PublicKey serverPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(serverPublicKeyBytes);
        final TemporaryKey temporaryKey = TemporaryKeyFetchUtil.fetchTemporaryKey(version, EncryptorScope.ACTIVATION_SCOPE, config);
        final ClientEncryptor clientEncryptor = ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.VAULT_UNLOCK,
                new EncryptorParameters(version.value(), config.getApplicationKey(), config.getActivationId(version), temporaryKey != null ? temporaryKey.getId() : null),
                new ClientEncryptorSecrets(temporaryKey != null ? temporaryKey.getPublicKey() : serverPublicKey, config.getApplicationSecret(), transportMasterKeyBytes)
        );
        VaultUnlockRequestPayload requestPayload = new VaultUnlockRequestPayload();
        requestPayload.setReason("TEST");
        final byte[] requestBytesPayload = OBJECT_MAPPER.writeValueAsBytes(requestPayload);
        final EncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(requestBytesPayload);
        EciesEncryptedRequest eciesRequest = new EciesEncryptedRequest();
        eciesRequest.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        eciesRequest.setEncryptedData(encryptedRequest.getEncryptedData());
        eciesRequest.setMac(encryptedRequest.getMac());
        eciesRequest.setNonce(encryptedRequest.getNonce());
        eciesRequest.setTimestamp(encryptedRequest.getTimestamp());
        eciesRequest.setTemporaryKeyId(temporaryKey != null ? temporaryKey.getId() : null);
        final byte[] requestBytes = OBJECT_MAPPER.writeValueAsBytes(eciesRequest);
        String normalizedData = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/signature/validate", nonceBytes, requestBytes);
        String normalizedDataWithSecret = normalizedData + "&" + config.getApplicationSecret();
        byte[] ctrData = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "ctrData"));
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "signatureKnowledgeKeyEncrypted"));
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, KEY_GENERATOR);
        SecretKey signaturePossessionKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        String signatureValue = CLIENT_SIGNATURE.signatureForData(normalizedDataWithSecret.getBytes(StandardCharsets.UTF_8), KEY_FACTORY.keysForSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
                signaturePossessionKey, signatureKnowledgeKey, null), ctrData, SignatureConfiguration.base64());
        final VaultUnlockRequest unlockRequest = new VaultUnlockRequest();
        unlockRequest.setActivationId(config.getActivationId(version));
        unlockRequest.setApplicationKey(config.getApplicationKey());
        unlockRequest.setSignature(signatureValue);
        unlockRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        unlockRequest.setSignatureVersion(version.value());
        unlockRequest.setSignedData(normalizedData);
        unlockRequest.setEphemeralPublicKey(eciesRequest.getEphemeralPublicKey());
        unlockRequest.setEncryptedData(encryptedRequest.getEncryptedData());
        unlockRequest.setMac(eciesRequest.getMac());
        unlockRequest.setNonce(eciesRequest.getNonce());
        unlockRequest.setTimestamp(eciesRequest.getTimestamp());
        unlockRequest.setTemporaryKeyId(eciesRequest.getTemporaryKeyId());
        VaultUnlockResponse unlockResponse = powerAuthClient.unlockVault(unlockRequest);
        assertTrue(unlockResponse.isSignatureValid());
        byte[] decryptedData = clientEncryptor.decryptResponse(new EncryptedResponse(
                unlockResponse.getEncryptedData(),
                unlockResponse.getMac(),
                unlockResponse.getNonce(),
                unlockResponse.getTimestamp()
        ));
        VaultUnlockResponsePayload response = OBJECT_MAPPER.readValue(decryptedData, VaultUnlockResponsePayload.class);
        assertNotNull(response.getEncryptedVaultEncryptionKey());
        byte[] encryptedVaultEncryptionKey = Base64.getDecoder().decode(response.getEncryptedVaultEncryptionKey());
        SecretKey transportMasterKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(transportMasterKeyBytes);
        SecretKey vaultEncryptionKey = CLIENT_VAULT.decryptVaultEncryptionKey(encryptedVaultEncryptionKey, transportMasterKey);
        PrivateKey devicePrivateKey = CLIENT_VAULT.decryptDevicePrivateKey(encryptedDevicePrivateKeyBytes, vaultEncryptionKey);
        assertNotNull(devicePrivateKey);
        BaseStepModel model = new BaseStepModel();
        model.setResultStatusObject(config.getResultStatusObject(version));
        CounterUtil.incrementCounter(model);
        String testData = "test_data";
        byte[] ecdsaSignature = SIGNATURE_UTILS.computeECDSASignature(testData.getBytes(StandardCharsets.UTF_8), devicePrivateKey);
        VerifyECDSASignatureResponse ecdsaResponse = powerAuthClient.verifyECDSASignature(config.getActivationId(version),
                Base64.getEncoder().encodeToString(testData.getBytes(StandardCharsets.UTF_8)), Base64.getEncoder().encodeToString(ecdsaSignature));
        assertTrue(ecdsaResponse.isSignatureValid());
    }

    // createApplication and createApplication version tests are skipped to avoid creating too many applications

    public static void createValidateAndRemoveTokenTestActiveActivation(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws Exception {
        final TokenInfo tokenInfo = createToken(powerAuthClient, config, version);

        // Check successful token validation and activation status
        final ValidateTokenResponse validateResponse = powerAuthClient.validateToken(tokenInfo.getTokenId(),
                Base64.getEncoder().encodeToString(tokenInfo.getTokenNonce()),
                version.value(),
                Long.parseLong(new String(tokenInfo.getTokenTimestamp())),
                Base64.getEncoder().encodeToString(tokenInfo.getTokenDigest()));
        assertTrue(validateResponse.isTokenValid());
        assertEquals(ActivationStatus.ACTIVE, validateResponse.getActivationStatus());
        assertNull(validateResponse.getBlockedReason());

        RemoveTokenResponse removeResponse = powerAuthClient.removeToken(tokenInfo.getTokenId(), config.getActivationId(version));
        assertTrue(removeResponse.isRemoved());
    }

    public static void recoveryCodeConfirmAndActivationTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws Exception {
        String activationName = "test_create_recovery";
        KeyPair deviceKeyPair = CLIENT_ACTIVATION.generateDeviceKeyPair();
        byte[] devicePublicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(deviceKeyPair.getPublic());
        String devicePublicKeyBase64 = Base64.getEncoder().encodeToString(devicePublicKeyBytes);
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(activationName);
        requestL2.setDevicePublicKey(devicePublicKeyBase64);
        final TemporaryKey temporaryKey = TemporaryKeyFetchUtil.fetchTemporaryKey(version, EncryptorScope.APPLICATION_SCOPE, config);
        ClientEncryptor clientEncryptorL2 = ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters(version.value(), config.getApplicationKey(), null, temporaryKey != null ? temporaryKey.getId() : null),
                new ClientEncryptorSecrets(temporaryKey != null ? temporaryKey.getPublicKey() : config.getMasterPublicKey(), config.getApplicationSecret())
        );
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        OBJECT_MAPPER.writeValue(baosL2, requestL2);
        EncryptedRequest encryptedRequestL2 = clientEncryptorL2.encryptRequest(baosL2.toByteArray());
        final CreateActivationRequest activationRequest = new CreateActivationRequest();
        activationRequest.setUserId(config.getUser(version));
        activationRequest.setApplicationKey(config.getApplicationKey());
        activationRequest.setEphemeralPublicKey(encryptedRequestL2.getEphemeralPublicKey());
        activationRequest.setEncryptedData(encryptedRequestL2.getEncryptedData());
        activationRequest.setMac(encryptedRequestL2.getMac());
        activationRequest.setNonce(encryptedRequestL2.getNonce());
        activationRequest.setTimestamp(encryptedRequestL2.getTimestamp());
        activationRequest.setTemporaryKeyId(encryptedRequestL2.getTemporaryKeyId());
        activationRequest.setProtocolVersion(version.value());
        activationRequest.setGenerateRecoveryCodes(true);
        CreateActivationResponse createResponse = powerAuthClient.createActivation(activationRequest);
        String activationId = createResponse.getActivationId();
        assertNotNull(activationId);
        byte[] responseRaw = clientEncryptorL2.decryptResponse(new EncryptedResponse(
                createResponse.getEncryptedData(),
                createResponse.getMac(),
                createResponse.getNonce(),
                createResponse.getTimestamp()
        ));
        ActivationLayer2Response responseL2 = OBJECT_MAPPER.readValue(responseRaw, ActivationLayer2Response.class);
        String recoveryCode = responseL2.getActivationRecovery().getRecoveryCode();
        String recoveryPuk = responseL2.getActivationRecovery().getPuk();
        PublicKey serverPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(Base64.getDecoder().decode(responseL2.getServerPublicKey()));
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.PENDING_COMMIT, statusResponse.getActivationStatus());
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(activationId, config.getUser(version));
        assertTrue(commitResponse.isActivated());
        SecretKey masterSecretKey = KEY_FACTORY.generateClientMasterSecretKey(deviceKeyPair.getPrivate(), serverPublicKey);
        SecretKey transportMasterKey = KEY_FACTORY.generateServerTransportKey(masterSecretKey);
        byte[] transportMasterKeyBytes = KEY_CONVERTOR.convertSharedSecretKeyToBytes(transportMasterKey);
        // Confirm recovery code
        final String activationIdOrig = config.getActivationId(version);
        final String transportMasterKeyOrig = (String) config.getResultStatusObject(version).get("transportMasterKey");
        final String serverPublicKeyOrig = (String) config.getResultStatusObject(version).get("serverPublicKey");
        try {
            config.setActivationId(activationId, version);
            config.getResultStatusObject(version).put("transportMasterKey", Base64.getEncoder().encodeToString(transportMasterKeyBytes));
            config.getResultStatusObject(version).put("serverPublicKey", responseL2.getServerPublicKey());
            final TemporaryKey temporaryKey2 = TemporaryKeyFetchUtil.fetchTemporaryKey(version, EncryptorScope.ACTIVATION_SCOPE, config);
            System.out.println(temporaryKey2);
            System.out.println(temporaryKey2.getId());
            System.out.println(new EncryptorParameters(version.value(), config.getApplicationKey(), activationId, temporaryKey2 != null ? temporaryKey2.getId() : null));
            ClientEncryptor encryptorConfirmRC = ENCRYPTOR_FACTORY.getClientEncryptor(
                    EncryptorId.CONFIRM_RECOVERY_CODE,
                    new EncryptorParameters(version.value(), config.getApplicationKey(), activationId, temporaryKey2 != null ? temporaryKey2.getId() : null),
                    new ClientEncryptorSecrets(temporaryKey2 != null ? temporaryKey2.getPublicKey() : serverPublicKey, config.getApplicationSecret(), transportMasterKeyBytes)
            );
            ConfirmRecoveryRequestPayload confirmRequestPayload = new ConfirmRecoveryRequestPayload();
            confirmRequestPayload.setRecoveryCode(recoveryCode);

            EncryptedRequest encryptedRequestConfirm = encryptorConfirmRC.encryptRequest(OBJECT_MAPPER.writeValueAsBytes(confirmRequestPayload));
            final ConfirmRecoveryCodeRequest confirmRequest = new ConfirmRecoveryCodeRequest();
            confirmRequest.setActivationId(activationId);
            confirmRequest.setApplicationKey(config.getApplicationKey());
            confirmRequest.setEphemeralPublicKey(encryptedRequestConfirm.getEphemeralPublicKey());
            confirmRequest.setEncryptedData(encryptedRequestConfirm.getEncryptedData());
            confirmRequest.setMac(encryptedRequestConfirm.getMac());
            confirmRequest.setNonce(encryptedRequestConfirm.getNonce());
            confirmRequest.setTimestamp(encryptedRequestConfirm.getTimestamp());
            confirmRequest.setTemporaryKeyId(encryptedRequestConfirm.getTemporaryKeyId());
            confirmRequest.setProtocolVersion(version.value());
            ConfirmRecoveryCodeResponse confirmResponse = powerAuthClient.confirmRecoveryCode(confirmRequest);
            byte[] confirmResponseRaw = encryptorConfirmRC.decryptResponse(new EncryptedResponse(
                    confirmResponse.getEncryptedData(),
                    confirmResponse.getMac(),
                    confirmResponse.getNonce(),
                    confirmResponse.getTimestamp()
            ));
            final ConfirmRecoveryResponsePayload confirmResponsePayload = RestClientConfiguration.defaultMapper().readValue(confirmResponseRaw, ConfirmRecoveryResponsePayload.class);
            assertTrue(confirmResponsePayload.isAlreadyConfirmed());
            // Create recovery activation
            KeyPair deviceKeyPairR = CLIENT_ACTIVATION.generateDeviceKeyPair();
            byte[] devicePublicKeyBytesR = KEY_CONVERTOR.convertPublicKeyToBytes(deviceKeyPairR.getPublic());
            String devicePublicKeyBase64R = Base64.getEncoder().encodeToString(devicePublicKeyBytesR);
            ActivationLayer2Request requestL2R = new ActivationLayer2Request();
            requestL2R.setActivationName(activationName + "_2");
            requestL2R.setDevicePublicKey(devicePublicKeyBase64R);
            // Note: we reuse clientEncryptorL2
            ByteArrayOutputStream baosL2R = new ByteArrayOutputStream();
            OBJECT_MAPPER.writeValue(baosL2R, requestL2R);
            clientEncryptorL2.encryptRequest(baosL2R.toByteArray());
            EncryptedRequest encryptedRequestL2R = clientEncryptorL2.encryptRequest(baosL2R.toByteArray());
            final RecoveryCodeActivationRequest activationRequestRecovery = new RecoveryCodeActivationRequest();
            activationRequestRecovery.setRecoveryCode(recoveryCode);
            activationRequestRecovery.setPuk(recoveryPuk);
            activationRequestRecovery.setApplicationKey(config.getApplicationKey());
            activationRequestRecovery.setEphemeralPublicKey(encryptedRequestL2R.getEphemeralPublicKey());
            activationRequestRecovery.setEncryptedData(encryptedRequestL2R.getEncryptedData());
            activationRequestRecovery.setMac(encryptedRequestL2R.getMac());
            activationRequestRecovery.setNonce(encryptedRequestL2R.getNonce());
            activationRequestRecovery.setTimestamp(encryptedRequestL2R.getTimestamp());
            activationRequestRecovery.setTemporaryKeyId(encryptedRequestL2R.getTemporaryKeyId());
            activationRequestRecovery.setProtocolVersion(version.value());
            RecoveryCodeActivationResponse createResponseR = powerAuthClient.createActivationUsingRecoveryCode(activationRequestRecovery);
            String activationIdNew = createResponseR.getActivationId();
            GetActivationStatusResponse statusResponseR1 = powerAuthClient.getActivationStatus(activationIdNew);
            assertEquals(ActivationStatus.PENDING_COMMIT, statusResponseR1.getActivationStatus());
            CommitActivationResponse commitResponseR = powerAuthClient.commitActivation(activationIdNew, config.getUser(version));
            assertTrue(commitResponseR.isActivated());
            GetActivationStatusResponse statusResponseR2 = powerAuthClient.getActivationStatus(activationIdNew);
            assertEquals(ActivationStatus.ACTIVE, statusResponseR2.getActivationStatus());
            GetActivationStatusResponse statusResponseR3 = powerAuthClient.getActivationStatus(activationId);
            assertEquals(ActivationStatus.REMOVED, statusResponseR3.getActivationStatus());
        } finally {
            config.setActivationId(activationIdOrig, version);
            config.getResultStatusObject(version).put("transportMasterKey", transportMasterKeyOrig);
            config.getResultStatusObject(version).put("serverPublicKey", serverPublicKeyOrig);
        }
    }

    // Activation flags are tested using PowerAuthActivationFlagsTest
    // Application roles are tested using PowerAuthApplicationRolesTest

    private static TokenInfo createToken(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws Exception {
        byte[] transportMasterKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "transportMasterKey"));
        byte[] serverPublicKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "serverPublicKey"));
        final PublicKey serverPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(serverPublicKeyBytes);
        final TemporaryKey temporaryKey = TemporaryKeyFetchUtil.fetchTemporaryKey(version, EncryptorScope.ACTIVATION_SCOPE, config);
        final ClientEncryptor clientEncryptor = ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.CREATE_TOKEN,
                new EncryptorParameters(version.value(), config.getApplicationKey(), config.getActivationId(version), temporaryKey != null ? temporaryKey.getId() : null),
                new ClientEncryptorSecrets(temporaryKey != null ? temporaryKey.getPublicKey() :serverPublicKey, config.getApplicationSecret(), transportMasterKeyBytes)
        );
        final EncryptedRequest encryptedRequest = clientEncryptor.encryptRequest("{}".getBytes(StandardCharsets.UTF_8));
        final CreateTokenRequest tokenRequest = new CreateTokenRequest();
        tokenRequest.setActivationId(config.getActivationId(version));
        tokenRequest.setApplicationKey(config.getApplicationKey());
        tokenRequest.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        tokenRequest.setEncryptedData(encryptedRequest.getEncryptedData());
        tokenRequest.setMac(encryptedRequest.getMac());
        tokenRequest.setNonce(encryptedRequest.getNonce());
        tokenRequest.setProtocolVersion(version.value());
        tokenRequest.setTimestamp(encryptedRequest.getTimestamp());
        tokenRequest.setTemporaryKeyId(encryptedRequest.getTemporaryKeyId());
        tokenRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        final CreateTokenResponse tokenResponse = powerAuthClient.createToken(tokenRequest);

        final byte[] decryptedData = clientEncryptor.decryptResponse(new EncryptedResponse(
                tokenResponse.getEncryptedData(),
                tokenResponse.getMac(),
                tokenResponse.getNonce(),
                tokenResponse.getTimestamp()
        ));
        final TokenResponsePayload response = OBJECT_MAPPER.readValue(decryptedData, TokenResponsePayload.class);
        assertNotNull(response.getTokenId());
        assertNotNull(response.getTokenSecret());
        final BaseStepModel model = new BaseStepModel();
        model.setResultStatusObject(config.getResultStatusObject(version));
        CounterUtil.incrementCounter(model);
        final TokenInfo tokenInfo = new TokenInfo();
        tokenInfo.setTokenId(response.getTokenId());
        tokenInfo.setTokenSecret(response.getTokenSecret());
        tokenInfo.setTokenNonce(CLIENT_TOKEN_GENERATOR.generateTokenNonce());
        tokenInfo.setTokenTimestamp(CLIENT_TOKEN_GENERATOR.generateTokenTimestamp());
        tokenInfo.setTokenDigest(CLIENT_TOKEN_GENERATOR.computeTokenDigest(
                tokenInfo.getTokenNonce(),
                tokenInfo.getTokenTimestamp(),
                version.value(),
                Base64.getDecoder().decode(response.getTokenSecret())));
        return tokenInfo;
    }

    @Data
    private static final class TokenInfo {
        private String tokenId;
        private String tokenSecret;
        private byte[] tokenNonce;
        private byte[] tokenTimestamp;
        private byte[] tokenDigest;
    }
}