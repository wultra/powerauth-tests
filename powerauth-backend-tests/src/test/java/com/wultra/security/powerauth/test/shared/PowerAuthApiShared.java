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
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.client.token.ClientTokenGenerator;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.config.SignatureConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ClientEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.lib.cmd.steps.model.BaseStepModel;
import io.getlime.security.powerauth.lib.cmd.util.CounterUtil;
import io.getlime.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.lib.cmd.util.JsonUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
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

    public static void verifySignatureTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, String version) throws GenericCryptoException, CryptoProviderException, InvalidKeyException, PowerAuthClientException {
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
        VerifySignatureResponse signatureResponse = powerAuthClient.verifySignature(config.getActivationId(version), config.getApplicationKey(), normalizedData, signatureValue, SignatureType.POSSESSION_KNOWLEDGE, version, null);
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
                assertEquals(version, item.getSignatureVersion());
                assertEquals(ActivationStatus.ACTIVE, item.getActivationStatus());
                assertEquals(config.getApplicationId(), item.getApplicationId());
                assertEquals(config.getUser(version), item.getUserId());
                assertEquals(3, item.getVersion());
                signatureFound = true;
            }
        }
        assertTrue(signatureFound);
    }

    public static void unlockVaultAndECDSASignatureTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, String version) throws GenericCryptoException, CryptoProviderException, InvalidKeySpecException, EncryptorException, IOException, InvalidKeyException, PowerAuthClientException {
        byte[] transportMasterKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "transportMasterKey"));
        byte[] serverPublicKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "serverPublicKey"));
        byte[] encryptedDevicePrivateKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "encryptedDevicePrivateKey"));
        byte[] nonceBytes = KEY_GENERATOR.generateRandomBytes(16);
        final PublicKey serverPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(serverPublicKeyBytes);
        final ClientEncryptor clientEncryptor = ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.VAULT_UNLOCK,
                new EncryptorParameters(version, config.getApplicationKey(), config.getActivationId(version)),
                new ClientEncryptorSecrets(serverPublicKey, config.getApplicationSecret(), transportMasterKeyBytes)
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
        VaultUnlockResponse unlockResponse = powerAuthClient.unlockVault(config.getActivationId(version), config.getApplicationKey(), signatureValue, SignatureType.POSSESSION_KNOWLEDGE, version, normalizedData,
                eciesRequest.getEphemeralPublicKey(), eciesRequest.getEncryptedData(), eciesRequest.getMac(), eciesRequest.getNonce(), eciesRequest.getTimestamp());
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

    public static void createValidateAndRemoveTokenTestActiveActivation(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, String version) throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException, IOException, EncryptorException, PowerAuthClientException {
        final TokenInfo tokenInfo = createToken(powerAuthClient, config, version);

        // Check successful token validation and activation status
        final ValidateTokenResponse validateResponse = powerAuthClient.validateToken(tokenInfo.getTokenId(),
                Base64.getEncoder().encodeToString(tokenInfo.getTokenNonce()),
                version,
                Long.parseLong(new String(tokenInfo.getTokenTimestamp())),
                Base64.getEncoder().encodeToString(tokenInfo.getTokenDigest()));
        assertTrue(validateResponse.isTokenValid());
        assertEquals(ActivationStatus.ACTIVE, validateResponse.getActivationStatus());
        assertNull(validateResponse.getBlockedReason());

        RemoveTokenResponse removeResponse = powerAuthClient.removeToken(tokenInfo.getTokenId(), config.getActivationId(version));
        assertTrue(removeResponse.isRemoved());
    }

    public static void recoveryCodeConfirmAndActivationTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, String version) throws CryptoProviderException, GenericCryptoException, IOException, EncryptorException, InvalidKeyException, InvalidKeySpecException, PowerAuthClientException {
        String activationName = "test_create_recovery";
        KeyPair deviceKeyPair = CLIENT_ACTIVATION.generateDeviceKeyPair();
        byte[] devicePublicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(deviceKeyPair.getPublic());
        String devicePublicKeyBase64 = Base64.getEncoder().encodeToString(devicePublicKeyBytes);
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(activationName);
        requestL2.setDevicePublicKey(devicePublicKeyBase64);
        ClientEncryptor clientEncryptorL2 = ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters(version, config.getApplicationKey(), null),
                new ClientEncryptorSecrets(config.getMasterPublicKey(), config.getApplicationSecret())
        );
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        OBJECT_MAPPER.writeValue(baosL2, requestL2);
        EncryptedRequest encryptedRequestL2 = clientEncryptorL2.encryptRequest(baosL2.toByteArray());
        CreateActivationResponse createResponse = powerAuthClient.createActivation(config.getUser(version), null,
                null, config.getApplicationKey(), encryptedRequestL2.getEphemeralPublicKey(),
                encryptedRequestL2.getEncryptedData(), encryptedRequestL2.getMac(), encryptedRequestL2.getNonce(), version, encryptedRequestL2.getTimestamp());
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
        ClientEncryptor encryptorConfirmRC = ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.CONFIRM_RECOVERY_CODE,
                new EncryptorParameters(version, config.getApplicationKey(), activationId),
                new ClientEncryptorSecrets(serverPublicKey, config.getApplicationSecret(), transportMasterKeyBytes)
        );
        ConfirmRecoveryRequestPayload confirmRequestPayload = new ConfirmRecoveryRequestPayload();
        confirmRequestPayload.setRecoveryCode(recoveryCode);

        EncryptedRequest encryptedRequestConfirm = encryptorConfirmRC.encryptRequest(OBJECT_MAPPER.writeValueAsBytes(confirmRequestPayload));
        ConfirmRecoveryCodeResponse confirmResponse = powerAuthClient.confirmRecoveryCode(activationId, config.getApplicationKey(), encryptedRequestConfirm.getEphemeralPublicKey(),
                encryptedRequestConfirm.getEncryptedData(), encryptedRequestConfirm.getMac(), encryptedRequestConfirm.getNonce(), version, encryptedRequestConfirm.getTimestamp());
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
        RecoveryCodeActivationResponse createResponseR = powerAuthClient.createActivationUsingRecoveryCode(recoveryCode, recoveryPuk,
                config.getApplicationKey(), null, encryptedRequestL2R.getEphemeralPublicKey(),
                encryptedRequestL2R.getEncryptedData(), encryptedRequestL2R.getMac(), encryptedRequestL2R.getNonce(), version, encryptedRequestL2R.getTimestamp());
        String activationIdNew = createResponseR.getActivationId();
        GetActivationStatusResponse statusResponseR1 = powerAuthClient.getActivationStatus(activationIdNew);
        assertEquals(ActivationStatus.PENDING_COMMIT, statusResponseR1.getActivationStatus());
        CommitActivationResponse commitResponseR = powerAuthClient.commitActivation(activationIdNew, config.getUser(version));
        assertTrue(commitResponseR.isActivated());
        GetActivationStatusResponse statusResponseR2 = powerAuthClient.getActivationStatus(activationIdNew);
        assertEquals(ActivationStatus.ACTIVE, statusResponseR2.getActivationStatus());
        GetActivationStatusResponse statusResponseR3 = powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.REMOVED, statusResponseR3.getActivationStatus());
    }

    // Activation flags are tested using PowerAuthActivationFlagsTest
    // Application roles are tested using PowerAuthApplicationRolesTest

    private static TokenInfo createToken(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, String version) throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException, IOException, EncryptorException, PowerAuthClientException {
        byte[] transportMasterKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "transportMasterKey"));
        byte[] serverPublicKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "serverPublicKey"));
        final PublicKey serverPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(serverPublicKeyBytes);
        final ClientEncryptor clientEncryptor = ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.CREATE_TOKEN,
                new EncryptorParameters(version, config.getApplicationKey(), config.getActivationId(version)),
                new ClientEncryptorSecrets(serverPublicKey, config.getApplicationSecret(), transportMasterKeyBytes)
        );
        final EncryptedRequest encryptedRequest = clientEncryptor.encryptRequest("{}".getBytes(StandardCharsets.UTF_8));
        final CreateTokenResponse tokenResponse = powerAuthClient.createToken(config.getActivationId(version), config.getApplicationKey(), encryptedRequest.getEphemeralPublicKey(), encryptedRequest.getEncryptedData(),
                encryptedRequest.getMac(), encryptedRequest.getNonce(), version, encryptedRequest.getTimestamp(), SignatureType.POSSESSION_KNOWLEDGE);

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
                version,
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