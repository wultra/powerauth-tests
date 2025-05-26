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
import com.wultra.security.powerauth.client.model.response.v3.*;
import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.client.model.entity.SignatureAuditItem;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.v3.SignatureType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.v3.CreateTokenRequest;
import com.wultra.security.powerauth.client.model.request.v3.VaultUnlockRequest;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.config.AuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.ClientEciesSecrets;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.model.TemporaryKey;
import com.wultra.security.powerauth.test.shared.util.TemporaryKeyFetchUtil;
import com.wultra.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import com.wultra.security.powerauth.crypto.client.authentication.PowerAuthClientAuthentication;
import com.wultra.security.powerauth.crypto.client.token.ClientTokenGenerator;
import com.wultra.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.*;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.http.PowerAuthHttpBody;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.steps.model.BaseStepModel;
import com.wultra.security.powerauth.lib.cmd.util.*;
import com.wultra.security.powerauth.rest.api.model.entity.TokenResponsePayload;
import com.wultra.security.powerauth.rest.api.model.request.VaultUnlockRequestPayload;
import com.wultra.security.powerauth.rest.api.model.response.VaultUnlockResponsePayload;
import lombok.Data;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
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

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final PowerAuthClientAuthentication CLIENT_SIGNATURE = new PowerAuthClientAuthentication();
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
        String normalizedData = PowerAuthHttpBody.getAuthenticationBaseString("POST", "/pa/signature/validate", nonceBytes, data.getBytes(StandardCharsets.UTF_8));
        String normalizedDataWithSecret = normalizedData + "&" + config.getApplicationSecret();
        byte[] ctrData = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "ctrData"));
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "signatureKnowledgeKeyEncrypted"));
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getKnowledgeFactorKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, KEY_GENERATOR);
        SecretKey signaturePossessionKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        String signatureValue = CLIENT_SIGNATURE.computeAuthCode(normalizedDataWithSecret.getBytes(StandardCharsets.UTF_8), KEY_FACTORY.keysForAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE,
                signaturePossessionKey, signatureKnowledgeKey, null), ctrData, AuthenticationCodeConfiguration.base64());
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
        final PublicKey serverPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, serverPublicKeyBytes);
        final TemporaryKey temporaryKey = TemporaryKeyFetchUtil.fetchTemporaryKey(version, EncryptorScope.ACTIVATION_SCOPE, config);
        final ClientEncryptor<EciesEncryptedRequest, EciesEncryptedResponse> clientEncryptor = ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.VAULT_UNLOCK,
                new EncryptorParameters(version.value(), config.getApplicationKey(), config.getActivationId(version), temporaryKey != null ? temporaryKey.getId() : null),
                new ClientEciesSecrets(temporaryKey != null ? temporaryKey.getPublicKey() : serverPublicKey, config.getApplicationSecret(), transportMasterKeyBytes)
        );
        VaultUnlockRequestPayload requestPayload = new VaultUnlockRequestPayload();
        requestPayload.setReason("TEST");
        final byte[] requestBytesPayload = OBJECT_MAPPER.writeValueAsBytes(requestPayload);
        final EciesEncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(requestBytesPayload);
        EciesEncryptedRequest eciesRequest = new EciesEncryptedRequest();
        eciesRequest.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        eciesRequest.setEncryptedData(encryptedRequest.getEncryptedData());
        eciesRequest.setMac(encryptedRequest.getMac());
        eciesRequest.setNonce(encryptedRequest.getNonce());
        eciesRequest.setTimestamp(encryptedRequest.getTimestamp());
        eciesRequest.setTemporaryKeyId(temporaryKey != null ? temporaryKey.getId() : null);
        final byte[] requestBytes = OBJECT_MAPPER.writeValueAsBytes(eciesRequest);
        String normalizedData = PowerAuthHttpBody.getAuthenticationBaseString("POST", "/pa/signature/validate", nonceBytes, requestBytes);
        String normalizedDataWithSecret = normalizedData + "&" + config.getApplicationSecret();
        byte[] ctrData = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "ctrData"));
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "signatureKnowledgeKeyEncrypted"));
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getKnowledgeFactorKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, KEY_GENERATOR);
        SecretKey signaturePossessionKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        String signatureValue = CLIENT_SIGNATURE.computeAuthCode(normalizedDataWithSecret.getBytes(StandardCharsets.UTF_8), KEY_FACTORY.keysForAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE,
                signaturePossessionKey, signatureKnowledgeKey, null), ctrData, AuthenticationCodeConfiguration.base64());
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
        byte[] decryptedData = clientEncryptor.decryptResponse(new EciesEncryptedResponse(
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
        byte[] ecdsaSignature = SIGNATURE_UTILS.computeECDSASignature(EcCurve.P256, testData.getBytes(StandardCharsets.UTF_8), devicePrivateKey);
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

    // Activation flags are tested using PowerAuthActivationFlagsTest
    // Application roles are tested using PowerAuthApplicationRolesTest

    private static TokenInfo createToken(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws Exception {
        byte[] transportMasterKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "transportMasterKey"));
        byte[] serverPublicKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "serverPublicKey"));
        final PublicKey serverPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, serverPublicKeyBytes);
        final TemporaryKey temporaryKey = TemporaryKeyFetchUtil.fetchTemporaryKey(version, EncryptorScope.ACTIVATION_SCOPE, config);
        final ClientEncryptor<EciesEncryptedRequest, EciesEncryptedResponse> clientEncryptor = ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.CREATE_TOKEN,
                new EncryptorParameters(version.value(), config.getApplicationKey(), config.getActivationId(version), temporaryKey != null ? temporaryKey.getId() : null),
                new ClientEciesSecrets(temporaryKey != null ? temporaryKey.getPublicKey() :serverPublicKey, config.getApplicationSecret(), transportMasterKeyBytes)
        );
        final EciesEncryptedRequest encryptedRequest = clientEncryptor.encryptRequest("{}".getBytes(StandardCharsets.UTF_8));
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

        final byte[] decryptedData = clientEncryptor.decryptResponse(new EciesEncryptedResponse(
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