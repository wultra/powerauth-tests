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
package com.wultra.security.powerauth.test.shared.v4;

import com.wultra.security.powerauth.client.model.entity.SignatureAuditItem;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.v4.AsymmetricSignatureFormat;
import com.wultra.security.powerauth.client.model.enumeration.v4.AsymmetricSignatureType;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.v4.VaultUnlockRequest;
import com.wultra.security.powerauth.client.model.request.v4.CreateTokenRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyAsymmetricSignatureRequest;
import com.wultra.security.powerauth.client.model.response.RemoveTokenResponse;
import com.wultra.security.powerauth.client.model.response.v4.*;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.client.v4.token.ClientTokenGenerator;
import com.wultra.security.powerauth.crypto.client.v4.authentication.PowerAuthClientAuthentication;
import com.wultra.security.powerauth.crypto.client.v4.keyfactory.PowerAuthClientKeyFactory;
import com.wultra.security.powerauth.crypto.client.v4.vault.PowerAuthClientVault;
import com.wultra.security.powerauth.crypto.lib.config.AuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsa;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.context.AeadSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsa;
import com.wultra.security.powerauth.http.PowerAuthHttpBody;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.steps.model.BaseStepModel;
import com.wultra.security.powerauth.lib.cmd.util.CounterUtil;
import com.wultra.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import com.wultra.security.powerauth.lib.cmd.util.JsonUtil;
import com.wultra.security.powerauth.model.v4.TemporaryKey;
import com.wultra.security.powerauth.rest.api.model.entity.TokenResponsePayload;
import com.wultra.security.powerauth.rest.api.model.request.v4.VaultUnlockRequestPayload;
import com.wultra.security.powerauth.rest.api.model.response.v4.VaultUnlockResponsePayload;
import com.wultra.security.powerauth.test.shared.v4.util.TemporaryKeyFetchUtil;
import lombok.Data;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import tools.jackson.databind.ObjectMapper;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * PowerAuth server API test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthApiShared {

    private static final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();
    private static final PowerAuthClientAuthentication CLIENT_SIGNATURE = new PowerAuthClientAuthentication();
    private static final PowerAuthClientVault CLIENT_VAULT = new PowerAuthClientVault();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final PowerAuthClientAuthentication CLIENT_AUTHENTICATION = new PowerAuthClientAuthentication();
    private static final PowerAuthClientKeyFactory KEY_FACTORY = new PowerAuthClientKeyFactory();
    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();
    private static final ClientTokenGenerator CLIENT_TOKEN_GENERATOR = new ClientTokenGenerator();
    private static final PqcDsa PQC_DSA;

    private static final int TIME_SYNCHRONIZATION_WINDOW_SECONDS = 60;

    static {
        try {
            PQC_DSA = new MlDsa(MLDSAParameterSpec.ml_dsa_65);
        } catch (GenericCryptoException e) {
            throw new RuntimeException(e);
        }
    }

    public static void verifyAuthenticationTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws GenericCryptoException, CryptoProviderException, InvalidKeyException, PowerAuthClientException {
        Calendar before = new GregorianCalendar();
        before.add(Calendar.SECOND, -TIME_SYNCHRONIZATION_WINDOW_SECONDS);
        byte[] nonceBytes = KEY_GENERATOR.generateRandomBytes(16);
        String data = "test_data";
        String normalizedData = PowerAuthHttpBody.getAuthenticationBaseString("POST", "/pa/auth/validate", nonceBytes, data.getBytes(StandardCharsets.UTF_8));
        String normalizedDataWithSecret = normalizedData + "&" + config.getApplicationSecret();
        byte[] ctrData = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "ctrData"));
        byte[] possessionKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "possessionFactorKey"));
        byte[] knowledgeKeySalt = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "knowledgeFactorKeySalt"));
        byte[] knowledgeKeyEncryptedBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "knowledgeFactorKeyEncrypted"));
        SecretKey knowledgeKey = EncryptedStorageUtil.getKnowledgeFactorKey(config.getPassword().toCharArray(), knowledgeKeyEncryptedBytes, knowledgeKeySalt, KEY_GENERATOR);
        SecretKey possessionKey = KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(possessionKeyBytes);
        String authCodeValue = CLIENT_AUTHENTICATION.computeAuthCode(normalizedDataWithSecret.getBytes(StandardCharsets.UTF_8), KEY_FACTORY.keysForAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE,
                possessionKey, knowledgeKey, null), ctrData, AuthenticationCodeConfiguration.base64());
        VerifyAuthenticationResponse signatureResponse = powerAuthClient.verifyAuthentication(config.getActivationId(version), config.getApplicationKey(), normalizedData, authCodeValue, AuthenticationCodeType.POSSESSION_KNOWLEDGE, version.value());
        assertTrue(signatureResponse.isAuthenticationValid());
        BaseStepModel model = new BaseStepModel();
        model.setResultStatusObject(config.getResultStatusObject(version));
        CounterUtil.incrementCounter(model.getResultStatus());
        Calendar after = new GregorianCalendar();
        after.add(Calendar.SECOND, TIME_SYNCHRONIZATION_WINDOW_SECONDS);
        List<SignatureAuditItem> auditItems = powerAuthClient.getSignatureAuditLog(config.getUser(version), config.getApplicationId(), before.getTime(), after.getTime());
        boolean signatureFound = auditItems.stream()
                .filter(item -> authCodeValue.equals(item.getSignature()))
                .peek(item -> verifyAuditItem(item, version, config, normalizedDataWithSecret))
                .findFirst()
                .isPresent();
        assertTrue(signatureFound);
    }

    public static void unlockVaultAndECDSASignatureTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws Exception {
        final BaseStepModel model = new BaseStepModel();
        model.setResultStatusObject(config.getResultStatusObject(version));
        final TemporaryKey temporaryKey = TemporaryKeyFetchUtil.fetchTemporaryKey(version, EncryptorScope.ACTIVATION_SCOPE, config);
        assertNotNull(temporaryKey);
        final ClientEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> clientEncryptor = ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.VAULT_UNLOCK,
                new EncryptorParameters(version.value(), config.getApplicationKey(), config.getActivationId(version), temporaryKey.getId()),
                new AeadSecrets(temporaryKey.getSharedSecret().getEncoded(), config.getApplicationSecret(), Base64.getDecoder().decode(model.getResultStatus().getSharedInfo2Key()))
        );
        final byte[] nonceBytes = KEY_GENERATOR.generateRandomBytes(16);
        final VaultUnlockRequestPayload requestPayload = new VaultUnlockRequestPayload();
        requestPayload.setReason("TEST");
        requestPayload.setKeyIdentifier("KEK_DEVICE_PRIVATE");
        final byte[] requestBytesPayload = OBJECT_MAPPER.writeValueAsBytes(requestPayload);
        final AeadEncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(requestBytesPayload);
        final byte[] requestBytes = OBJECT_MAPPER.writeValueAsBytes(encryptedRequest);
        final String normalizedData = PowerAuthHttpBody.getAuthenticationBaseString("POST", "/pa/signature/validate", nonceBytes, requestBytes);
        final String normalizedDataWithSecret = normalizedData + "&" + config.getApplicationSecret();
        final byte[] ctrData = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "ctrData"));
        final byte[] signatureKnowledgeKeySalt = model.getResultStatus().getKnowledgeFactorKeySaltBytes();
        final byte[] signatureKnowledgeKeyEncryptedBytes = model.getResultStatus().getKnowledgeFactorKeyEncryptedBytes();
        final SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getKnowledgeFactorKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, KEY_GENERATOR);
        final SecretKey signaturePossessionKey = model.getResultStatus().getPossessionFactorKeyObject();
        final String authCode = CLIENT_SIGNATURE.computeAuthCode(normalizedDataWithSecret.getBytes(StandardCharsets.UTF_8), KEY_FACTORY.keysForAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE,
                signaturePossessionKey, signatureKnowledgeKey, null), ctrData, AuthenticationCodeConfiguration.base64());
        final VaultUnlockRequest unlockRequest = new VaultUnlockRequest();
        unlockRequest.setActivationId(config.getActivationId(version));
        unlockRequest.setApplicationKey(config.getApplicationKey());
        unlockRequest.setAuthenticationCode(authCode);
        unlockRequest.setAuthenticationCodeType(AuthenticationCodeType.POSSESSION_KNOWLEDGE);
        unlockRequest.setAuthenticationVersion(version.value());
        unlockRequest.setRequestData(normalizedData);
        unlockRequest.setEncryptedData(encryptedRequest.getEncryptedData());
        unlockRequest.setNonce(encryptedRequest.getNonce());
        unlockRequest.setTimestamp(encryptedRequest.getTimestamp());
        unlockRequest.setTemporaryKeyId(encryptedRequest.getTemporaryKeyId());
        final VaultUnlockResponse unlockResponse = powerAuthClient.unlockVault(unlockRequest);
        assertTrue(unlockResponse.isAuthenticationValid());
        final byte[] decryptedData = clientEncryptor.decryptResponse(new AeadEncryptedResponse(
                unlockResponse.getEncryptedData(),
                unlockResponse.getTimestamp()
        ));
        final VaultUnlockResponsePayload response = OBJECT_MAPPER.readValue(decryptedData, VaultUnlockResponsePayload.class);
        assertNotNull(response.getVaultEncryptionKey());
        final byte[] vaultUnlockKekDevicePrivateBytes = Base64.getDecoder().decode(response.getVaultEncryptionKey());
        CounterUtil.incrementCounter(model.getResultStatus());
        final String testData = "test_data";

        final SecretKey vaultUnlockKekDevicePrivate = KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(vaultUnlockKekDevicePrivateBytes);
        final byte[] encryptedEcDevicePrivateKeyBytes = model.getResultStatus().getEncryptedEcDevicePrivateKeyBytes();
        final PrivateKey ecDevicePrivateKey = CLIENT_VAULT.decryptEcDevicePrivateKey(encryptedEcDevicePrivateKeyBytes, vaultUnlockKekDevicePrivate);
        final byte[] signatureEc = SIGNATURE_UTILS.computeECDSASignature(EcCurve.P384, testData.getBytes(StandardCharsets.UTF_8), ecDevicePrivateKey);
        final VerifyAsymmetricSignatureResponse ecdsaResponse = powerAuthClient.verifyAsymmetricSignature(config.getActivationId(version),
                Base64.getEncoder().encodeToString(testData.getBytes(StandardCharsets.UTF_8)), Base64.getEncoder().encodeToString(signatureEc));
        assertTrue(ecdsaResponse.isSignatureValid());

        final byte[] encryptedPqcDevicePrivateKeyBytes = model.getResultStatus().getEncryptedPqcDevicePrivateKeyBytes();
        final PrivateKey pqcDevicePrivateKey = CLIENT_VAULT.decryptPqcDevicePrivateKey(encryptedPqcDevicePrivateKeyBytes, vaultUnlockKekDevicePrivate);
        final byte[] signaturePqc = PQC_DSA.sign(pqcDevicePrivateKey, testData.getBytes(StandardCharsets.UTF_8));
        final VerifyAsymmetricSignatureRequest verifyPqcRequest = new VerifyAsymmetricSignatureRequest();
        verifyPqcRequest.setSignature(Base64.getEncoder().encodeToString(signaturePqc));
        verifyPqcRequest.setData(Base64.getEncoder().encodeToString(testData.getBytes(StandardCharsets.UTF_8)));
        verifyPqcRequest.setActivationId(config.getActivationId(version));
        verifyPqcRequest.setSignatureFormat(AsymmetricSignatureFormat.DER);
        verifyPqcRequest.setSignatureType(AsymmetricSignatureType.MLDSA);
        final VerifyAsymmetricSignatureResponse pqcResponse = powerAuthClient.verifyAsymmetricSignature(verifyPqcRequest);
        assertTrue(pqcResponse.isSignatureValid());
    }

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

    private static void verifyAuditItem(SignatureAuditItem item, PowerAuthVersion version, PowerAuthTestConfiguration config, String normalizedDataWithSecret) {
        assertEquals(config.getActivationId(version), item.getActivationId());
        assertEquals(
                normalizedDataWithSecret,
                new String(Base64.getDecoder().decode(item.getDataBase64()))
        );
        assertEquals("POSSESSION_KNOWLEDGE", item.getSignatureType());
        assertEquals(version.value(), item.getSignatureVersion());
        assertEquals(ActivationStatus.ACTIVE, item.getActivationStatus());
        assertEquals(config.getApplicationId(), item.getApplicationId());
        assertEquals(config.getUser(version), item.getUserId());
        assertEquals(4, item.getVersion());
    }

    private static TokenInfo createToken(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws Exception {
        final BaseStepModel model = new BaseStepModel();
        model.setResultStatusObject(config.getResultStatusObject(version));
        final TemporaryKey temporaryKey = TemporaryKeyFetchUtil.fetchTemporaryKey(version, EncryptorScope.ACTIVATION_SCOPE, config);
        assertNotNull(temporaryKey);
        final ClientEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> clientEncryptor = ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.CREATE_TOKEN,
                new EncryptorParameters(version.value(), config.getApplicationKey(), config.getActivationId(version), temporaryKey.getId()),
                new AeadSecrets(temporaryKey.getSharedSecret().getEncoded(), config.getApplicationSecret(), Base64.getDecoder().decode(model.getResultStatus().getSharedInfo2Key()))
        );
        final AeadEncryptedRequest encryptedRequest = clientEncryptor.encryptRequest("{}".getBytes(StandardCharsets.UTF_8));
        final CreateTokenRequest tokenRequest = new CreateTokenRequest();
        tokenRequest.setActivationId(config.getActivationId(version));
        tokenRequest.setApplicationKey(config.getApplicationKey());
        tokenRequest.setEncryptedData(encryptedRequest.getEncryptedData());
        tokenRequest.setNonce(encryptedRequest.getNonce());
        tokenRequest.setProtocolVersion(version.value());
        tokenRequest.setTimestamp(encryptedRequest.getTimestamp());
        tokenRequest.setTemporaryKeyId(encryptedRequest.getTemporaryKeyId());
        tokenRequest.setAuthenticationCodeType(AuthenticationCodeType.POSSESSION_KNOWLEDGE);
        final CreateTokenResponse tokenResponse = powerAuthClient.createToken(tokenRequest);

        final byte[] decryptedData = clientEncryptor.decryptResponse(new AeadEncryptedResponse(
                tokenResponse.getEncryptedData(),
                tokenResponse.getTimestamp()
        ));
        final TokenResponsePayload response = OBJECT_MAPPER.readValue(decryptedData, TokenResponsePayload.class);
        assertNotNull(response.getTokenId());
        assertNotNull(response.getTokenSecret());
        CounterUtil.incrementCounter(model.getResultStatus());
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