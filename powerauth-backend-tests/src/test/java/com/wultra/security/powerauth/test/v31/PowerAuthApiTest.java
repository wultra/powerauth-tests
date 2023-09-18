/*
 * PowerAuth test and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.v31;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.entity.*;
import com.wultra.security.powerauth.client.model.enumeration.*;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.GetActivationListForUserRequest;
import com.wultra.security.powerauth.client.model.request.GetEciesDecryptorRequest;
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
import io.getlime.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEnvelopeKey;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ClientEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ServerEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth API tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthApiTest {

    private final String protocolVersion = "3.1";
    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;

    private final PowerAuthClientActivation activation = new PowerAuthClientActivation();
    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final EncryptorFactory encryptorFactory = new EncryptorFactory();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final PowerAuthClientSignature signature = new PowerAuthClientSignature();
    private final PowerAuthClientVault vault = new PowerAuthClientVault();
    private final PowerAuthClientKeyFactory keyFactory = new PowerAuthClientKeyFactory();
    private final SignatureUtils signatureUtils = new SignatureUtils();
    private final ClientTokenGenerator tokenGenerator = new ClientTokenGenerator();

    private static final int TIME_SYNCHRONIZATION_WINDOW_SECONDS = 60;

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Test
    void systemStatusTest() throws PowerAuthClientException {
        final GetSystemStatusResponse response = powerAuthClient.getSystemStatus();
        assertEquals("OK", response.getStatus());
    }

    @Test
    void errorListTest() throws PowerAuthClientException {
        final GetErrorCodeListResponse response = powerAuthClient.getErrorList(Locale.ENGLISH.getLanguage());
        assertTrue(response.getErrors().size() > 32);
    }

    @Test
    void initActivationTest() throws PowerAuthClientException {
        final InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31(), config.getApplicationId());
        assertNotNull(response.getActivationId());
        assertNotNull(response.getActivationCode());
        assertNotNull(response.getActivationSignature());
        assertEquals(config.getUserV31(), response.getUserId());
        assertEquals(config.getApplicationId(), response.getApplicationId());
        final GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());
    }

    @Test
    void prepareActivationTest() throws CryptoProviderException, EncryptorException, IOException, PowerAuthClientException {
        String activationName = "test_prepare";
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31(), config.getApplicationId());
        String activationId = response.getActivationId();
        String activationCode = response.getActivationCode();
        KeyPair deviceKeyPair = activation.generateDeviceKeyPair();
        byte[] devicePublicKeyBytes = keyConvertor.convertPublicKeyToBytes(deviceKeyPair.getPublic());
        String devicePublicKeyBase64 = Base64.getEncoder().encodeToString(devicePublicKeyBytes);
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(activationName);
        requestL2.setDevicePublicKey(devicePublicKeyBase64);
        ClientEncryptor clientEncryptorL2 = encryptorFactory.getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters(protocolVersion, config.getApplicationKey(), null),
                new ClientEncryptorSecrets(config.getMasterPublicKey(), config.getApplicationSecret())
        );
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        objectMapper.writeValue(baosL2, requestL2);
        EncryptedRequest encryptedRequestL2 = clientEncryptorL2.encryptRequest(baosL2.toByteArray());
        PrepareActivationResponse prepareResponse = powerAuthClient.prepareActivation(activationCode, config.getApplicationKey(), true, encryptedRequestL2.getEphemeralPublicKey(), encryptedRequestL2.getEncryptedData(), encryptedRequestL2.getMac(), encryptedRequestL2.getNonce(), protocolVersion, encryptedRequestL2.getTimestamp());
        assertEquals(ActivationStatus.PENDING_COMMIT, prepareResponse.getActivationStatus());
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(activationId, config.getUserV31());
        assertTrue(commitResponse.isActivated());
    }

    @Test
    void createActivationTest() throws CryptoProviderException, EncryptorException, IOException, PowerAuthClientException {
        String activationName = "test_create";
        KeyPair deviceKeyPair = activation.generateDeviceKeyPair();
        byte[] devicePublicKeyBytes = keyConvertor.convertPublicKeyToBytes(deviceKeyPair.getPublic());
        String devicePublicKeyBase64 = Base64.getEncoder().encodeToString(devicePublicKeyBytes);
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(activationName);
        requestL2.setDevicePublicKey(devicePublicKeyBase64);
        ClientEncryptor clientEncryptorL2 = encryptorFactory.getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters(protocolVersion, config.getApplicationKey(), null),
                new ClientEncryptorSecrets(config.getMasterPublicKey(), config.getApplicationSecret())
        );
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        objectMapper.writeValue(baosL2, requestL2);
        EncryptedRequest encryptedRequestL2 = clientEncryptorL2.encryptRequest(baosL2.toByteArray());
        CreateActivationResponse createResponse = powerAuthClient.createActivation(config.getUserV31(), null,
                null, config.getApplicationKey(), encryptedRequestL2.getEphemeralPublicKey(), encryptedRequestL2.getEncryptedData(), encryptedRequestL2.getMac(), encryptedRequestL2.getNonce(), protocolVersion, encryptedRequestL2.getTimestamp());
        String activationId = createResponse.getActivationId();
        assertNotNull(activationId);
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.PENDING_COMMIT, statusResponse.getActivationStatus());
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(activationId, config.getUserV31());
        assertTrue(commitResponse.isActivated());
    }

    @Test
    void updateActivationOtpAndCommitTest() throws CryptoProviderException, EncryptorException, IOException, PowerAuthClientException {
        String activationName = "test_update_otp";
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31(), config.getApplicationId(), ActivationOtpValidation.NONE, null);
        String activationId = response.getActivationId();
        String activationCode = response.getActivationCode();
        KeyPair deviceKeyPair = activation.generateDeviceKeyPair();
        byte[] devicePublicKeyBytes = keyConvertor.convertPublicKeyToBytes(deviceKeyPair.getPublic());
        String devicePublicKeyBase64 = Base64.getEncoder().encodeToString(devicePublicKeyBytes);
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(activationName);
        requestL2.setDevicePublicKey(devicePublicKeyBase64);
        ClientEncryptor clientEncryptorL2 = encryptorFactory.getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters(protocolVersion, config.getApplicationKey(), null),
                new ClientEncryptorSecrets(config.getMasterPublicKey(), config.getApplicationSecret())
        );
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        objectMapper.writeValue(baosL2, requestL2);
        EncryptedRequest encryptedRequestL2 = clientEncryptorL2.encryptRequest(baosL2.toByteArray());
        PrepareActivationResponse prepareResponse = powerAuthClient.prepareActivation(activationCode, config.getApplicationKey(), true, encryptedRequestL2.getEphemeralPublicKey(), encryptedRequestL2.getEncryptedData(), encryptedRequestL2.getMac(), encryptedRequestL2.getNonce(), protocolVersion, encryptedRequestL2.getTimestamp());
        assertEquals(ActivationStatus.PENDING_COMMIT, prepareResponse.getActivationStatus());
        UpdateActivationOtpResponse otpResponse = powerAuthClient.updateActivationOtp(activationId, config.getUserV31(), "12345678");
        assertTrue(otpResponse.isUpdated());
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(activationId, config.getUserV31(), "12345678");
        assertTrue(commitResponse.isActivated());
    }

    @Test
    void removeActivationTest() throws PowerAuthClientException {
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31(), config.getApplicationId());
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());
        RemoveActivationResponse removeResponse = powerAuthClient.removeActivation(response.getActivationId(), null);
        assertTrue(removeResponse.isRemoved());
        GetActivationStatusResponse statusResponse2 = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.REMOVED, statusResponse2.getActivationStatus());
    }

    @Test
    void activationListForUserTest() throws PowerAuthClientException {
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31(), config.getApplicationId());
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());
        final List<Activation> listResponse = powerAuthClient.getActivationListForUser(config.getUserV31());
        assertNotEquals(0, listResponse.size());
    }

    @Test
    void testGetActivationListForUserPagination() throws PowerAuthClientException {
        // Prepare the base GetActivationListForUserRequest
        final GetActivationListForUserRequest baseRequest = new GetActivationListForUserRequest();
        baseRequest.setUserId(config.getUserV31());
        baseRequest.setApplicationId(config.getApplicationId());

        // Create a list to store the activation IDs
        final List<String> activationIds = new ArrayList<>();

        // Create multiple activations for the test user
        for (int i = 0; i < 10; i++) {
            InitActivationResponse initResponse = powerAuthClient.initActivation(baseRequest.getUserId(), baseRequest.getApplicationId());
            activationIds.add(initResponse.getActivationId());
        }

        // Prepare the request for the first page of activations
        final GetActivationListForUserRequest requestPage1 = new GetActivationListForUserRequest();
        requestPage1.setUserId(baseRequest.getUserId());
        requestPage1.setApplicationId(baseRequest.getApplicationId());
        requestPage1.setPageNumber(0);
        requestPage1.setPageSize(5);

        // Fetch the first page of activations
        final GetActivationListForUserResponse responsePage1 = powerAuthClient.getActivationListForUser(requestPage1);
        assertEquals(5, responsePage1.getActivations().size());

        // Prepare the request for the second page of activations
        final GetActivationListForUserRequest requestPage2 = new GetActivationListForUserRequest();
        requestPage2.setUserId(baseRequest.getUserId());
        requestPage2.setApplicationId(baseRequest.getApplicationId());
        requestPage2.setPageNumber(1);
        requestPage2.setPageSize(5);

        // Fetch the second page of activations
        final GetActivationListForUserResponse responsePage2 = powerAuthClient.getActivationListForUser(requestPage2);
        assertEquals(5, responsePage2.getActivations().size());

        // Check that the activations on the different pages are not the same
        assertNotEquals(responsePage1.getActivations(), responsePage2.getActivations());

        // Clean up the created activations at the end
        for (String id : activationIds) {
            RemoveActivationResponse removeActivationResponse = powerAuthClient.removeActivation(id, config.getUserV31());
            assertTrue(removeActivationResponse.isRemoved());
        }
    }

    @Test
    void lookupActivationsTest() throws PowerAuthClientException {
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31(), config.getApplicationId());
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(response.getActivationId());
        final Date timestampCreated = statusResponse.getTimestampCreated();
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());
        List<Activation> activations = powerAuthClient.lookupActivations(Collections.singletonList(config.getUserV31()), Collections.singletonList(config.getApplicationId()),
                null, timestampCreated, ActivationStatus.CREATED, null);
        assertTrue(activations.size() >= 1);
    }

    @Test
    void activationStatusUpdateTest() throws PowerAuthClientException {
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31(), config.getApplicationId());
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());
        UpdateStatusForActivationsResponse updateResponse = powerAuthClient.updateStatusForActivations(Collections.singletonList(response.getActivationId()), ActivationStatus.REMOVED);
        assertTrue(updateResponse.isUpdated());
        GetActivationStatusResponse statusResponse2 = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.REMOVED, statusResponse2.getActivationStatus());
    }

    @Test
    void verifySignatureTest() throws GenericCryptoException, CryptoProviderException, InvalidKeyException, PowerAuthClientException {
        Calendar before = new GregorianCalendar();
        before.add(Calendar.SECOND, -TIME_SYNCHRONIZATION_WINDOW_SECONDS);
        byte[] nonceBytes = keyGenerator.generateRandomBytes(16);
        String data = "test_data";
        String normalizedData = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/signature/validate", nonceBytes, data.getBytes(StandardCharsets.UTF_8));
        String normalizedDataWithSecret = normalizedData + "&" + config.getApplicationSecret();
        byte[] ctrData = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "ctrData"));
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "signatureKnowledgeKeyEncrypted"));
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);
        SecretKey signaturePossessionKey = keyConvertor.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        String signatureValue = signature.signatureForData(normalizedDataWithSecret.getBytes(StandardCharsets.UTF_8), keyFactory.keysForSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
                signaturePossessionKey, signatureKnowledgeKey, null), ctrData, SignatureConfiguration.base64());
        VerifySignatureResponse signatureResponse = powerAuthClient.verifySignature(config.getActivationIdV31(), config.getApplicationKey(), normalizedData, signatureValue, SignatureType.POSSESSION_KNOWLEDGE, protocolVersion, null);
        assertTrue(signatureResponse.isSignatureValid());
        BaseStepModel model = new BaseStepModel();
        model.setResultStatusObject(config.getResultStatusObjectV31());
        CounterUtil.incrementCounter(model);
        Calendar after = new GregorianCalendar();
        after.add(Calendar.SECOND, TIME_SYNCHRONIZATION_WINDOW_SECONDS);
        List<SignatureAuditItem> auditItems = powerAuthClient.getSignatureAuditLog(config.getUserV31(), config.getApplicationId(), before.getTime(), after.getTime());
        boolean signatureFound = false;
        for (SignatureAuditItem item: auditItems) {
            if (signatureValue.equals(item.getSignature())) {
                assertEquals(config.getActivationIdV31(), item.getActivationId());
                assertEquals(normalizedDataWithSecret, new String(Base64.getDecoder().decode(item.getDataBase64())));
                assertEquals(SignatureType.POSSESSION_KNOWLEDGE, item.getSignatureType());
                assertEquals(protocolVersion, item.getSignatureVersion());
                assertEquals(ActivationStatus.ACTIVE, item.getActivationStatus());
                assertEquals(config.getApplicationId(), item.getApplicationId());
                assertEquals(config.getUserV31(), item.getUserId());
                assertEquals(3, item.getVersion());
                signatureFound = true;
            }
        }
        assertTrue(signatureFound);
    }

    @Test
    void nonPersonalizedOfflineSignaturePayloadTest() throws PowerAuthClientException {
        // For more complete tests for createNonPersonalizedOfflineSignaturePayload see PowerAuthSignatureTest
        CreateNonPersonalizedOfflineSignaturePayloadResponse response = powerAuthClient.createNonPersonalizedOfflineSignaturePayload(config.getApplicationId(), "test_data");
        assertNotNull(response.getOfflineData());
        assertNotNull(response.getNonce());
    }

    @Test
    void personalizedOfflineSignaturePayloadTest() throws PowerAuthClientException {
        // For more complete tests for createPersonalizedOfflineSignaturePayload see PowerAuthSignatureTest
        CreatePersonalizedOfflineSignaturePayloadResponse response = powerAuthClient.createPersonalizedOfflineSignaturePayload(config.getActivationIdV31(), "test_data");
        assertNotNull(response.getOfflineData());
        assertNotNull(response.getNonce());
    }

    @Test
    void verifyOfflineSignatureTest() throws PowerAuthClientException {
        // For more complete tests for verifyOfflineSignature see PowerAuthSignatureTest
        VerifyOfflineSignatureResponse response = powerAuthClient.verifyOfflineSignature(config.getActivationIdV31(), "test_data", "12345678", false);
        assertFalse(response.isSignatureValid());
    }

    @Test
    void unlockVaultAndECDSASignatureTest() throws GenericCryptoException, CryptoProviderException, InvalidKeySpecException, EncryptorException, IOException, InvalidKeyException, PowerAuthClientException {
        byte[] transportMasterKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "transportMasterKey"));
        byte[] serverPublicKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "serverPublicKey"));
        byte[] encryptedDevicePrivateKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "encryptedDevicePrivateKey"));
        byte[] nonceBytes = keyGenerator.generateRandomBytes(16);
        final PublicKey serverPublicKey = keyConvertor.convertBytesToPublicKey(serverPublicKeyBytes);
        final ClientEncryptor clientEncryptor = encryptorFactory.getClientEncryptor(
                EncryptorId.VAULT_UNLOCK,
                new EncryptorParameters(protocolVersion, config.getApplicationKey(), config.getActivationIdV31()),
                new ClientEncryptorSecrets(serverPublicKey, config.getApplicationSecret(), transportMasterKeyBytes)
        );
        VaultUnlockRequestPayload requestPayload = new VaultUnlockRequestPayload();
        requestPayload.setReason("TEST");
        final byte[] requestBytesPayload = objectMapper.writeValueAsBytes(requestPayload);
        final EncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(requestBytesPayload);
        EciesEncryptedRequest eciesRequest = new EciesEncryptedRequest();
        eciesRequest.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        eciesRequest.setEncryptedData(encryptedRequest.getEncryptedData());
        eciesRequest.setMac(encryptedRequest.getMac());
        eciesRequest.setNonce(encryptedRequest.getNonce());
        eciesRequest.setTimestamp(encryptedRequest.getTimestamp());
        final byte[] requestBytes = objectMapper.writeValueAsBytes(eciesRequest);
        String normalizedData = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/signature/validate", nonceBytes, requestBytes);
        String normalizedDataWithSecret = normalizedData + "&" + config.getApplicationSecret();
        byte[] ctrData = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "ctrData"));
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "signatureKnowledgeKeyEncrypted"));
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);
        SecretKey signaturePossessionKey = keyConvertor.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        String signatureValue = signature.signatureForData(normalizedDataWithSecret.getBytes(StandardCharsets.UTF_8), keyFactory.keysForSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
                signaturePossessionKey, signatureKnowledgeKey, null), ctrData, SignatureConfiguration.base64());
        VaultUnlockResponse unlockResponse = powerAuthClient.unlockVault(config.getActivationIdV31(), config.getApplicationKey(), signatureValue, SignatureType.POSSESSION_KNOWLEDGE, protocolVersion, normalizedData,
                eciesRequest.getEphemeralPublicKey(), eciesRequest.getEncryptedData(), eciesRequest.getMac(), eciesRequest.getNonce(), eciesRequest.getTimestamp());
        assertTrue(unlockResponse.isSignatureValid());
        byte[] decryptedData = clientEncryptor.decryptResponse(new EncryptedResponse(
                unlockResponse.getEncryptedData(),
                unlockResponse.getMac(),
                unlockResponse.getNonce(),
                unlockResponse.getTimestamp()
        ));
        VaultUnlockResponsePayload response = objectMapper.readValue(decryptedData, VaultUnlockResponsePayload.class);
        assertNotNull(response.getEncryptedVaultEncryptionKey());
        byte[] encryptedVaultEncryptionKey = Base64.getDecoder().decode(response.getEncryptedVaultEncryptionKey());
        SecretKey transportMasterKey = keyConvertor.convertBytesToSharedSecretKey(transportMasterKeyBytes);
        SecretKey vaultEncryptionKey = vault.decryptVaultEncryptionKey(encryptedVaultEncryptionKey, transportMasterKey);
        PrivateKey devicePrivateKey = vault.decryptDevicePrivateKey(encryptedDevicePrivateKeyBytes, vaultEncryptionKey);
        assertNotNull(devicePrivateKey);
        BaseStepModel model = new BaseStepModel();
        model.setResultStatusObject(config.getResultStatusObjectV31());
        CounterUtil.incrementCounter(model);
        String testData = "test_data";
        byte[] ecdsaSignature = signatureUtils.computeECDSASignature(testData.getBytes(StandardCharsets.UTF_8), devicePrivateKey);
        VerifyECDSASignatureResponse ecdsaResponse = powerAuthClient.verifyECDSASignature(config.getActivationIdV31(),
                Base64.getEncoder().encodeToString(testData.getBytes(StandardCharsets.UTF_8)), Base64.getEncoder().encodeToString(ecdsaSignature));
        assertTrue(ecdsaResponse.isSignatureValid());
    }

    @Test
    void activationHistoryTest() throws PowerAuthClientException {
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31() + "_history_test", config.getApplicationId());
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());
        final Date before = statusResponse.getTimestampCreated();
        final Date after = Date.from(before.toInstant().plus(Duration.ofSeconds(1)));
        final List<ActivationHistoryItem> activationHistory = powerAuthClient.getActivationHistory(response.getActivationId(), before, after);
        final ActivationHistoryItem item = activationHistory.get(0);
        assertEquals(response.getActivationId(), item.getActivationId());
        assertEquals(ActivationStatus.CREATED, item.getActivationStatus());
    }

    @Test
    void blockAndUnblockActivationTest() throws PowerAuthClientException {
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31(), config.getApplicationId());
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());
        // Fake status change to ACTIVE for block and unblock test
        UpdateStatusForActivationsResponse updateResponse = powerAuthClient.updateStatusForActivations(Collections.singletonList(response.getActivationId()), ActivationStatus.ACTIVE);
        assertTrue(updateResponse.isUpdated());
        BlockActivationResponse blockResponse = powerAuthClient.blockActivation(response.getActivationId(), "TEST", null);
        assertEquals(ActivationStatus.BLOCKED, blockResponse.getActivationStatus());
        GetActivationStatusResponse statusResponse2 = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.BLOCKED, statusResponse2.getActivationStatus());
        UnblockActivationResponse unblockResponse = powerAuthClient.unblockActivation(response.getActivationId(), null);
        assertEquals(ActivationStatus.ACTIVE, unblockResponse.getActivationStatus());
        GetActivationStatusResponse statusResponse3 = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, statusResponse3.getActivationStatus());
    }

    @Test
    void applicationListTest() throws PowerAuthClientException {
        final GetApplicationListResponse applications = powerAuthClient.getApplicationList();
        assertNotEquals(0, applications.getApplications().size());
        boolean testApplicationFound = false;
        for (Application app: applications.getApplications()) {
            if (app.getApplicationId().equals(config.getApplicationId())) {
                testApplicationFound = true;
            }
        }
        assertTrue(testApplicationFound);
    }

    @Test
    void applicationDetailTest() throws PowerAuthClientException {
        GetApplicationDetailResponse response = powerAuthClient.getApplicationDetail(config.getApplicationId());
        assertEquals(config.getApplicationName(), response.getApplicationId());
        boolean testAppVersionFound = false;
        for (ApplicationVersion version: response.getVersions()) {
            if (version.getApplicationVersionId().equals(config.getApplicationVersionId())) {
                testAppVersionFound = true;
            }
        }
        assertTrue(testAppVersionFound);
    }

    @Test
    void applicationVersionLookupTest() throws PowerAuthClientException {
        LookupApplicationByAppKeyResponse response = powerAuthClient.lookupApplicationByAppKey(config.getApplicationKey());
        assertEquals(config.getApplicationId(), response.getApplicationId());
    }

    // createApplication and createApplication version tests are skipped to avoid creating too many applications

    @Test
    void applicationSupportTest() throws PowerAuthClientException {
        UnsupportApplicationVersionResponse response = powerAuthClient.unsupportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());
        assertFalse(response.isSupported());
        SupportApplicationVersionResponse response2 = powerAuthClient.supportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());
        assertTrue(response2.isSupported());
    }

    @Test
    void applicationIntegrationTest() throws PowerAuthClientException {
        String integrationName = UUID.randomUUID().toString();
        CreateIntegrationResponse response = powerAuthClient.createIntegration(integrationName);
        assertEquals(integrationName, response.getName());
        final GetIntegrationListResponse items = powerAuthClient.getIntegrationList();
        boolean integrationFound = false;
        for (Integration integration: items.getItems()) {
            if (integration.getName().equals(integrationName)) {
                integrationFound = true;
            }
        }
        assertTrue(integrationFound);
        RemoveIntegrationResponse removeResponse = powerAuthClient.removeIntegration(response.getId());
        assertTrue(removeResponse.isRemoved());
    }

    @Test
    void callbackTest() throws PowerAuthClientException {
        String callbackName = UUID.randomUUID().toString();
        String url = "http://test.wultra.com/";
        CreateCallbackUrlResponse response = powerAuthClient.createCallbackUrl(config.getApplicationId(), callbackName, CallbackUrlType.ACTIVATION_STATUS_CHANGE, url, Collections.emptyList(), null);
        assertEquals(callbackName, response.getName());
        final GetCallbackUrlListResponse items = powerAuthClient.getCallbackUrlList(config.getApplicationId());
        boolean callbackFound = false;
        for (CallbackUrl callback: items.getCallbackUrlList()) {
            if (callback.getName().equals(callbackName)) {
                callbackFound = true;
            }
        }
        assertTrue(callbackFound);
        RemoveCallbackUrlResponse removeResponse = powerAuthClient.removeCallbackUrl(response.getId());
        assertTrue(removeResponse.isRemoved());
    }

    @Test
    void createValidateAndRemoveTokenTestActiveActivation() throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException, IOException, EncryptorException, PowerAuthClientException {
        final TokenInfo tokenInfo = createToken();

        // Check successful token validation and activation status
        final ValidateTokenResponse validateResponse = powerAuthClient.validateToken(tokenInfo.getTokenId(),
                Base64.getEncoder().encodeToString(tokenInfo.getTokenNonce()),
                "3.1",
                Long.parseLong(new String(tokenInfo.getTokenTimestamp())),
                Base64.getEncoder().encodeToString(tokenInfo.getTokenDigest()));
        assertTrue(validateResponse.isTokenValid());
        assertEquals(ActivationStatus.ACTIVE, validateResponse.getActivationStatus());
        assertNull(validateResponse.getBlockedReason());

        RemoveTokenResponse removeResponse = powerAuthClient.removeToken(tokenInfo.getTokenId(), config.getActivationIdV31());
        assertTrue(removeResponse.isRemoved());
    }

    @Test
    void createValidateAndRemoveTokenTestBlockedActivation() throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException, IOException, EncryptorException, PowerAuthClientException {
        final TokenInfo tokenInfo = createToken();

        // Block activation
        final BlockActivationResponse blockResponse = powerAuthClient.blockActivation(config.getActivationIdV31(), "TEST", null);
        assertEquals(ActivationStatus.BLOCKED, blockResponse.getActivationStatus());

        // Check that token validation failed and activation status and blocked reason is available
        final ValidateTokenResponse validateResponse = powerAuthClient.validateToken(tokenInfo.getTokenId(),
                Base64.getEncoder().encodeToString(tokenInfo.getTokenNonce()),
                "3.1",
                Long.parseLong(new String(tokenInfo.getTokenTimestamp())),
                Base64.getEncoder().encodeToString(tokenInfo.getTokenDigest()));
        assertFalse(validateResponse.isTokenValid());
        assertEquals(ActivationStatus.BLOCKED, validateResponse.getActivationStatus());
        assertEquals("TEST", validateResponse.getBlockedReason());

        // Unblock activation
        final UnblockActivationResponse unblockResponse = powerAuthClient.unblockActivation(config.getActivationIdV31(), "TEST");
        assertEquals(ActivationStatus.ACTIVE, unblockResponse.getActivationStatus());

        final RemoveTokenResponse removeResponse = powerAuthClient.removeToken(tokenInfo.getTokenId(), config.getActivationIdV31());
        assertTrue(removeResponse.isRemoved());
    }

    @Test
    void getEciesDecryptorTest() throws EncryptorException, PowerAuthClientException {
        String requestData = "test_data";
        ClientEncryptor clientEncryptor = encryptorFactory.getClientEncryptor(
                EncryptorId.APPLICATION_SCOPE_GENERIC,
                new EncryptorParameters(protocolVersion, config.getApplicationKey(), null),
                new ClientEncryptorSecrets(config.getMasterPublicKey(), config.getApplicationSecret())
        );
        EncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(requestData.getBytes(StandardCharsets.UTF_8));
        final GetEciesDecryptorRequest eciesDecryptorRequest = new GetEciesDecryptorRequest();
        eciesDecryptorRequest.setProtocolVersion(protocolVersion);
        eciesDecryptorRequest.setActivationId(null);
        eciesDecryptorRequest.setApplicationKey(config.getApplicationKey());
        eciesDecryptorRequest.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        eciesDecryptorRequest.setNonce(encryptedRequest.getNonce());
        eciesDecryptorRequest.setTimestamp(encryptedRequest.getTimestamp());
        GetEciesDecryptorResponse decryptorResponse = powerAuthClient.getEciesDecryptor(eciesDecryptorRequest);

        final byte[] secretKey = Base64.getDecoder().decode(decryptorResponse.getSecretKey());
        final byte[] sharedInfo2Base = Base64.getDecoder().decode(decryptorResponse.getSharedInfo2());
        final byte[] ephemeralPublicKeyBytes = Base64.getDecoder().decode(encryptedRequest.getEphemeralPublicKey());
        final EciesEnvelopeKey envelopeKey = new EciesEnvelopeKey(secretKey, ephemeralPublicKeyBytes);
        final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(
                EncryptorId.APPLICATION_SCOPE_GENERIC,
                new EncryptorParameters(protocolVersion, config.getApplicationKey(), null),
                new ServerEncryptorSecrets(secretKey, sharedInfo2Base)
        );
        byte[] decryptedData = serverEncryptor.decryptRequest(encryptedRequest);
        assertArrayEquals(requestData.getBytes(StandardCharsets.UTF_8), decryptedData);
    }

    @Test
    void recoveryCodeCreateLookupRevokeTest() throws PowerAuthClientException {
        CreateRecoveryCodeResponse createResponse = powerAuthClient.createRecoveryCode(config.getApplicationId(), config.getUserV31(), 2L);
        assertEquals(config.getUserV31(), createResponse.getUserId());
        assertEquals(RecoveryCodeStatus.CREATED, createResponse.getStatus());
        assertEquals(2, createResponse.getPuks().size());
        LookupRecoveryCodesResponse lookupResponse = powerAuthClient.lookupRecoveryCodes(config.getUserV31(), null, config.getApplicationId(), RecoveryCodeStatus.CREATED, RecoveryPukStatus.VALID);
        assertNotEquals(0, lookupResponse.getRecoveryCodes().size());
        RevokeRecoveryCodesResponse revokeResponse = powerAuthClient.revokeRecoveryCodes(Collections.singletonList(createResponse.getRecoveryCodeId()));
        assertTrue(revokeResponse.isRevoked());
    }

    @Test
    void recoveryCodeConfirmAndActivationTest() throws CryptoProviderException, GenericCryptoException, IOException, EncryptorException, InvalidKeyException, InvalidKeySpecException, PowerAuthClientException {
        String activationName = "test_create_recovery";
        KeyPair deviceKeyPair = activation.generateDeviceKeyPair();
        byte[] devicePublicKeyBytes = keyConvertor.convertPublicKeyToBytes(deviceKeyPair.getPublic());
        String devicePublicKeyBase64 = Base64.getEncoder().encodeToString(devicePublicKeyBytes);
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(activationName);
        requestL2.setDevicePublicKey(devicePublicKeyBase64);
        ClientEncryptor clientEncryptorL2 = encryptorFactory.getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters(protocolVersion, config.getApplicationKey(), null),
                new ClientEncryptorSecrets(config.getMasterPublicKey(), config.getApplicationSecret())
        );
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        objectMapper.writeValue(baosL2, requestL2);
        EncryptedRequest encryptedRequestL2 = clientEncryptorL2.encryptRequest(baosL2.toByteArray());
        CreateActivationResponse createResponse = powerAuthClient.createActivation(config.getUserV31(), null,
                null, config.getApplicationKey(), encryptedRequestL2.getEphemeralPublicKey(),
                encryptedRequestL2.getEncryptedData(), encryptedRequestL2.getMac(), encryptedRequestL2.getNonce(), protocolVersion, encryptedRequestL2.getTimestamp());
        String activationId = createResponse.getActivationId();
        assertNotNull(activationId);
        byte[] responseRaw = clientEncryptorL2.decryptResponse(new EncryptedResponse(
                createResponse.getEncryptedData(),
                createResponse.getMac(),
                createResponse.getNonce(),
                createResponse.getTimestamp()
        ));
        ActivationLayer2Response responseL2 = objectMapper.readValue(responseRaw, ActivationLayer2Response.class);
        String recoveryCode = responseL2.getActivationRecovery().getRecoveryCode();
        String recoveryPuk = responseL2.getActivationRecovery().getPuk();
        PublicKey serverPublicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode(responseL2.getServerPublicKey()));
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.PENDING_COMMIT, statusResponse.getActivationStatus());
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(activationId, config.getUserV31());
        assertTrue(commitResponse.isActivated());
        SecretKey masterSecretKey = keyFactory.generateClientMasterSecretKey(deviceKeyPair.getPrivate(), serverPublicKey);
        SecretKey transportMasterKey = keyFactory.generateServerTransportKey(masterSecretKey);
        byte[] transportMasterKeyBytes = keyConvertor.convertSharedSecretKeyToBytes(transportMasterKey);
        // Confirm recovery code
        ClientEncryptor encryptorConfirmRC = encryptorFactory.getClientEncryptor(
                EncryptorId.CONFIRM_RECOVERY_CODE,
                new EncryptorParameters(protocolVersion, config.getApplicationKey(), activationId),
                new ClientEncryptorSecrets(serverPublicKey, config.getApplicationSecret(), transportMasterKeyBytes)
        );
        ConfirmRecoveryRequestPayload confirmRequestPayload = new ConfirmRecoveryRequestPayload();
        confirmRequestPayload.setRecoveryCode(recoveryCode);

        EncryptedRequest encryptedRequestConfirm = encryptorConfirmRC.encryptRequest(objectMapper.writeValueAsBytes(confirmRequestPayload));
        ConfirmRecoveryCodeResponse confirmResponse = powerAuthClient.confirmRecoveryCode(activationId, config.getApplicationKey(), encryptedRequestConfirm.getEphemeralPublicKey(),
                encryptedRequestConfirm.getEncryptedData(), encryptedRequestConfirm.getMac(), encryptedRequestConfirm.getNonce(), protocolVersion, encryptedRequestConfirm.getTimestamp());
        byte[] confirmResponseRaw = encryptorConfirmRC.decryptResponse(new EncryptedResponse(
                confirmResponse.getEncryptedData(),
                confirmResponse.getMac(),
                confirmResponse.getNonce(),
                confirmResponse.getTimestamp()
        ));
        ConfirmRecoveryResponsePayload confirmResponsePayload = RestClientConfiguration.defaultMapper().readValue(confirmResponseRaw, ConfirmRecoveryResponsePayload.class);
        assertTrue(confirmResponsePayload.getAlreadyConfirmed());
        // Create recovery activation
        KeyPair deviceKeyPairR = activation.generateDeviceKeyPair();
        byte[] devicePublicKeyBytesR = keyConvertor.convertPublicKeyToBytes(deviceKeyPairR.getPublic());
        String devicePublicKeyBase64R = Base64.getEncoder().encodeToString(devicePublicKeyBytesR);
        ActivationLayer2Request requestL2R = new ActivationLayer2Request();
        requestL2.setActivationName(activationName + "_2");
        requestL2.setDevicePublicKey(devicePublicKeyBase64R);
        // Note: we reuse clientEncryptorL2
        ByteArrayOutputStream baosL2R = new ByteArrayOutputStream();
        objectMapper.writeValue(baosL2R, requestL2R);
        clientEncryptorL2.encryptRequest(baosL2R.toByteArray());
        EncryptedRequest encryptedRequestL2R = clientEncryptorL2.encryptRequest(baosL2R.toByteArray());
        RecoveryCodeActivationResponse createResponseR = powerAuthClient.createActivationUsingRecoveryCode(recoveryCode, recoveryPuk,
                config.getApplicationKey(), null, encryptedRequestL2.getEphemeralPublicKey(),
                encryptedRequestL2.getEncryptedData(), encryptedRequestL2.getMac(), encryptedRequestL2.getNonce(), protocolVersion, encryptedRequestL2.getTimestamp());
        String activationIdNew = createResponseR.getActivationId();
        GetActivationStatusResponse statusResponseR1 = powerAuthClient.getActivationStatus(activationIdNew);
        assertEquals(ActivationStatus.PENDING_COMMIT, statusResponseR1.getActivationStatus());
        CommitActivationResponse commitResponseR = powerAuthClient.commitActivation(activationIdNew, config.getUserV31());
        assertTrue(commitResponseR.isActivated());
        GetActivationStatusResponse statusResponseR2 = powerAuthClient.getActivationStatus(activationIdNew);
        assertEquals(ActivationStatus.ACTIVE, statusResponseR2.getActivationStatus());
        GetActivationStatusResponse statusResponseR3 = powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.REMOVED, statusResponseR3.getActivationStatus());
    }

    @Test
    void recoveryConfigTest() throws PowerAuthClientException {
        GetRecoveryConfigResponse response = powerAuthClient.getRecoveryConfig(config.getApplicationId());
        String remotePostcardPublicKey = response.getRemotePostcardPublicKey();
        assertNotNull(response.getPostcardPublicKey());
        assertNotNull(remotePostcardPublicKey);
        UpdateRecoveryConfigResponse configResponse = powerAuthClient.updateRecoveryConfig(config.getApplicationId(), false, false, false, "test_key");
        assertTrue(configResponse.isUpdated());
        GetRecoveryConfigResponse response2 = powerAuthClient.getRecoveryConfig(config.getApplicationId());
        assertNotNull(response2.getPostcardPublicKey());
        assertFalse(response2.isActivationRecoveryEnabled());
        assertFalse(response2.isRecoveryPostcardEnabled());
        assertFalse(response2.isAllowMultipleRecoveryCodes());
        assertEquals("test_key", response2.getRemotePostcardPublicKey());
        UpdateRecoveryConfigResponse configResponse2 = powerAuthClient.updateRecoveryConfig(config.getApplicationId(), true, true, false, remotePostcardPublicKey);
        assertTrue(configResponse2.isUpdated());
    }

    // Activation flags are tested using PowerAuthActivationFlagsTest
    // Application roles are tested using PowerAuthApplicationRolesTest

    private TokenInfo createToken() throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException, IOException, EncryptorException, PowerAuthClientException {
        byte[] transportMasterKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "transportMasterKey"));
        byte[] serverPublicKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "serverPublicKey"));
        final PublicKey serverPublicKey = keyConvertor.convertBytesToPublicKey(serverPublicKeyBytes);
        final ClientEncryptor clientEncryptor = encryptorFactory.getClientEncryptor(
                EncryptorId.CREATE_TOKEN,
                new EncryptorParameters(protocolVersion, config.getApplicationKey(), config.getActivationIdV31()),
                new ClientEncryptorSecrets(serverPublicKey, config.getApplicationSecret(), transportMasterKeyBytes)
        );
        final EncryptedRequest encryptedRequest = clientEncryptor.encryptRequest("{}".getBytes(StandardCharsets.UTF_8));
        final CreateTokenResponse tokenResponse = powerAuthClient.createToken(config.getActivationIdV31(), config.getApplicationKey(), encryptedRequest.getEphemeralPublicKey(), encryptedRequest.getEncryptedData(),
                encryptedRequest.getMac(), encryptedRequest.getNonce(), protocolVersion, encryptedRequest.getTimestamp(), SignatureType.POSSESSION_KNOWLEDGE);

        final byte[] decryptedData = clientEncryptor.decryptResponse(new EncryptedResponse(
                tokenResponse.getEncryptedData(),
                tokenResponse.getMac(),
                tokenResponse.getNonce(),
                tokenResponse.getTimestamp()
        ));
        final TokenResponsePayload response = objectMapper.readValue(decryptedData, TokenResponsePayload.class);
        assertNotNull(response.getTokenId());
        assertNotNull(response.getTokenSecret());
        final BaseStepModel model = new BaseStepModel();
        model.setResultStatusObject(config.getResultStatusObjectV31());
        CounterUtil.incrementCounter(model);
        final TokenInfo tokenInfo = new TokenInfo();
        tokenInfo.setTokenId(response.getTokenId());
        tokenInfo.setTokenSecret(response.getTokenSecret());
        tokenInfo.setTokenNonce(tokenGenerator.generateTokenNonce());
        tokenInfo.setTokenTimestamp(tokenGenerator.generateTokenTimestamp());
        tokenInfo.setTokenDigest(tokenGenerator.computeTokenDigest(
                tokenInfo.getTokenNonce(),
                tokenInfo.getTokenTimestamp(),
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