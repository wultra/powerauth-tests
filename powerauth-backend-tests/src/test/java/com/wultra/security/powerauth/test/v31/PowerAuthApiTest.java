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
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEnvelopeKey;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
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
import java.security.interfaces.ECPublicKey;
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

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;

    private final PowerAuthClientActivation activation = new PowerAuthClientActivation();
    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final EciesFactory eciesFactory = new EciesFactory();
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
    void prepareActivationTest() throws CryptoProviderException, GenericCryptoException, EciesException, IOException, PowerAuthClientException {
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
        EciesEncryptor eciesEncryptorL2 = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) config.getMasterPublicKey(), config.getApplicationSecret().getBytes(StandardCharsets.UTF_8), EciesSharedInfo1.ACTIVATION_LAYER_2);
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        objectMapper.writeValue(baosL2, requestL2);
        EciesCryptogram eciesCryptogramL2 = eciesEncryptorL2.encryptRequest(baosL2.toByteArray(), true);
        EciesEncryptedRequest encryptedRequestL2 = new EciesEncryptedRequest();
        encryptedRequestL2.setEphemeralPublicKey(Base64.getEncoder().encodeToString(eciesCryptogramL2.getEphemeralPublicKey()));
        encryptedRequestL2.setEncryptedData(Base64.getEncoder().encodeToString(eciesCryptogramL2.getEncryptedData()));
        encryptedRequestL2.setMac(Base64.getEncoder().encodeToString(eciesCryptogramL2.getMac()));
        encryptedRequestL2.setNonce(Base64.getEncoder().encodeToString(eciesCryptogramL2.getNonce()));
        PrepareActivationResponse prepareResponse = powerAuthClient.prepareActivation(activationCode, config.getApplicationKey(), true, encryptedRequestL2.getEphemeralPublicKey(), encryptedRequestL2.getEncryptedData(), encryptedRequestL2.getMac(), encryptedRequestL2.getNonce());
        assertEquals(ActivationStatus.PENDING_COMMIT, prepareResponse.getActivationStatus());
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(activationId, config.getUserV31());
        assertTrue(commitResponse.isActivated());
    }

    @Test
    void createActivationTest() throws CryptoProviderException, GenericCryptoException, EciesException, IOException, PowerAuthClientException {
        String activationName = "test_create";
        KeyPair deviceKeyPair = activation.generateDeviceKeyPair();
        byte[] devicePublicKeyBytes = keyConvertor.convertPublicKeyToBytes(deviceKeyPair.getPublic());
        String devicePublicKeyBase64 = Base64.getEncoder().encodeToString(devicePublicKeyBytes);
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(activationName);
        requestL2.setDevicePublicKey(devicePublicKeyBase64);
        EciesEncryptor eciesEncryptorL2 = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) config.getMasterPublicKey(), config.getApplicationSecret().getBytes(StandardCharsets.UTF_8), EciesSharedInfo1.ACTIVATION_LAYER_2);
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        objectMapper.writeValue(baosL2, requestL2);
        EciesCryptogram eciesCryptogramL2 = eciesEncryptorL2.encryptRequest(baosL2.toByteArray(), true);
        EciesEncryptedRequest encryptedRequestL2 = new EciesEncryptedRequest();
        encryptedRequestL2.setEphemeralPublicKey(Base64.getEncoder().encodeToString(eciesCryptogramL2.getEphemeralPublicKey()));
        encryptedRequestL2.setEncryptedData(Base64.getEncoder().encodeToString(eciesCryptogramL2.getEncryptedData()));
        encryptedRequestL2.setMac(Base64.getEncoder().encodeToString(eciesCryptogramL2.getMac()));
        encryptedRequestL2.setNonce(Base64.getEncoder().encodeToString(eciesCryptogramL2.getNonce()));
        CreateActivationResponse createResponse = powerAuthClient.createActivation(config.getUserV31(), null,
                null, config.getApplicationKey(), encryptedRequestL2.getEphemeralPublicKey(), encryptedRequestL2.getEncryptedData(), encryptedRequestL2.getMac(), encryptedRequestL2.getNonce());
        String activationId = createResponse.getActivationId();
        assertNotNull(activationId);
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.PENDING_COMMIT, statusResponse.getActivationStatus());
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(activationId, config.getUserV31());
        assertTrue(commitResponse.isActivated());
    }

    @Test
    void updateActivationOtpAndCommitTest() throws CryptoProviderException, GenericCryptoException, EciesException, IOException, PowerAuthClientException {
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
        EciesEncryptor eciesEncryptorL2 = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) config.getMasterPublicKey(), config.getApplicationSecret().getBytes(StandardCharsets.UTF_8), EciesSharedInfo1.ACTIVATION_LAYER_2);
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        objectMapper.writeValue(baosL2, requestL2);
        EciesCryptogram eciesCryptogramL2 = eciesEncryptorL2.encryptRequest(baosL2.toByteArray(), true);
        EciesEncryptedRequest encryptedRequestL2 = new EciesEncryptedRequest();
        encryptedRequestL2.setEphemeralPublicKey(Base64.getEncoder().encodeToString(eciesCryptogramL2.getEphemeralPublicKey()));
        encryptedRequestL2.setEncryptedData(Base64.getEncoder().encodeToString(eciesCryptogramL2.getEncryptedData()));
        encryptedRequestL2.setMac(Base64.getEncoder().encodeToString(eciesCryptogramL2.getMac()));
        encryptedRequestL2.setNonce(Base64.getEncoder().encodeToString(eciesCryptogramL2.getNonce()));
        PrepareActivationResponse prepareResponse = powerAuthClient.prepareActivation(activationCode, config.getApplicationKey(), true, encryptedRequestL2.getEphemeralPublicKey(), encryptedRequestL2.getEncryptedData(), encryptedRequestL2.getMac(), encryptedRequestL2.getNonce());
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
        GetActivationListForUserRequest request = new GetActivationListForUserRequest();
        request.setUserId(config.getUserV31());
        request.setApplicationId(config.getApplicationId());

        // Create multiple activations for the test user
        for (int i = 0; i < 10; i++) {
            powerAuthClient.initActivation(request.getUserId(), request.getApplicationId());
        }

        // Prepare the query parameters for the first page
        Map<String, String> queryParams1 = new HashMap<>();
        queryParams1.put("pageNumber", "0");
        queryParams1.put("pageSize", "5");

        // Fetch the first page of activations
        GetActivationListForUserResponse responsePage1 = powerAuthClient.getActivationListForUser(request, MapUtil.toMultiValueMap(queryParams1), null);
        assertEquals(5, responsePage1.getActivations().size());

        // Prepare the query parameters for the second page
        Map<String, String> queryParams2 = new HashMap<>();
        queryParams2.put("pageNumber", "1");
        queryParams2.put("pageSize", "5");

        // Fetch the second page of activations
        GetActivationListForUserResponse responsePage2 = powerAuthClient.getActivationListForUser(request, MapUtil.toMultiValueMap(queryParams2), null);
        assertEquals(5, responsePage2.getActivations().size());

        // Check that the activations on the different pages are not the same
        assertNotEquals(responsePage1.getActivations(), responsePage2.getActivations());
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
        VerifySignatureResponse signatureResponse = powerAuthClient.verifySignature(config.getActivationIdV31(), config.getApplicationKey(), normalizedData, signatureValue, SignatureType.POSSESSION_KNOWLEDGE, "3.1", null);
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
                assertEquals("3.1", item.getSignatureVersion());
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
    void unlockVaultAndECDSASignatureTest() throws GenericCryptoException, CryptoProviderException, InvalidKeySpecException, EciesException, IOException, InvalidKeyException, PowerAuthClientException {
        byte[] transportMasterKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "transportMasterKey"));
        byte[] serverPublicKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "serverPublicKey"));
        byte[] encryptedDevicePrivateKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "encryptedDevicePrivateKey"));
        byte[] nonceBytes = keyGenerator.generateRandomBytes(16);
        final ECPublicKey serverPublicKey = (ECPublicKey) keyConvertor.convertBytesToPublicKey(serverPublicKeyBytes);
        final EciesEncryptor eciesEncryptor = eciesFactory.getEciesEncryptorForActivation(serverPublicKey, config.getApplicationSecret().getBytes(StandardCharsets.UTF_8),
                transportMasterKeyBytes, EciesSharedInfo1.VAULT_UNLOCK);
        VaultUnlockRequestPayload requestPayload = new VaultUnlockRequestPayload();
        requestPayload.setReason("TEST");
        final byte[] requestBytesPayload = objectMapper.writeValueAsBytes(requestPayload);
        final EciesCryptogram eciesCryptogram = eciesEncryptor.encryptRequest(requestBytesPayload, true);
        EciesEncryptedRequest eciesRequest = new EciesEncryptedRequest();
        eciesRequest.setEphemeralPublicKey(Base64.getEncoder().encodeToString(eciesCryptogram.getEphemeralPublicKey()));
        eciesRequest.setEncryptedData(Base64.getEncoder().encodeToString(eciesCryptogram.getEncryptedData()));
        eciesRequest.setMac(Base64.getEncoder().encodeToString(eciesCryptogram.getMac()));
        eciesRequest.setNonce(Base64.getEncoder().encodeToString(eciesCryptogram.getNonce()));
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
        VaultUnlockResponse unlockResponse = powerAuthClient.unlockVault(config.getActivationIdV31(), config.getApplicationKey(), signatureValue, SignatureType.POSSESSION_KNOWLEDGE, "3.1", normalizedData,
                eciesRequest.getEphemeralPublicKey(), eciesRequest.getEncryptedData(), eciesRequest.getMac(), eciesRequest.getNonce());
        assertTrue(unlockResponse.isSignatureValid());
        assertNotNull(unlockResponse.getEncryptedData());
        assertNotNull(unlockResponse.getMac());
        EciesCryptogram responseCryptogram = new EciesCryptogram(Base64.getDecoder().decode(unlockResponse.getMac()), Base64.getDecoder().decode(unlockResponse.getEncryptedData()));
        byte[] decryptedData = eciesEncryptor.decryptResponse(responseCryptogram);
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
    void createValidateAndRemoveTokenTestActiveActivation() throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException, IOException, EciesException, PowerAuthClientException {
        final TokenInfo tokenInfo = createToken();

        // Check successful token validation and activation status
        final ValidateTokenResponse validateResponse = powerAuthClient.validateToken(tokenInfo.getTokenId(),
                Base64.getEncoder().encodeToString(tokenInfo.getTokenNonce()),
                Long.parseLong(new String(tokenInfo.getTokenTimestamp())),
                Base64.getEncoder().encodeToString(tokenInfo.getTokenDigest()));
        assertTrue(validateResponse.isTokenValid());
        assertEquals(ActivationStatus.ACTIVE, validateResponse.getActivationStatus());
        assertNull(validateResponse.getBlockedReason());

        RemoveTokenResponse removeResponse = powerAuthClient.removeToken(tokenInfo.getTokenId(), config.getActivationIdV31());
        assertTrue(removeResponse.isRemoved());
    }

    @Test
    void createValidateAndRemoveTokenTestBlockedActivation() throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException, IOException, EciesException, PowerAuthClientException {
        final TokenInfo tokenInfo = createToken();

        // Block activation
        final BlockActivationResponse blockResponse = powerAuthClient.blockActivation(config.getActivationIdV31(), "TEST", null);
        assertEquals(ActivationStatus.BLOCKED, blockResponse.getActivationStatus());

        // Check that token validation failed and activation status and blocked reason is available
        final ValidateTokenResponse validateResponse = powerAuthClient.validateToken(tokenInfo.getTokenId(),
                Base64.getEncoder().encodeToString(tokenInfo.getTokenNonce()),
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
    void getEciesDecryptorTest() throws CryptoProviderException, GenericCryptoException, EciesException, PowerAuthClientException {
        String requestData = "test_data";
        EciesEncryptor eciesEncryptor = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) config.getMasterPublicKey(), config.getApplicationSecret().getBytes(StandardCharsets.UTF_8), EciesSharedInfo1.APPLICATION_SCOPE_GENERIC);
        EciesCryptogram eciesCryptogram = eciesEncryptor.encryptRequest(requestData.getBytes(StandardCharsets.UTF_8), true);
        EciesEncryptedRequest encryptedRequest = new EciesEncryptedRequest();
        encryptedRequest.setEphemeralPublicKey(Base64.getEncoder().encodeToString(eciesCryptogram.getEphemeralPublicKey()));
        encryptedRequest.setEncryptedData(Base64.getEncoder().encodeToString(eciesCryptogram.getEncryptedData()));
        encryptedRequest.setMac(Base64.getEncoder().encodeToString(eciesCryptogram.getMac()));
        encryptedRequest.setNonce(Base64.getEncoder().encodeToString(eciesCryptogram.getNonce()));
        final byte[] ephemeralPublicKeyBytes = eciesCryptogram.getEphemeralPublicKey();
        final byte[] encryptedDataBytes = eciesCryptogram.getEncryptedData();
        final byte[] macBytes = eciesCryptogram.getMac();
        final byte[] nonceBytes = eciesCryptogram.getNonce();
        final GetEciesDecryptorRequest eciesDecryptorRequest = new GetEciesDecryptorRequest();
        eciesDecryptorRequest.setActivationId(null);
        eciesDecryptorRequest.setApplicationKey(config.getApplicationKey());
        eciesDecryptorRequest.setEphemeralPublicKey(Base64.getEncoder().encodeToString(eciesCryptogram.getEphemeralPublicKey()));
        GetEciesDecryptorResponse eciesDecryptorResponse = powerAuthClient.getEciesDecryptor(eciesDecryptorRequest);
        final byte[] secretKey = Base64.getDecoder().decode(eciesDecryptorResponse.getSecretKey());
        final EciesEnvelopeKey envelopeKey = new EciesEnvelopeKey(secretKey, ephemeralPublicKeyBytes);
        final byte[] sharedInfo2 = Base64.getDecoder().decode(eciesDecryptorResponse.getSharedInfo2());
        final EciesDecryptor eciesDecryptor = eciesFactory.getEciesDecryptor(envelopeKey, sharedInfo2);
        EciesCryptogram cryptogram = new EciesCryptogram(ephemeralPublicKeyBytes, macBytes, encryptedDataBytes, nonceBytes);
        byte[] decryptedData = eciesDecryptor.decryptRequest(cryptogram);
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
    void recoveryCodeConfirmAndActivationTest() throws CryptoProviderException, GenericCryptoException, IOException, EciesException, InvalidKeyException, InvalidKeySpecException, PowerAuthClientException {
        String activationName = "test_create_recovery";
        KeyPair deviceKeyPair = activation.generateDeviceKeyPair();
        byte[] devicePublicKeyBytes = keyConvertor.convertPublicKeyToBytes(deviceKeyPair.getPublic());
        String devicePublicKeyBase64 = Base64.getEncoder().encodeToString(devicePublicKeyBytes);
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(activationName);
        requestL2.setDevicePublicKey(devicePublicKeyBase64);
        EciesEncryptor eciesEncryptorL2 = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) config.getMasterPublicKey(), config.getApplicationSecret().getBytes(StandardCharsets.UTF_8), EciesSharedInfo1.ACTIVATION_LAYER_2);
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        objectMapper.writeValue(baosL2, requestL2);
        EciesCryptogram eciesCryptogramL2 = eciesEncryptorL2.encryptRequest(baosL2.toByteArray(), true);
        EciesEncryptedRequest encryptedRequestL2 = new EciesEncryptedRequest();
        encryptedRequestL2.setEphemeralPublicKey(Base64.getEncoder().encodeToString(eciesCryptogramL2.getEphemeralPublicKey()));
        encryptedRequestL2.setEncryptedData(Base64.getEncoder().encodeToString(eciesCryptogramL2.getEncryptedData()));
        encryptedRequestL2.setMac(Base64.getEncoder().encodeToString(eciesCryptogramL2.getMac()));
        encryptedRequestL2.setNonce(Base64.getEncoder().encodeToString(eciesCryptogramL2.getNonce()));
        CreateActivationResponse createResponse = powerAuthClient.createActivation(config.getUserV31(), null,
                null, config.getApplicationKey(), encryptedRequestL2.getEphemeralPublicKey(),
                encryptedRequestL2.getEncryptedData(), encryptedRequestL2.getMac(), encryptedRequestL2.getNonce());
        String activationId = createResponse.getActivationId();
        assertNotNull(activationId);
        EciesCryptogram cryptogram = new EciesCryptogram(Base64.getDecoder().decode(createResponse.getMac()), Base64.getDecoder().decode(createResponse.getEncryptedData()));
        byte[] responseRaw = eciesEncryptorL2.decryptResponse(cryptogram);
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
        final EciesEncryptor encryptor = eciesFactory.getEciesEncryptorForActivation((ECPublicKey) serverPublicKey,
                config.getApplicationSecret().getBytes(StandardCharsets.UTF_8), transportMasterKeyBytes, EciesSharedInfo1.CONFIRM_RECOVERY_CODE);
        ConfirmRecoveryRequestPayload confirmRequestPayload = new ConfirmRecoveryRequestPayload();
        confirmRequestPayload.setRecoveryCode(recoveryCode);
        EciesCryptogram confirmCryptogram = encryptor.encryptRequest(objectMapper.writeValueAsBytes(confirmRequestPayload), true);
        EciesEncryptedRequest encryptedRequestConfirm = new EciesEncryptedRequest();
        encryptedRequestConfirm.setEphemeralPublicKey(Base64.getEncoder().encodeToString(confirmCryptogram.getEphemeralPublicKey()));
        encryptedRequestConfirm.setEncryptedData(Base64.getEncoder().encodeToString(confirmCryptogram.getEncryptedData()));
        encryptedRequestConfirm.setMac(Base64.getEncoder().encodeToString(confirmCryptogram.getMac()));
        encryptedRequestConfirm.setNonce(Base64.getEncoder().encodeToString(confirmCryptogram.getNonce()));
        ConfirmRecoveryCodeResponse confirmResponse = powerAuthClient.confirmRecoveryCode(activationId, config.getApplicationKey(), encryptedRequestConfirm.getEphemeralPublicKey(),
                encryptedRequestConfirm.getEncryptedData(), encryptedRequestConfirm.getMac(), encryptedRequestConfirm.getNonce());
        EciesCryptogram confirmResponseCryptogram = new EciesCryptogram(Base64.getDecoder().decode(confirmResponse.getMac()),
                Base64.getDecoder().decode(confirmResponse.getEncryptedData()));
        byte[] confirmResponseRaw = encryptor.decryptResponse(confirmResponseCryptogram);
        ConfirmRecoveryResponsePayload confirmResponsePayload = RestClientConfiguration.defaultMapper().readValue(confirmResponseRaw, ConfirmRecoveryResponsePayload.class);
        assertTrue(confirmResponsePayload.getAlreadyConfirmed());
        KeyPair deviceKeyPairR = activation.generateDeviceKeyPair();
        byte[] devicePublicKeyBytesR = keyConvertor.convertPublicKeyToBytes(deviceKeyPairR.getPublic());
        String devicePublicKeyBase64R = Base64.getEncoder().encodeToString(devicePublicKeyBytesR);
        ActivationLayer2Request requestL2R = new ActivationLayer2Request();
        requestL2.setActivationName(activationName + "_2");
        requestL2.setDevicePublicKey(devicePublicKeyBase64R);
        EciesEncryptor eciesEncryptorL2R = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) config.getMasterPublicKey(), config.getApplicationSecret().getBytes(StandardCharsets.UTF_8), EciesSharedInfo1.ACTIVATION_LAYER_2);
        ByteArrayOutputStream baosL2R = new ByteArrayOutputStream();
        objectMapper.writeValue(baosL2R, requestL2R);
        EciesCryptogram eciesCryptogramL2R = eciesEncryptorL2R.encryptRequest(baosL2R.toByteArray(), true);
        EciesEncryptedRequest encryptedRequestL2R = new EciesEncryptedRequest();
        encryptedRequestL2R.setEphemeralPublicKey(Base64.getEncoder().encodeToString(eciesCryptogramL2R.getEphemeralPublicKey()));
        encryptedRequestL2R.setEncryptedData(Base64.getEncoder().encodeToString(eciesCryptogramL2R.getEncryptedData()));
        encryptedRequestL2R.setMac(Base64.getEncoder().encodeToString(eciesCryptogramL2R.getMac()));
        encryptedRequestL2R.setNonce(Base64.getEncoder().encodeToString(eciesCryptogramL2R.getNonce()));
        RecoveryCodeActivationResponse createResponseR = powerAuthClient.createActivationUsingRecoveryCode(recoveryCode, recoveryPuk,
                config.getApplicationKey(), null, encryptedRequestL2.getEphemeralPublicKey(),
                encryptedRequestL2.getEncryptedData(), encryptedRequestL2.getMac(), encryptedRequestL2.getNonce());
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

    private TokenInfo createToken() throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException, IOException, EciesException, PowerAuthClientException {
        byte[] transportMasterKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "transportMasterKey"));
        byte[] serverPublicKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "serverPublicKey"));
        final ECPublicKey serverPublicKey = (ECPublicKey) keyConvertor.convertBytesToPublicKey(serverPublicKeyBytes);
        final EciesEncryptor eciesEncryptor = eciesFactory.getEciesEncryptorForActivation(serverPublicKey, config.getApplicationSecret().getBytes(StandardCharsets.UTF_8),
                transportMasterKeyBytes, EciesSharedInfo1.CREATE_TOKEN);
        final EciesCryptogram eciesCryptogram = eciesEncryptor.encryptRequest("{}".getBytes(StandardCharsets.UTF_8), true);
        final EciesEncryptedRequest eciesRequest = new EciesEncryptedRequest();
        eciesRequest.setEphemeralPublicKey(Base64.getEncoder().encodeToString(eciesCryptogram.getEphemeralPublicKey()));
        eciesRequest.setEncryptedData(Base64.getEncoder().encodeToString(eciesCryptogram.getEncryptedData()));
        eciesRequest.setMac(Base64.getEncoder().encodeToString(eciesCryptogram.getMac()));
        eciesRequest.setNonce(Base64.getEncoder().encodeToString(eciesCryptogram.getNonce()));
        final CreateTokenResponse tokenResponse = powerAuthClient.createToken(config.getActivationIdV31(), config.getApplicationKey(), eciesRequest.getEphemeralPublicKey(), eciesRequest.getEncryptedData(),
                eciesRequest.getMac(), eciesRequest.getNonce(), SignatureType.POSSESSION_KNOWLEDGE);
        assertNotNull(tokenResponse.getEncryptedData());
        assertNotNull(tokenResponse.getMac());
        final EciesCryptogram responseCryptogram = new EciesCryptogram(Base64.getDecoder().decode(tokenResponse.getMac()), Base64.getDecoder().decode(tokenResponse.getEncryptedData()));
        final byte[] decryptedData = eciesEncryptor.decryptResponse(responseCryptogram);
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