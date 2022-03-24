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
import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.CallbackUrlType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.v3.*;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.client.signature.PowerAuthClientSignature;
import io.getlime.security.powerauth.crypto.client.token.ClientTokenGenerator;
import io.getlime.security.powerauth.crypto.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEnvelopeKey;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
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
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer2Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.ConfirmRecoveryRequestPayload;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.request.v3.VaultUnlockRequestPayload;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.ConfirmRecoveryResponsePayload;
import io.getlime.security.powerauth.rest.api.model.response.v3.UpgradeResponsePayload;
import io.getlime.security.powerauth.rest.api.model.response.v3.VaultUnlockResponsePayload;
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
public class PowerAuthApiTest {

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

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Test
    public void systemStatusTest() throws PowerAuthClientException {
        GetSystemStatusResponse response = powerAuthClient.getSystemStatus();
        assertEquals("OK", response.getStatus());
    }

    @Test
    public void errorListTest() throws PowerAuthClientException {
        GetErrorCodeListResponse response = powerAuthClient.getErrorList(Locale.ENGLISH.getLanguage());
        assertTrue(response.getErrors().size() > 32);
    }

    @Test
    public void initActivationTest() throws PowerAuthClientException {
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31(), config.getApplicationId());
        assertNotNull(response.getActivationId());
        assertNotNull(response.getActivationCode());
        assertNotNull(response.getActivationSignature());
        assertEquals(config.getUserV31(), response.getUserId());
        assertEquals(config.getApplicationId(), response.getApplicationId());
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());
    }

    @Test
    public void prepareActivationTest() throws CryptoProviderException, GenericCryptoException, EciesException, IOException, PowerAuthClientException {
        String activationName = "test_prepare";
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31(), config.getApplicationId());
        String activationId = response.getActivationId();
        String activationCode = response.getActivationCode();
        KeyPair deviceKeyPair = activation.generateDeviceKeyPair();
        byte[] devicePublicKeyBytes = keyConvertor.convertPublicKeyToBytes(deviceKeyPair.getPublic());
        String devicePublicKeyBase64 = BaseEncoding.base64().encode(devicePublicKeyBytes);
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(activationName);
        requestL2.setDevicePublicKey(devicePublicKeyBase64);
        EciesEncryptor eciesEncryptorL2 = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) config.getMasterPublicKey(), config.getApplicationSecret().getBytes(StandardCharsets.UTF_8), EciesSharedInfo1.ACTIVATION_LAYER_2);
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        objectMapper.writeValue(baosL2, requestL2);
        EciesCryptogram eciesCryptogramL2 = eciesEncryptorL2.encryptRequest(baosL2.toByteArray(), true);
        EciesEncryptedRequest encryptedRequestL2 = new EciesEncryptedRequest();
        encryptedRequestL2.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogramL2.getEphemeralPublicKey()));
        encryptedRequestL2.setEncryptedData(BaseEncoding.base64().encode(eciesCryptogramL2.getEncryptedData()));
        encryptedRequestL2.setMac(BaseEncoding.base64().encode(eciesCryptogramL2.getMac()));
        encryptedRequestL2.setNonce(BaseEncoding.base64().encode(eciesCryptogramL2.getNonce()));
        PrepareActivationResponse prepareResponse = powerAuthClient.prepareActivation(activationCode, config.getApplicationKey(), encryptedRequestL2.getEphemeralPublicKey(), encryptedRequestL2.getEncryptedData(), encryptedRequestL2.getMac(), encryptedRequestL2.getNonce());
        assertEquals(ActivationStatus.PENDING_COMMIT, prepareResponse.getActivationStatus());
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(activationId, config.getUserV31());
        assertTrue(commitResponse.isActivated());
    }

    @Test
    public void createActivationTest() throws CryptoProviderException, GenericCryptoException, EciesException, IOException, PowerAuthClientException {
        String activationName = "test_create";
        KeyPair deviceKeyPair = activation.generateDeviceKeyPair();
        byte[] devicePublicKeyBytes = keyConvertor.convertPublicKeyToBytes(deviceKeyPair.getPublic());
        String devicePublicKeyBase64 = BaseEncoding.base64().encode(devicePublicKeyBytes);
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(activationName);
        requestL2.setDevicePublicKey(devicePublicKeyBase64);
        EciesEncryptor eciesEncryptorL2 = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) config.getMasterPublicKey(), config.getApplicationSecret().getBytes(StandardCharsets.UTF_8), EciesSharedInfo1.ACTIVATION_LAYER_2);
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        objectMapper.writeValue(baosL2, requestL2);
        EciesCryptogram eciesCryptogramL2 = eciesEncryptorL2.encryptRequest(baosL2.toByteArray(), true);
        EciesEncryptedRequest encryptedRequestL2 = new EciesEncryptedRequest();
        encryptedRequestL2.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogramL2.getEphemeralPublicKey()));
        encryptedRequestL2.setEncryptedData(BaseEncoding.base64().encode(eciesCryptogramL2.getEncryptedData()));
        encryptedRequestL2.setMac(BaseEncoding.base64().encode(eciesCryptogramL2.getMac()));
        encryptedRequestL2.setNonce(BaseEncoding.base64().encode(eciesCryptogramL2.getNonce()));
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
    public void updateActivationOtpAndCommitTest() throws CryptoProviderException, GenericCryptoException, EciesException, IOException, PowerAuthClientException {
        String activationName = "test_update_otp";
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31(), config.getApplicationId(), ActivationOtpValidation.NONE, null);
        String activationId = response.getActivationId();
        String activationCode = response.getActivationCode();
        KeyPair deviceKeyPair = activation.generateDeviceKeyPair();
        byte[] devicePublicKeyBytes = keyConvertor.convertPublicKeyToBytes(deviceKeyPair.getPublic());
        String devicePublicKeyBase64 = BaseEncoding.base64().encode(devicePublicKeyBytes);
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(activationName);
        requestL2.setDevicePublicKey(devicePublicKeyBase64);
        EciesEncryptor eciesEncryptorL2 = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) config.getMasterPublicKey(), config.getApplicationSecret().getBytes(StandardCharsets.UTF_8), EciesSharedInfo1.ACTIVATION_LAYER_2);
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        objectMapper.writeValue(baosL2, requestL2);
        EciesCryptogram eciesCryptogramL2 = eciesEncryptorL2.encryptRequest(baosL2.toByteArray(), true);
        EciesEncryptedRequest encryptedRequestL2 = new EciesEncryptedRequest();
        encryptedRequestL2.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogramL2.getEphemeralPublicKey()));
        encryptedRequestL2.setEncryptedData(BaseEncoding.base64().encode(eciesCryptogramL2.getEncryptedData()));
        encryptedRequestL2.setMac(BaseEncoding.base64().encode(eciesCryptogramL2.getMac()));
        encryptedRequestL2.setNonce(BaseEncoding.base64().encode(eciesCryptogramL2.getNonce()));
        PrepareActivationResponse prepareResponse = powerAuthClient.prepareActivation(activationCode, config.getApplicationKey(), encryptedRequestL2.getEphemeralPublicKey(), encryptedRequestL2.getEncryptedData(), encryptedRequestL2.getMac(), encryptedRequestL2.getNonce());
        assertEquals(ActivationStatus.PENDING_COMMIT, prepareResponse.getActivationStatus());
        UpdateActivationOtpResponse otpResponse = powerAuthClient.updateActivationOtp(activationId, config.getUserV31(), "12345678");
        assertTrue(otpResponse.isUpdated());
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(activationId, config.getUserV31(), "12345678");
        assertTrue(commitResponse.isActivated());
    }

    @Test
    public void removeActivationTest() throws PowerAuthClientException {
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31(), config.getApplicationId());
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());
        RemoveActivationResponse removeResponse = powerAuthClient.removeActivation(response.getActivationId(), null);
        assertEquals(true, removeResponse.isRemoved());
        GetActivationStatusResponse statusResponse2 = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.REMOVED, statusResponse2.getActivationStatus());
    }

    @Test
    public void activationListForUserTest() throws PowerAuthClientException {
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31(), config.getApplicationId());
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());
        List<GetActivationListForUserResponse.Activations> listResponse = powerAuthClient.getActivationListForUser(config.getUserV31());
        assertNotEquals(0, listResponse.size());
    }

    @Test
    public void lookupActivationsTest() throws PowerAuthClientException {
        Calendar now = new GregorianCalendar();
        now.add(Calendar.SECOND, -1);
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31(), config.getApplicationId());
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());
        List<LookupActivationsResponse.Activations> activations = powerAuthClient.lookupActivations(Collections.singletonList(config.getUserV31()), Collections.singletonList(config.getApplicationId()),
                null, now.getTime(), ActivationStatus.CREATED, null);
        assertEquals(1, activations.size());
    }

    @Test
    public void activationStatusUpdateTest() throws PowerAuthClientException {
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31(), config.getApplicationId());
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());
        UpdateStatusForActivationsResponse updateResponse = powerAuthClient.updateStatusForActivations(Collections.singletonList(response.getActivationId()), ActivationStatus.REMOVED);
        assertTrue(updateResponse.isUpdated());
        GetActivationStatusResponse statusResponse2 = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.REMOVED, statusResponse2.getActivationStatus());
    }

    @Test
    public void verifySignatureTest() throws GenericCryptoException, CryptoProviderException, InvalidKeyException, PowerAuthClientException {
        Calendar before = new GregorianCalendar();
        before.add(Calendar.SECOND, -10);
        byte[] nonceBytes = keyGenerator.generateRandomBytes(16);
        String data = "test_data";
        String normalizedData = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/signature/validate", nonceBytes, data.getBytes(StandardCharsets.UTF_8));
        String normalizedDataWithSecret = normalizedData + "&" + config.getApplicationSecret();
        byte[] ctrData = BaseEncoding.base64().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "ctrData"));
        byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "signatureKnowledgeKeyEncrypted"));
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);
        SecretKey signaturePossessionKey = keyConvertor.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        String signatureValue = signature.signatureForData(normalizedDataWithSecret.getBytes(StandardCharsets.UTF_8), keyFactory.keysForSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
                signaturePossessionKey, signatureKnowledgeKey, null), ctrData, PowerAuthSignatureFormat.BASE64);
        VerifySignatureResponse signatureResponse = powerAuthClient.verifySignature(config.getActivationIdV31(), config.getApplicationKey(), normalizedData, signatureValue, SignatureType.POSSESSION_KNOWLEDGE, "3.1", null);
        assertTrue(signatureResponse.isSignatureValid());
        BaseStepModel model = new BaseStepModel();
        model.setResultStatusObject(config.getResultStatusObjectV31());
        CounterUtil.incrementCounter(model);
        Calendar after = new GregorianCalendar();
        after.add(Calendar.SECOND, 10);
        List<SignatureAuditResponse.Items> auditItems = powerAuthClient.getSignatureAuditLog(config.getUserV31(), config.getApplicationId(), before.getTime(), after.getTime());
        boolean signatureFound = false;
        for (SignatureAuditResponse.Items item: auditItems) {
            if (signatureValue.equals(item.getSignature())) {
                assertEquals(config.getActivationIdV31(), item.getActivationId());
                assertEquals(normalizedDataWithSecret, new String(BaseEncoding.base64().decode(item.getDataBase64())));
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
    public void nonPersonalizedOfflineSignaturePayloadTest() throws PowerAuthClientException {
        // For more complete tests for createNonPersonalizedOfflineSignaturePayload see PowerAuthSignatureTest
        CreateNonPersonalizedOfflineSignaturePayloadResponse response = powerAuthClient.createNonPersonalizedOfflineSignaturePayload(config.getApplicationId(), "test_data");
        assertNotNull(response.getOfflineData());
        assertNotNull(response.getNonce());
    }

    @Test
    public void personalizedOfflineSignaturePayloadTest() throws PowerAuthClientException {
        // For more complete tests for createPersonalizedOfflineSignaturePayload see PowerAuthSignatureTest
        CreatePersonalizedOfflineSignaturePayloadResponse response = powerAuthClient.createPersonalizedOfflineSignaturePayload(config.getActivationIdV31(), "test_data");
        assertNotNull(response.getOfflineData());
        assertNotNull(response.getNonce());
    }

    @Test
    public void verifyOfflineSignatureTest() throws PowerAuthClientException {
        // For more complete tests for verifyOfflineSignature see PowerAuthSignatureTest
        VerifyOfflineSignatureResponse response = powerAuthClient.verifyOfflineSignature(config.getActivationIdV31(), "test_data", "12345678", false);
        assertFalse(response.isSignatureValid());
    }

    @Test
    public void unlockVaultAndECDSASignatureTest() throws GenericCryptoException, CryptoProviderException, InvalidKeySpecException, EciesException, IOException, InvalidKeyException, PowerAuthClientException {
        byte[] transportMasterKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "transportMasterKey"));
        byte[] serverPublicKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "serverPublicKey"));
        byte[] encryptedDevicePrivateKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "encryptedDevicePrivateKey"));
        byte[] nonceBytes = keyGenerator.generateRandomBytes(16);
        final ECPublicKey serverPublicKey = (ECPublicKey) keyConvertor.convertBytesToPublicKey(serverPublicKeyBytes);
        final EciesEncryptor eciesEncryptor = eciesFactory.getEciesEncryptorForActivation(serverPublicKey, config.getApplicationSecret().getBytes(StandardCharsets.UTF_8),
                transportMasterKeyBytes, EciesSharedInfo1.VAULT_UNLOCK);
        VaultUnlockRequestPayload requestPayload = new VaultUnlockRequestPayload();
        requestPayload.setReason("TEST");
        final byte[] requestBytesPayload = objectMapper.writeValueAsBytes(requestPayload);
        final EciesCryptogram eciesCryptogram = eciesEncryptor.encryptRequest(requestBytesPayload, true);
        EciesEncryptedRequest eciesRequest = new EciesEncryptedRequest();
        eciesRequest.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogram.getEphemeralPublicKey()));
        eciesRequest.setEncryptedData(BaseEncoding.base64().encode(eciesCryptogram.getEncryptedData()));
        eciesRequest.setMac(BaseEncoding.base64().encode(eciesCryptogram.getMac()));
        eciesRequest.setNonce(BaseEncoding.base64().encode(eciesCryptogram.getNonce()));
        final byte[] requestBytes = objectMapper.writeValueAsBytes(eciesRequest);
        String normalizedData = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/signature/validate", nonceBytes, requestBytes);
        String normalizedDataWithSecret = normalizedData + "&" + config.getApplicationSecret();
        byte[] ctrData = BaseEncoding.base64().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "ctrData"));
        byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "signatureKnowledgeKeyEncrypted"));
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, keyGenerator);
        SecretKey signaturePossessionKey = keyConvertor.convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        String signatureValue = signature.signatureForData(normalizedDataWithSecret.getBytes(StandardCharsets.UTF_8), keyFactory.keysForSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
                signaturePossessionKey, signatureKnowledgeKey, null), ctrData, PowerAuthSignatureFormat.BASE64);
        VaultUnlockResponse unlockResponse = powerAuthClient.unlockVault(config.getActivationIdV31(), config.getApplicationKey(), signatureValue, SignatureType.POSSESSION_KNOWLEDGE, "3.1", normalizedData,
                eciesRequest.getEphemeralPublicKey(), eciesRequest.getEncryptedData(), eciesRequest.getMac(), eciesRequest.getNonce());
        assertTrue(unlockResponse.isSignatureValid());
        assertNotNull(unlockResponse.getEncryptedData());
        assertNotNull(unlockResponse.getMac());
        EciesCryptogram responseCryptogram = new EciesCryptogram(BaseEncoding.base64().decode(unlockResponse.getMac()), BaseEncoding.base64().decode(unlockResponse.getEncryptedData()));
        byte[] decryptedData = eciesEncryptor.decryptResponse(responseCryptogram);
        VaultUnlockResponsePayload response = objectMapper.readValue(decryptedData, VaultUnlockResponsePayload.class);
        assertNotNull(response.getEncryptedVaultEncryptionKey());
        byte[] encryptedVaultEncryptionKey = BaseEncoding.base64().decode(response.getEncryptedVaultEncryptionKey());
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
                BaseEncoding.base64().encode(testData.getBytes(StandardCharsets.UTF_8)), BaseEncoding.base64().encode(ecdsaSignature));
        assertTrue(ecdsaResponse.isSignatureValid());
    }

    @Test
    public void activationHistoryTest() throws PowerAuthClientException {
        Calendar before = new GregorianCalendar();
        before.add(Calendar.SECOND, -10);
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV31() + "_history_test", config.getApplicationId());
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(response.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());
        Calendar after = new GregorianCalendar();
        after.add(Calendar.SECOND, 10);
        List<ActivationHistoryResponse.Items> activationHistory = powerAuthClient.getActivationHistory(response.getActivationId(), before.getTime(), after.getTime());
        ActivationHistoryResponse.Items item = activationHistory.get(0);
        assertEquals(response.getActivationId(), item.getActivationId());
        assertEquals(ActivationStatus.CREATED, item.getActivationStatus());
    }

    @Test
    public void blockAndUnblockActivationTest() throws PowerAuthClientException {
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
    public void applicationListTest() throws PowerAuthClientException {
        List<GetApplicationListResponse.Applications> applications = powerAuthClient.getApplicationList();
        assertNotEquals(0, applications.size());
        boolean testApplicationFound = false;
        for (GetApplicationListResponse.Applications app: applications) {
            if (app.getId() == config.getApplicationId()) {
                testApplicationFound = true;
            }
        }
        assertTrue(testApplicationFound);
    }

    @Test
    public void applicationDetailTest() throws PowerAuthClientException {
        GetApplicationDetailResponse response = powerAuthClient.getApplicationDetail(config.getApplicationId());
        assertEquals(config.getApplicationName(), response.getApplicationName());
        boolean testAppVersionFound = false;
        for (GetApplicationDetailResponse.Versions version: response.getVersions()) {
            if (version.getApplicationVersionId() == config.getApplicationVersionId()) {
                testAppVersionFound = true;
            }
        }
        assertTrue(testAppVersionFound);
    }

    @Test
    public void applicationVersionLookupTest() throws PowerAuthClientException {
        LookupApplicationByAppKeyResponse response = powerAuthClient.lookupApplicationByAppKey(config.getApplicationKey());
        assertEquals(config.getApplicationId(), response.getApplicationId());
    }

    // createApplication and createApplication version tests are skipped to avoid creating too many applications

    @Test
    public void applicationSupportTest() throws PowerAuthClientException {
        UnsupportApplicationVersionResponse response = powerAuthClient.unsupportApplicationVersion(config.getApplicationVersionId());
        assertFalse(response.isSupported());
        SupportApplicationVersionResponse response2 = powerAuthClient.supportApplicationVersion(config.getApplicationVersionId());
        assertTrue(response2.isSupported());
    }

    @Test
    public void applicationIntegrationTest() throws PowerAuthClientException {
        String integrationName = UUID.randomUUID().toString();
        CreateIntegrationResponse response = powerAuthClient.createIntegration(integrationName);
        assertEquals(integrationName, response.getName());
        List<GetIntegrationListResponse.Items> items = powerAuthClient.getIntegrationList();
        boolean integrationFound = false;
        for (GetIntegrationListResponse.Items integration: items) {
            if (integration.getName().equals(integrationName)) {
                integrationFound = true;
            }
        }
        assertTrue(integrationFound);
        RemoveIntegrationResponse removeResponse = powerAuthClient.removeIntegration(response.getId());
        assertTrue(removeResponse.isRemoved());
    }

    @Test
    public void callbackTest() throws PowerAuthClientException {
        String callbackName = UUID.randomUUID().toString();
        String url = "http://test.wultra.com/";
        CreateCallbackUrlResponse response = powerAuthClient.createCallbackUrl(config.getApplicationId(), callbackName, CallbackUrlType.ACTIVATION_STATUS_CHANGE, url, Collections.emptyList(), null);
        assertEquals(callbackName, response.getName());
        List<GetCallbackUrlListResponse.CallbackUrlList> items = powerAuthClient.getCallbackUrlList(config.getApplicationId());
        boolean callbackFound = false;
        for (GetCallbackUrlListResponse.CallbackUrlList callback: items) {
            if (callback.getName().equals(callbackName)) {
                callbackFound = true;
            }
        }
        assertTrue(callbackFound);
        RemoveCallbackUrlResponse removeResponse = powerAuthClient.removeCallbackUrl(response.getId());
        assertTrue(removeResponse.isRemoved());
    }

    @Test
    public void createValidateAndRemoveTokenTest() throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException, IOException, EciesException, PowerAuthClientException {
        byte[] transportMasterKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "transportMasterKey"));
        byte[] serverPublicKeyBytes = BaseEncoding.base64().decode(JsonUtil.stringValue(config.getResultStatusObjectV31(), "serverPublicKey"));
        final ECPublicKey serverPublicKey = (ECPublicKey) keyConvertor.convertBytesToPublicKey(serverPublicKeyBytes);
        final EciesEncryptor eciesEncryptor = eciesFactory.getEciesEncryptorForActivation(serverPublicKey, config.getApplicationSecret().getBytes(StandardCharsets.UTF_8),
                transportMasterKeyBytes, EciesSharedInfo1.CREATE_TOKEN);
        final EciesCryptogram eciesCryptogram = eciesEncryptor.encryptRequest("{}".getBytes(StandardCharsets.UTF_8), true);
        EciesEncryptedRequest eciesRequest = new EciesEncryptedRequest();
        eciesRequest.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogram.getEphemeralPublicKey()));
        eciesRequest.setEncryptedData(BaseEncoding.base64().encode(eciesCryptogram.getEncryptedData()));
        eciesRequest.setMac(BaseEncoding.base64().encode(eciesCryptogram.getMac()));
        eciesRequest.setNonce(BaseEncoding.base64().encode(eciesCryptogram.getNonce()));
        CreateTokenResponse tokenResponse = powerAuthClient.createToken(config.getActivationIdV31(), config.getApplicationKey(), eciesRequest.getEphemeralPublicKey(), eciesRequest.getEncryptedData(),
                eciesRequest.getMac(), eciesRequest.getNonce(), SignatureType.POSSESSION_KNOWLEDGE);
        assertNotNull(tokenResponse.getEncryptedData());
        assertNotNull(tokenResponse.getMac());
        EciesCryptogram responseCryptogram = new EciesCryptogram(BaseEncoding.base64().decode(tokenResponse.getMac()), BaseEncoding.base64().decode(tokenResponse.getEncryptedData()));
        byte[] decryptedData = eciesEncryptor.decryptResponse(responseCryptogram);
        TokenResponsePayload response = objectMapper.readValue(decryptedData, TokenResponsePayload.class);
        assertNotNull(response.getTokenId());
        assertNotNull(response.getTokenSecret());
        BaseStepModel model = new BaseStepModel();
        model.setResultStatusObject(config.getResultStatusObjectV31());
        CounterUtil.incrementCounter(model);
        final byte[] tokenNonce = tokenGenerator.generateTokenNonce();
        final byte[] tokenTimestamp = tokenGenerator.generateTokenTimestamp();
        final byte[] tokenDigest = tokenGenerator.computeTokenDigest(tokenNonce, tokenTimestamp, BaseEncoding.base64().decode(response.getTokenSecret()));
        ValidateTokenResponse validateResponse = powerAuthClient.validateToken(response.getTokenId(), BaseEncoding.base64().encode(tokenNonce), Long.parseLong(new String(tokenTimestamp)), BaseEncoding.base64().encode(tokenDigest));
        assertTrue(validateResponse.isTokenValid());
        RemoveTokenResponse removeResponse = powerAuthClient.removeToken(response.getTokenId(), config.getActivationIdV31());
        assertTrue(removeResponse.isRemoved());
    }

    @Test
    public void getEciesDecryptorTest() throws CryptoProviderException, GenericCryptoException, EciesException, PowerAuthClientException {
        String requestData = "test_data";
        EciesEncryptor eciesEncryptor = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) config.getMasterPublicKey(), config.getApplicationSecret().getBytes(StandardCharsets.UTF_8), EciesSharedInfo1.APPLICATION_SCOPE_GENERIC);
        EciesCryptogram eciesCryptogram = eciesEncryptor.encryptRequest(requestData.getBytes(StandardCharsets.UTF_8), true);
        EciesEncryptedRequest encryptedRequest = new EciesEncryptedRequest();
        encryptedRequest.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogram.getEphemeralPublicKey()));
        encryptedRequest.setEncryptedData(BaseEncoding.base64().encode(eciesCryptogram.getEncryptedData()));
        encryptedRequest.setMac(BaseEncoding.base64().encode(eciesCryptogram.getMac()));
        encryptedRequest.setNonce(BaseEncoding.base64().encode(eciesCryptogram.getNonce()));
        final byte[] ephemeralPublicKeyBytes = eciesCryptogram.getEphemeralPublicKey();
        final byte[] encryptedDataBytes = eciesCryptogram.getEncryptedData();
        final byte[] macBytes = eciesCryptogram.getMac();
        final byte[] nonceBytes = eciesCryptogram.getNonce();
        GetEciesDecryptorRequest eciesDecryptorRequest = new GetEciesDecryptorRequest();
        eciesDecryptorRequest.setActivationId(null);
        eciesDecryptorRequest.setApplicationKey(config.getApplicationKey());
        eciesDecryptorRequest.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogram.getEphemeralPublicKey()));
        GetEciesDecryptorResponse eciesDecryptorResponse = powerAuthClient.getEciesDecryptor(eciesDecryptorRequest);
        final byte[] secretKey = BaseEncoding.base64().decode(eciesDecryptorResponse.getSecretKey());
        final EciesEnvelopeKey envelopeKey = new EciesEnvelopeKey(secretKey, ephemeralPublicKeyBytes);
        final byte[] sharedInfo2 = BaseEncoding.base64().decode(eciesDecryptorResponse.getSharedInfo2());
        final EciesDecryptor eciesDecryptor = eciesFactory.getEciesDecryptor(envelopeKey, sharedInfo2);
        EciesCryptogram cryptogram = new EciesCryptogram(ephemeralPublicKeyBytes, macBytes, encryptedDataBytes, nonceBytes);
        byte[] decryptedData = eciesDecryptor.decryptRequest(cryptogram);
        assertArrayEquals(requestData.getBytes(StandardCharsets.UTF_8), decryptedData);
    }

    @Test
    public void upgradeTest() throws CryptoProviderException, GenericCryptoException, InvalidKeyException, InvalidKeySpecException, EciesException, IOException, PowerAuthClientException {
        KeyPair clientEphemeralKeyPair = keyGenerator.generateKeyPair();
        KeyPair deviceKeyPair = activation.generateDeviceKeyPair();
        String activationIdentity = UUID.randomUUID().toString();
        String activationOTP = "00000-00000";
        byte[] nonceDeviceBytes = activation.generateActivationNonce();
        byte[] cDevicePublicKeyBytes = activation.encryptDevicePublicKey(deviceKeyPair.getPublic(), clientEphemeralKeyPair.getPrivate(), config.getMasterPublicKey(),
                activationOTP, activationIdentity, nonceDeviceBytes);
        byte[] signature = activation.computeApplicationSignature(activationIdentity, nonceDeviceBytes, cDevicePublicKeyBytes, BaseEncoding.base64().decode(config.getApplicationKey()),
                BaseEncoding.base64().decode(config.getApplicationSecret()));
        byte[] ephemeralPublicKeyBytes = keyConvertor.convertPublicKeyToBytes(clientEphemeralKeyPair.getPublic());
        com.wultra.security.powerauth.client.v2.CreateActivationResponse createResponse = powerAuthClient.v2().createActivation(config.getApplicationKey(), config.getUserV31(), activationIdentity,
                "test_activation_v2", BaseEncoding.base64().encode(nonceDeviceBytes),
                BaseEncoding.base64().encode(ephemeralPublicKeyBytes), BaseEncoding.base64().encode(cDevicePublicKeyBytes),
                null, BaseEncoding.base64().encode(signature));
        String activationId = createResponse.getActivationId();
        assertNotNull(activationId);
        byte[] nonceServerBytes = BaseEncoding.base64().decode(createResponse.getActivationNonce());
        byte[] cServerPubKeyBytes = BaseEncoding.base64().decode(createResponse.getEncryptedServerPublicKey());
        byte[] ephemeralKeyBytes = BaseEncoding.base64().decode(createResponse.getEphemeralPublicKey());
        PublicKey ephemeralPubKey = keyConvertor.convertBytesToPublicKey(ephemeralKeyBytes);
        PublicKey serverPublicKey = activation.decryptServerPublicKey(cServerPubKeyBytes, deviceKeyPair.getPrivate(),
                ephemeralPubKey, activationOTP, activationIdentity, nonceServerBytes);
        SecretKey masterSecretKey = keyFactory.generateClientMasterSecretKey(deviceKeyPair.getPrivate(), serverPublicKey);
        SecretKey transportMasterKey = keyFactory.generateServerTransportKey(masterSecretKey);
        powerAuthClient.commitActivation(activationId, null);
        byte[] transportMasterKeyBytes = keyConvertor.convertSharedSecretKeyToBytes(transportMasterKey);
        EciesEncryptor eciesEncryptor = eciesFactory.getEciesEncryptorForActivation((ECPublicKey) serverPublicKey,
                config.getApplicationSecret().getBytes(StandardCharsets.UTF_8), transportMasterKeyBytes, EciesSharedInfo1.UPGRADE);
        EciesCryptogram eciesCryptogram = eciesEncryptor.encryptRequest("{}".getBytes(StandardCharsets.UTF_8), true);
        String ephemeralPublicKey = BaseEncoding.base64().encode(eciesCryptogram.getEphemeralPublicKey());
        String encryptedData = BaseEncoding.base64().encode(eciesCryptogram.getEncryptedData());
        String mac = BaseEncoding.base64().encode(eciesCryptogram.getMac());
        String nonce = BaseEncoding.base64().encode(eciesCryptogram.getNonce());
        StartUpgradeResponse startResponse = powerAuthClient.startUpgrade(activationId, config.getApplicationKey(), ephemeralPublicKey, encryptedData, mac, nonce);
        byte[] macResponse = BaseEncoding.base64().decode(startResponse.getMac());
        byte[] encryptedDataResponse = BaseEncoding.base64().decode(startResponse.getEncryptedData());
        EciesCryptogram eciesCryptogramResponse = new EciesCryptogram(macResponse, encryptedDataResponse);
        byte[] decryptedBytes = eciesEncryptor.decryptResponse(eciesCryptogramResponse);
        UpgradeResponsePayload upgradeResponsePayload = objectMapper.readValue(decryptedBytes, UpgradeResponsePayload.class);
        assertNotNull(upgradeResponsePayload.getCtrData());
        CommitUpgradeResponse commitResponse = powerAuthClient.commitUpgrade(activationId, config.getApplicationKey());
        assertTrue(commitResponse.isCommitted());
    }

    @Test
    public void recoveryCodeCreateLookupRevokeTest() throws PowerAuthClientException {
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
    public void recoveryCodeConfirmAndActivationTest() throws CryptoProviderException, GenericCryptoException, IOException, EciesException, InvalidKeyException, InvalidKeySpecException, PowerAuthClientException {
        String activationName = "test_create_recovery";
        KeyPair deviceKeyPair = activation.generateDeviceKeyPair();
        byte[] devicePublicKeyBytes = keyConvertor.convertPublicKeyToBytes(deviceKeyPair.getPublic());
        String devicePublicKeyBase64 = BaseEncoding.base64().encode(devicePublicKeyBytes);
        ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(activationName);
        requestL2.setDevicePublicKey(devicePublicKeyBase64);
        EciesEncryptor eciesEncryptorL2 = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) config.getMasterPublicKey(), config.getApplicationSecret().getBytes(StandardCharsets.UTF_8), EciesSharedInfo1.ACTIVATION_LAYER_2);
        ByteArrayOutputStream baosL2 = new ByteArrayOutputStream();
        objectMapper.writeValue(baosL2, requestL2);
        EciesCryptogram eciesCryptogramL2 = eciesEncryptorL2.encryptRequest(baosL2.toByteArray(), true);
        EciesEncryptedRequest encryptedRequestL2 = new EciesEncryptedRequest();
        encryptedRequestL2.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogramL2.getEphemeralPublicKey()));
        encryptedRequestL2.setEncryptedData(BaseEncoding.base64().encode(eciesCryptogramL2.getEncryptedData()));
        encryptedRequestL2.setMac(BaseEncoding.base64().encode(eciesCryptogramL2.getMac()));
        encryptedRequestL2.setNonce(BaseEncoding.base64().encode(eciesCryptogramL2.getNonce()));
        CreateActivationResponse createResponse = powerAuthClient.createActivation(config.getUserV31(), null,
                null, config.getApplicationKey(), encryptedRequestL2.getEphemeralPublicKey(),
                encryptedRequestL2.getEncryptedData(), encryptedRequestL2.getMac(), encryptedRequestL2.getNonce());
        String activationId = createResponse.getActivationId();
        assertNotNull(activationId);
        EciesCryptogram cryptogram = new EciesCryptogram(BaseEncoding.base64().decode(createResponse.getMac()), BaseEncoding.base64().decode(createResponse.getEncryptedData()));
        byte[] responseRaw = eciesEncryptorL2.decryptResponse(cryptogram);
        ActivationLayer2Response responseL2 = objectMapper.readValue(responseRaw, ActivationLayer2Response.class);
        String recoveryCode = responseL2.getActivationRecovery().getRecoveryCode();
        String recoveryPuk = responseL2.getActivationRecovery().getPuk();
        PublicKey serverPublicKey = keyConvertor.convertBytesToPublicKey(BaseEncoding.base64().decode(responseL2.getServerPublicKey()));
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
        encryptedRequestConfirm.setEphemeralPublicKey(BaseEncoding.base64().encode(confirmCryptogram.getEphemeralPublicKey()));
        encryptedRequestConfirm.setEncryptedData(BaseEncoding.base64().encode(confirmCryptogram.getEncryptedData()));
        encryptedRequestConfirm.setMac(BaseEncoding.base64().encode(confirmCryptogram.getMac()));
        encryptedRequestConfirm.setNonce(BaseEncoding.base64().encode(confirmCryptogram.getNonce()));
        ConfirmRecoveryCodeResponse confirmResponse = powerAuthClient.confirmRecoveryCode(activationId, config.getApplicationKey(), encryptedRequestConfirm.getEphemeralPublicKey(),
                encryptedRequestConfirm.getEncryptedData(), encryptedRequestConfirm.getMac(), encryptedRequestConfirm.getNonce());
        EciesCryptogram confirmResponseCryptogram = new EciesCryptogram(BaseEncoding.base64().decode(confirmResponse.getMac()),
                BaseEncoding.base64().decode(confirmResponse.getEncryptedData()));
        byte[] confirmResponseRaw = encryptor.decryptResponse(confirmResponseCryptogram);
        ConfirmRecoveryResponsePayload confirmResponsePayload = RestClientConfiguration.defaultMapper().readValue(confirmResponseRaw, ConfirmRecoveryResponsePayload.class);
        assertTrue(confirmResponsePayload.getAlreadyConfirmed());
        KeyPair deviceKeyPairR = activation.generateDeviceKeyPair();
        byte[] devicePublicKeyBytesR = keyConvertor.convertPublicKeyToBytes(deviceKeyPairR.getPublic());
        String devicePublicKeyBase64R = BaseEncoding.base64().encode(devicePublicKeyBytesR);
        ActivationLayer2Request requestL2R = new ActivationLayer2Request();
        requestL2.setActivationName(activationName + "_2");
        requestL2.setDevicePublicKey(devicePublicKeyBase64R);
        EciesEncryptor eciesEncryptorL2R = eciesFactory.getEciesEncryptorForApplication((ECPublicKey) config.getMasterPublicKey(), config.getApplicationSecret().getBytes(StandardCharsets.UTF_8), EciesSharedInfo1.ACTIVATION_LAYER_2);
        ByteArrayOutputStream baosL2R = new ByteArrayOutputStream();
        objectMapper.writeValue(baosL2R, requestL2R);
        EciesCryptogram eciesCryptogramL2R = eciesEncryptorL2R.encryptRequest(baosL2R.toByteArray(), true);
        EciesEncryptedRequest encryptedRequestL2R = new EciesEncryptedRequest();
        encryptedRequestL2R.setEphemeralPublicKey(BaseEncoding.base64().encode(eciesCryptogramL2R.getEphemeralPublicKey()));
        encryptedRequestL2R.setEncryptedData(BaseEncoding.base64().encode(eciesCryptogramL2R.getEncryptedData()));
        encryptedRequestL2R.setMac(BaseEncoding.base64().encode(eciesCryptogramL2R.getMac()));
        encryptedRequestL2R.setNonce(BaseEncoding.base64().encode(eciesCryptogramL2R.getNonce()));
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
    public void recoveryConfigTest() throws PowerAuthClientException {
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

}