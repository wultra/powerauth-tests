/*
 * PowerAuth test and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.v3;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.powerauth.soap.v3.*;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.VerifySignatureStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import io.getlime.security.powerauth.lib.cmd.util.CounterUtil;
import io.getlime.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.json.simple.JSONObject;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthSignatureTest {

    private PowerAuthTestConfiguration config;
    private static File dataFile;
    private VerifySignatureStepModel model;
    private ObjectStepLogger stepLogger;

    private PowerAuthServiceClient powerAuthClient;

    private SignatureUtils signatureUtils = new SignatureUtils();

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Autowired
    public void setPowerAuthServiceClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @BeforeClass
    public static void setUpBeforeClass() throws IOException {
        dataFile = File.createTempFile("data", ".json");
        FileWriter fw = new FileWriter(dataFile);
        fw.write("All your base are belong to us!");
        fw.close();
    }

    @AfterClass
    public static void tearDownAfterClass() {
        assertTrue(dataFile.delete());
    }

    @Before
    public void setUp() {
        model = new VerifySignatureStepModel();
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setDataFileName(dataFile.getAbsolutePath());
        model.setHeaders(new HashMap<>());
        model.setHttpMethod("POST");
        model.setPassword(config.getPassword());
        model.setResourceId("/pa/signature/validate");
        model.setResultStatusObject(config.getResultStatusObjectV3());
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        model.setStatusFileName(config.getStatusFileV3().getAbsolutePath());
        model.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate");
        model.setVersion("3.0");

        stepLogger = new ObjectStepLogger(System.out);
    }

    @Test
    public void signatureValidTest() throws Exception {
        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        Response responseOK = (Response) stepLogger.getResponse().getResponseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    @Test
    public void signatureInvalidPasswordTest() throws Exception {
        model.setPassword("1111");
        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(401, stepLogger.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);
    }

    @Test
    public void signatureIncorrectPasswordFormatTest() throws Exception {
        model.setPassword("*");
        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(401, stepLogger.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);
    }

    @Test
    public void signatureCounterLookAheadTest() throws Exception {
        // Move counter by 1-4, next signature should succeed thanks to counter lookahead and it is still in max failure limit
        for (int i = 1; i < 4; i++) {
            for (int j=0; j < i; j++) {
                ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
                model.setPassword("1111");
                new VerifySignatureStep().execute(stepLogger, model.toMap());
                assertFalse(stepLogger.getResult().isSuccess());
                assertEquals(401, stepLogger.getResponse().getStatusCode());
            }

            ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
            model.setPassword(config.getPassword());
            new VerifySignatureStep().execute(stepLogger, model.toMap());
            assertTrue(stepLogger.getResult().isSuccess());
            assertEquals(200, stepLogger.getResponse().getStatusCode());

            Response responseOK = (Response) stepLogger.getResponse().getResponseObject();
            assertEquals("OK", responseOK.getStatus());
        }

    }

    @Test
    public void signatureBlockedActivationTest() throws Exception {
        powerAuthClient.blockActivation(config.getActivationIdV3(), "test", "test");

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new VerifySignatureStep().execute(stepLogger1, model.toMap());
        assertFalse(stepLogger1.getResult().isSuccess());
        assertEquals(401, stepLogger1.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);

        powerAuthClient.unblockActivation(config.getActivationIdV3(), "test");

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifySignatureStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().isSuccess());
        assertEquals(200, stepLogger2.getResponse().getStatusCode());
    }

    @Test
    public void signatureSingleFactorTest() throws Exception {
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION);

        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(401, stepLogger.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
    }

    @Test
    public void signatureBiometryTest() throws Exception {
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_BIOMETRY);

        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
    }

    @Test
    public void signatureThreeFactorTest() throws Exception {
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY);

        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
    }

    @Test
    public void signatureEmptyDataTest() throws Exception {
        File dataFile = File.createTempFile("data_empty_v3", ".json");
        dataFile.deleteOnExit();
        FileWriter fw = new FileWriter(dataFile);
        fw.close();
        model.setDataFileName(dataFile.getAbsolutePath());

        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        Response responseOK = (Response) stepLogger.getResponse().getResponseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    @Test
    public void signatureValidGetTest() throws Exception {
        model.setHttpMethod("GET");
        model.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate?who=John_Tramonta&when=now");
        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        Response responseOK = (Response) stepLogger.getResponse().getResponseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    @Test
    public void signatureValidGetNoParamTest() throws Exception {
        model.setHttpMethod("GET");
        model.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate");
        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        Response responseOK = (Response) stepLogger.getResponse().getResponseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    @Test
    public void signatureGetInvalidPasswordTest() throws Exception {
        model.setHttpMethod("GET");
        model.setPassword("0000");
        model.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate?who=John_Tramonta&when=now");
        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(401, stepLogger.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);
    }

    @Test
    public void signatureUnsupportedApplicationTest() throws Exception {
        powerAuthClient.unsupportApplicationVersion(config.getApplicationVersionId());

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new VerifySignatureStep().execute(stepLogger1, model.toMap());
        assertFalse(stepLogger1.getResult().isSuccess());
        assertEquals(401, stepLogger1.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);

        powerAuthClient.supportApplicationVersion(config.getApplicationVersionId());

        ObjectStepLogger stepLogger2 = new ObjectStepLogger(System.out);
        new VerifySignatureStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().isSuccess());
        assertEquals(200, stepLogger2.getResponse().getStatusCode());

        Response responseOK = (Response) stepLogger2.getResponse().getResponseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    @Test
    public void signatureMaxFailedAttemptsTest() throws Exception {
        // Create temp status file
        File tempStatusFile = File.createTempFile("pa_status", ".json");
        tempStatusFile.deleteOnExit();

        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV3());
        initRequest.setMaxFailureCount(3L);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        PrepareActivationStepModel modelPrepare = new PrepareActivationStepModel();
        modelPrepare.setActivationCode(initResponse.getActivationCode());
        modelPrepare.setActivationName("test v3");
        modelPrepare.setApplicationKey(config.getApplicationKey());
        modelPrepare.setApplicationSecret(config.getApplicationSecret());
        modelPrepare.setMasterPublicKey(config.getMasterPublicKey());
        modelPrepare.setHeaders(new HashMap<>());
        modelPrepare.setPassword(config.getPassword());
        modelPrepare.setStatusFileName(tempStatusFile.getAbsolutePath());
        modelPrepare.setResultStatusObject(resultStatusObject);
        modelPrepare.setUriString(config.getPowerAuthIntegrationUrl());
        modelPrepare.setVersion("3.0");

        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, modelPrepare.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(resultStatusObject);
        model.setPassword("1111");

        // Fail two signatures
        for (int i = 0; i < 2; i++) {
            ObjectStepLogger stepLoggerSignature = new ObjectStepLogger();
            new VerifySignatureStep().execute(stepLoggerSignature, model.toMap());
            assertFalse(stepLoggerSignature.getResult().isSuccess());
            assertEquals(401, stepLoggerSignature.getResponse().getStatusCode());
        }

        // Last signature before max failed attempts should be successful
        model.setPassword(config.getPassword());
        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifySignatureStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().isSuccess());
        assertEquals(200, stepLogger2.getResponse().getStatusCode());

        // Fail three signatures
        model.setPassword("1111");
        for (int i = 0; i < 3; i++) {
            ObjectStepLogger stepLoggerSignature = new ObjectStepLogger();
            new VerifySignatureStep().execute(stepLoggerSignature, model.toMap());
            assertFalse(stepLoggerSignature.getResult().isSuccess());
            assertEquals(401, stepLoggerSignature.getResponse().getStatusCode());
        }

        // Activation should be blocked
        GetActivationStatusResponse statusResponseBlocked = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.BLOCKED, statusResponseBlocked.getActivationStatus());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    public void signatureLookAheadTest() throws Exception {
        // Create temp status file
        File tempStatusFile = File.createTempFile("pa_status_lookahead", ".json");
        tempStatusFile.deleteOnExit();

        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV3());
        // High limit to test lookahead
        initRequest.setMaxFailureCount(100L);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        PrepareActivationStepModel modelPrepare = new PrepareActivationStepModel();
        modelPrepare.setActivationCode(initResponse.getActivationCode());
        modelPrepare.setActivationName("test v3");
        modelPrepare.setApplicationKey(config.getApplicationKey());
        modelPrepare.setApplicationSecret(config.getApplicationSecret());
        modelPrepare.setMasterPublicKey(config.getMasterPublicKey());
        modelPrepare.setHeaders(new HashMap<>());
        modelPrepare.setPassword(config.getPassword());
        modelPrepare.setStatusFileName(tempStatusFile.getAbsolutePath());
        modelPrepare.setResultStatusObject(resultStatusObject);
        modelPrepare.setUriString(config.getPowerAuthIntegrationUrl());
        modelPrepare.setVersion("3.0");

        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, modelPrepare.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(resultStatusObject);
        model.setPassword("1111");

        // Fail 19 signatures
        for (int i = 0; i < 19; i++) {
            ObjectStepLogger stepLoggerSignature = new ObjectStepLogger();
            new VerifySignatureStep().execute(stepLoggerSignature, model.toMap());
            assertFalse(stepLoggerSignature.getResult().isSuccess());
            assertEquals(401, stepLoggerSignature.getResponse().getStatusCode());
        }

        // Last signature before lookahead failure should be successful and should fix counter
        model.setPassword(config.getPassword());
        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifySignatureStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().isSuccess());
        assertEquals(200, stepLogger2.getResponse().getStatusCode());

        // Fail 20 signatures
        model.setPassword("1111");
        for (int i = 0; i < 20; i++) {
            ObjectStepLogger stepLoggerSignature = new ObjectStepLogger();
            new VerifySignatureStep().execute(stepLoggerSignature, model.toMap());
            assertFalse(stepLoggerSignature.getResult().isSuccess());
            assertEquals(401, stepLoggerSignature.getResponse().getStatusCode());
        }

        // Signature after lookahead failure should be fail
        model.setPassword(config.getPassword());
        ObjectStepLogger stepLogger3 = new ObjectStepLogger();
        new VerifySignatureStep().execute(stepLogger3, model.toMap());
        assertFalse(stepLogger3.getResult().isSuccess());
        assertEquals(401, stepLogger3.getResponse().getStatusCode());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    public void signatureCounterIncrementTest() throws Exception {
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        HashBasedCounter counter = new HashBasedCounter();
        for (int i = 1; i <= 10; i++) {
            ObjectStepLogger stepLoggerLoop = new ObjectStepLogger();
            new VerifySignatureStep().execute(stepLoggerLoop, model.toMap());
            assertTrue(stepLoggerLoop.getResult().isSuccess());
            assertEquals(200, stepLoggerLoop.getResponse().getStatusCode());

            // Verify hash based counter
            ctrData = counter.next(ctrData);
            assertArrayEquals(ctrData, CounterUtil.getCtrData(model, stepLoggerLoop));
        }
    }

    @Test
    public void signatureLargeDataTest() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        File dataFileLarge = File.createTempFile("data_large_v3", ".dat");
        dataFileLarge.deleteOnExit();
        FileWriter fw = new FileWriter(dataFileLarge);
        for (int i = 0; i < 10000; i++) {
            fw.write(secureRandom.nextInt());
        }
        fw.close();

        model.setDataFileName(dataFileLarge.getAbsolutePath());

        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        Response responseOK = (Response) stepLogger.getResponse().getResponseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    @Test
    public void signatureOfflinePersonalizedValidTest() throws Exception {
        String data = "5ff1b1ed-a3cc-45a3-8ab0-ed60950312b6\n" +
                "Payment\n" +
                "Please confirm this payment\n" +
                "A1*A100CZK*ICZ2730300000001165254011*D20180425\n" +
                "B";
        CreatePersonalizedOfflineSignaturePayloadResponse offlineResponse = powerAuthClient.createPersonalizedOfflineSignaturePayload(
                config.getActivationIdV3(), data);
        String nonce = offlineResponse.getNonce();
        String offlineData = offlineResponse.getOfflineData();

        // Split the offline data into individual lines
        String[] parts = offlineData.split("\n");

        // Extract last line which contains information about key and ECDSA signature
        String lastLine = parts[parts.length-1];

        // 1 = KEY_SERVER_PRIVATE was used to sign data (personalized offline signature)
        assertEquals("1", lastLine.substring(0, 1));

        // The remainder of last line is Base64 encoded ECDSA signature
        String ecdsaSignature = lastLine.substring(1);
        final byte[] serverPublicKeyBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("serverPublicKey"));
        final ECPublicKey serverPublicKey = (ECPublicKey) config.getKeyConversion().convertBytesToPublicKey(serverPublicKeyBytes);

        // Prepare offline data without signature
        String offlineDataWithoutSignature = offlineData.substring(0, offlineData.length() - ecdsaSignature.length());

        // Validate ECDSA signature of data using server public key
        assertTrue(signatureUtils.validateECDSASignature(offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8), BaseEncoding.base64().decode(ecdsaSignature), serverPublicKey));

        // Prepare normalized data for signature
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/operation/authorize/offline", BaseEncoding.base64().decode(nonce), data.getBytes(StandardCharsets.UTF_8));

        // Prepare keys
        byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));

        // Get the signature keys
        SecretKey signaturePossessionKey = config.getKeyConversion().convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, new KeyGenerator());

        // Put keys into a list
        List<SecretKey> signatureKeys = new ArrayList<>();
        signatureKeys.add(signaturePossessionKey);
        signatureKeys.add(signatureKnowledgeKey);

        // Calculate signature of normalized signature base string with 'offline' as application secret
        String signature = signatureUtils.computePowerAuthSignature((signatureBaseString + "&offline").getBytes(StandardCharsets.UTF_8), signatureKeys, CounterUtil.getCtrData(model, stepLogger));

        VerifyOfflineSignatureResponse signatureResponse = powerAuthClient.verifyOfflineSignature(config.getActivationIdV3(), signatureBaseString, signature, SignatureType.POSSESSION_KNOWLEDGE);
        assertTrue(signatureResponse.isSignatureValid());
        assertEquals(config.getActivationIdV3(), signatureResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, signatureResponse.getActivationStatus());
        assertEquals(BigInteger.valueOf(5), signatureResponse.getRemainingAttempts());
        assertEquals(SignatureType.POSSESSION_KNOWLEDGE, signatureResponse.getSignatureType());
        assertEquals(config.getApplicationId(), signatureResponse.getApplicationId());

        // Increment counter
        CounterUtil.incrementCounter(model);
    }

    @Test
    public void signatureOfflinePersonalizedInvalidTest() throws Exception {
        String data = "5ff1b1ed-a3cc-45a3-8ab0-ed60950312b6\n" +
                "Payment\n" +
                "Please confirm this payment\n" +
                "A1*A100CZK*ICZ2730300000001165254011*D20180425\n" +
                "B";
        CreatePersonalizedOfflineSignaturePayloadResponse offlineResponse = powerAuthClient.createPersonalizedOfflineSignaturePayload(
                config.getActivationIdV3(), data);
        String nonce = offlineResponse.getNonce();
        String offlineData = offlineResponse.getOfflineData();

        // Split the offline data into individual lines
        String[] parts = offlineData.split("\n");

        // Extract last line which contains information about key and ECDSA signature
        String lastLine = parts[parts.length-1];

        // 1 = KEY_SERVER_PRIVATE was used to sign data (personalized offline signature)
        assertEquals("1", lastLine.substring(0, 1));

        // The remainder of last line is Base64 encoded ECDSA signature
        String ecdsaSignature = lastLine.substring(1);
        final byte[] serverPublicKeyBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("serverPublicKey"));
        final ECPublicKey serverPublicKey = (ECPublicKey) config.getKeyConversion().convertBytesToPublicKey(serverPublicKeyBytes);

        // Prepare offline data without signature
        String offlineDataWithoutSignature = offlineData.substring(0, offlineData.length() - ecdsaSignature.length());

        // Validate ECDSA signature of data using server public key
        assertTrue(signatureUtils.validateECDSASignature(offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8), BaseEncoding.base64().decode(ecdsaSignature), serverPublicKey));

        // Prepare normalized data for signature
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/operation/authorize/offline", BaseEncoding.base64().decode(nonce), data.getBytes(StandardCharsets.UTF_8));

        // Prepare keys
        byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));

        // Get the signature keys
        SecretKey signaturePossessionKey = config.getKeyConversion().convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, new KeyGenerator());

        // Put keys into a list
        List<SecretKey> signatureKeys = new ArrayList<>();
        signatureKeys.add(signaturePossessionKey);
        signatureKeys.add(signatureKnowledgeKey);

        // Calculate signature of normalized signature base string with 'offline' as application secret
        String signature = signatureUtils.computePowerAuthSignature((signatureBaseString + "&offline").getBytes(StandardCharsets.UTF_8), signatureKeys, CounterUtil.getCtrData(model, stepLogger));

        // Cripple signature
        String digitToReplace = signature.substring(0, 1);
        String replacedDigit = String.valueOf((Integer.valueOf(digitToReplace) + 1) % 10);
        signature = signature.replace(digitToReplace, replacedDigit);

        VerifyOfflineSignatureResponse signatureResponse = powerAuthClient.verifyOfflineSignature(config.getActivationIdV3(), signatureBaseString, signature, SignatureType.POSSESSION_KNOWLEDGE);
        assertFalse(signatureResponse.isSignatureValid());
        assertEquals(config.getActivationIdV3(), signatureResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, signatureResponse.getActivationStatus());
        assertTrue(signatureResponse.getRemainingAttempts().intValue() < 5);
        assertEquals(SignatureType.POSSESSION_KNOWLEDGE, signatureResponse.getSignatureType());
        assertEquals(config.getApplicationId(), signatureResponse.getApplicationId());
    }

    @Test
    public void signatureOfflineNonPersonalizedValidTest() throws Exception {
        String data = "5ff1b1ed-a3cc-45a3-8ab0-ed60950312b6\n" +
                "Payment\n" +
                "Please confirm this payment\n" +
                "A1*A100CZK*ICZ2730300000001165254011*D20180425\n" +
                "B";
        CreateNonPersonalizedOfflineSignaturePayloadResponse offlineResponse = powerAuthClient.createNonPersonalizedOfflineSignaturePayload(
                config.getApplicationId(), data);
        String nonce = offlineResponse.getNonce();
        String offlineData = offlineResponse.getOfflineData();

        // Split the offline data into individual lines
        String[] parts = offlineData.split("\n");

        // Extract last line which contains information about key and ECDSA signature
        String lastLine = parts[parts.length-1];

        // 1 = KEY_SERVER_MASTER_PRIVATE was used to sign data (non-personalized offline signature)
        assertEquals("0", lastLine.substring(0, 1));

        // The remainder of last line is Base64 encoded ECDSA signature
        String ecdsaSignature = lastLine.substring(1);

        // Prepare offline data without signature
        String offlineDataWithoutSignature = offlineData.substring(0, offlineData.length() - ecdsaSignature.length());

        // Validate ECDSA signature of data using server public key
        assertTrue(signatureUtils.validateECDSASignature(offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8), BaseEncoding.base64().decode(ecdsaSignature), config.getMasterPublicKey()));

        // Prepare normalized data for signature
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/operation/authorize/offline", BaseEncoding.base64().decode(nonce), data.getBytes(StandardCharsets.UTF_8));

        // Prepare keys
        byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));

        // Get the signature keys
        SecretKey signaturePossessionKey = config.getKeyConversion().convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, new KeyGenerator());

        // Put keys into a list
        List<SecretKey> signatureKeys = new ArrayList<>();
        signatureKeys.add(signaturePossessionKey);
        signatureKeys.add(signatureKnowledgeKey);

        // Calculate signature of normalized signature base string with 'offline' as application secret
        String signature = signatureUtils.computePowerAuthSignature((signatureBaseString + "&offline").getBytes(StandardCharsets.UTF_8), signatureKeys, CounterUtil.getCtrData(model, stepLogger));

        VerifyOfflineSignatureResponse signatureResponse = powerAuthClient.verifyOfflineSignature(config.getActivationIdV3(), signatureBaseString, signature, SignatureType.POSSESSION_KNOWLEDGE);
        assertTrue(signatureResponse.isSignatureValid());
        assertEquals(config.getActivationIdV3(), signatureResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, signatureResponse.getActivationStatus());
        assertEquals(BigInteger.valueOf(5), signatureResponse.getRemainingAttempts());
        assertEquals(SignatureType.POSSESSION_KNOWLEDGE, signatureResponse.getSignatureType());
        assertEquals(config.getApplicationId(), signatureResponse.getApplicationId());

        // Increment counter
        CounterUtil.incrementCounter(model);
    }

    @Test
    public void signatureOfflineNonPersonalizedInvalidTest() throws Exception {
        String data = "5ff1b1ed-a3cc-45a3-8ab0-ed60950312b6\n" +
                "Payment\n" +
                "Please confirm this payment\n" +
                "A1*A100CZK*ICZ2730300000001165254011*D20180425\n" +
                "B";
        CreateNonPersonalizedOfflineSignaturePayloadResponse offlineResponse = powerAuthClient.createNonPersonalizedOfflineSignaturePayload(
                config.getApplicationId(), data);
        String nonce = offlineResponse.getNonce();
        String offlineData = offlineResponse.getOfflineData();

        // Split the offline data into individual lines
        String[] parts = offlineData.split("\n");

        // Extract last line which contains information about key and ECDSA signature
        String lastLine = parts[parts.length-1];

        // 1 = KEY_SERVER_MASTER_PRIVATE was used to sign data (non-personalized offline signature)
        assertEquals("0", lastLine.substring(0, 1));

        // The remainder of last line is Base64 encoded ECDSA signature
        String ecdsaSignature = lastLine.substring(1);

        // Prepare offline data without signature
        String offlineDataWithoutSignature = offlineData.substring(0, offlineData.length() - ecdsaSignature.length());

        // Validate ECDSA signature of data using server public key
        assertTrue(signatureUtils.validateECDSASignature(offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8), BaseEncoding.base64().decode(ecdsaSignature), config.getMasterPublicKey()));

        // Prepare normalized data for signature
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/operation/authorize/offline", BaseEncoding.base64().decode(nonce), data.getBytes(StandardCharsets.UTF_8));

        // Prepare keys
        byte[] signaturePossessionKeyBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = BaseEncoding.base64().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));

        // Get the signature keys
        SecretKey signaturePossessionKey = config.getKeyConversion().convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, new KeyGenerator());

        // Put keys into a list
        List<SecretKey> signatureKeys = new ArrayList<>();
        signatureKeys.add(signaturePossessionKey);
        signatureKeys.add(signatureKnowledgeKey);

        // Calculate signature of normalized signature base string with 'offline' as application secret
        String signature = signatureUtils.computePowerAuthSignature((signatureBaseString + "&offline").getBytes(StandardCharsets.UTF_8), signatureKeys, CounterUtil.getCtrData(model, stepLogger));

        // Cripple signature
        String digitToReplace = signature.substring(0, 1);
        String replacedDigit = String.valueOf((Integer.valueOf(digitToReplace) + 1) % 10);
        signature = signature.replace(digitToReplace, replacedDigit);

        VerifyOfflineSignatureResponse signatureResponse = powerAuthClient.verifyOfflineSignature(config.getActivationIdV3(), signatureBaseString, signature, SignatureType.POSSESSION_KNOWLEDGE);
        assertFalse(signatureResponse.isSignatureValid());
        assertEquals(config.getActivationIdV3(), signatureResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, signatureResponse.getActivationStatus());
        assertTrue(signatureResponse.getRemainingAttempts().intValue() < 5);
        assertEquals(SignatureType.POSSESSION_KNOWLEDGE, signatureResponse.getSignatureType());
        assertEquals(config.getApplicationId(), signatureResponse.getApplicationId());
    }

    @Test
    public void signatureSwappedKeyTest() throws Exception {
        // Save biometry key
        String biometryKeyOrig = (String) model.getResultStatusObject().get("signatureBiometryKey");
        // Set possession key as biometry key
        model.getResultStatusObject().put("signatureBiometryKey", model.getResultStatusObject().get("signaturePossessionKey"));
        // Verify three factor signature
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY);

        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(401, stepLogger.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);

        // Revert biometry key change
        model.getResultStatusObject().put("signatureBiometryKey", biometryKeyOrig);
    }

    @Test
    public void signatureInvalidResourceIdTest() throws Exception {
        // Set invalid resource ID
        model.setResourceId("/pa/signature/invalid");

        // Verify two factor signature
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);

        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(401, stepLogger.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);

        // Revert resource ID
        model.setResourceId("/pa/signature/validate");
    }

    private void checkSignatureError(ErrorResponse errorResponse) {
        // Errors differ when Web Flow is used because of its Exception handler
        assertTrue("POWERAUTH_AUTH_FAIL".equals(errorResponse.getResponseObject().getCode()) || "ERR_AUTHENTICATION".equals(errorResponse.getResponseObject().getCode()));
        assertTrue("Signature validation failed".equals(errorResponse.getResponseObject().getMessage()) || "POWER_AUTH_SIGNATURE_INVALID_VALUE".equals(errorResponse.getResponseObject().getMessage()));
    }

}
