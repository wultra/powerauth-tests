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
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.CreatePersonalizedOfflineSignaturePayloadRequest;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.VerifyOfflineSignatureRequest;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.crypto.lib.config.SignatureConfiguration;
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
import org.json.simple.JSONObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthSignatureTest {

    private PowerAuthTestConfiguration config;
    private static File dataFile;
    private VerifySignatureStepModel model;
    private ObjectStepLogger stepLogger;

    private PowerAuthClient powerAuthClient;

    private final SignatureUtils signatureUtils = new SignatureUtils();

    // Data for offline signatures
    private final String operationId = "5ff1b1ed-a3cc-45a3-8ab0-ed60950312b6";
    private final String operationData = "A1*A100CZK*ICZ2730300000001165254011*D20180425";
    private final String title = "Payment";
    private final String message = "Please confirm this payment";
    private final String flags = "B";
    private final String offlineData = operationId + "\n" + title + "\n" + message + "\n" + operationData + "\n" + flags;

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @BeforeAll
    static void setUpBeforeClass() throws IOException {
        dataFile = File.createTempFile("data", ".json");
        FileWriter fw = new FileWriter(dataFile);
        fw.write("All your base are belong to us!");
        fw.close();
    }

    @AfterAll
    static void tearDownAfterClass() {
        assertTrue(dataFile.delete());
    }

    @BeforeEach
    void setUp() throws IOException {
        model = new VerifySignatureStepModel();
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));
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
    void signatureValidTest() throws Exception {
        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Response responseOK = (Response) stepLogger.getResponse().responseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    @Test
    void signatureInvalidPasswordTest() throws Exception {
        model.setPassword("1111");
        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);
    }

    @Test
    void signatureIncorrectPasswordFormatTest() throws Exception {
        model.setPassword("*");
        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);
    }

    @Test
    void signatureCounterLookAheadTest() throws Exception {
        // Move counter by 1-4, next signature should succeed thanks to counter lookahead and it is still in max failure limit
        for (int i = 1; i < 4; i++) {
            for (int j=0; j < i; j++) {
                ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
                model.setPassword("1111");
                new VerifySignatureStep().execute(stepLogger, model.toMap());
                assertFalse(stepLogger.getResult().success());
                assertEquals(401, stepLogger.getResponse().statusCode());
            }

            ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
            model.setPassword(config.getPassword());
            new VerifySignatureStep().execute(stepLogger, model.toMap());
            assertTrue(stepLogger.getResult().success());
            assertEquals(200, stepLogger.getResponse().statusCode());

            final Response responseOK = (Response) stepLogger.getResponse().responseObject();
            assertEquals("OK", responseOK.getStatus());
        }

    }

    @Test
    void signatureBlockedActivationTest() throws Exception {
        powerAuthClient.blockActivation(config.getActivationIdV3(), "test", "test");

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new VerifySignatureStep().execute(stepLogger1, model.toMap());
        assertFalse(stepLogger1.getResult().success());
        assertEquals(401, stepLogger1.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);

        powerAuthClient.unblockActivation(config.getActivationIdV3(), "test");

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifySignatureStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());
    }

    @Test
    void signatureSingleFactorTest() throws Exception {
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION);

        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    @Test
    void signatureBiometryTest() throws Exception {
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_BIOMETRY);

        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    @Test
    void signatureThreeFactorTest() throws Exception {
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY);

        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    @Test
    void signatureEmptyDataTest() throws Exception {
        File dataFile = File.createTempFile("data_empty_v3", ".json");
        dataFile.deleteOnExit();
        FileWriter fw = new FileWriter(dataFile);
        fw.close();
        model.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));

        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Response responseOK = (Response) stepLogger.getResponse().responseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    @Test
    void signatureValidGetTest() throws Exception {
        model.setHttpMethod("GET");
        model.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate?who=John_Tramonta&when=now");
        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Response responseOK = (Response) stepLogger.getResponse().responseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    @Test
    void signatureValidGetNoParamTest() throws Exception {
        model.setHttpMethod("GET");
        model.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate");
        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Response responseOK = (Response) stepLogger.getResponse().responseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    @Test
    void signatureGetInvalidPasswordTest() throws Exception {
        model.setHttpMethod("GET");
        model.setPassword("0000");
        model.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate?who=John_Tramonta&when=now");
        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);
    }

    @Test
    void signatureUnsupportedApplicationTest() throws Exception {
        powerAuthClient.unsupportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new VerifySignatureStep().execute(stepLogger1, model.toMap());
        assertFalse(stepLogger1.getResult().success());
        assertEquals(401, stepLogger1.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);

        powerAuthClient.supportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        ObjectStepLogger stepLogger2 = new ObjectStepLogger(System.out);
        new VerifySignatureStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        final Response responseOK = (Response) stepLogger2.getResponse().responseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    @Test
    void signatureMaxFailedAttemptsTest() throws Exception {
        // Create temp status file
        File tempStatusFile = File.createTempFile("pa_status", ".json");
        tempStatusFile.deleteOnExit();

        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        final InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV3());
        initRequest.setMaxFailureCount(3L);
        final InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

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
        modelPrepare.setDeviceInfo("backend-tests");

        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, modelPrepare.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

        // Commit activation
        final CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(resultStatusObject);
        model.setPassword("1111");

        // Fail two signatures
        for (int i = 0; i < 2; i++) {
            ObjectStepLogger stepLoggerSignature = new ObjectStepLogger();
            new VerifySignatureStep().execute(stepLoggerSignature, model.toMap());
            assertFalse(stepLoggerSignature.getResult().success());
            assertEquals(401, stepLoggerSignature.getResponse().statusCode());
        }

        // Last signature before max failed attempts should be successful
        model.setPassword(config.getPassword());
        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifySignatureStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        // Fail three signatures
        model.setPassword("1111");
        for (int i = 0; i < 3; i++) {
            ObjectStepLogger stepLoggerSignature = new ObjectStepLogger();
            new VerifySignatureStep().execute(stepLoggerSignature, model.toMap());
            assertFalse(stepLoggerSignature.getResult().success());
            assertEquals(401, stepLoggerSignature.getResponse().statusCode());
        }

        // Activation should be blocked
        final GetActivationStatusResponse statusResponseBlocked = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.BLOCKED, statusResponseBlocked.getActivationStatus());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    void signatureLookAheadTest() throws Exception {
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
        modelPrepare.setDeviceInfo("backend-tests");

        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, modelPrepare.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

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
            assertFalse(stepLoggerSignature.getResult().success());
            assertEquals(401, stepLoggerSignature.getResponse().statusCode());
        }

        // Last signature before lookahead failure should be successful and should fix counter
        model.setPassword(config.getPassword());
        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifySignatureStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        // Fail 20 signatures
        model.setPassword("1111");
        for (int i = 0; i < 20; i++) {
            ObjectStepLogger stepLoggerSignature = new ObjectStepLogger();
            new VerifySignatureStep().execute(stepLoggerSignature, model.toMap());
            assertFalse(stepLoggerSignature.getResult().success());
            assertEquals(401, stepLoggerSignature.getResponse().statusCode());
        }

        // Signature after lookahead failure should be fail
        model.setPassword(config.getPassword());
        ObjectStepLogger stepLogger3 = new ObjectStepLogger();
        new VerifySignatureStep().execute(stepLogger3, model.toMap());
        assertFalse(stepLogger3.getResult().success());
        assertEquals(401, stepLogger3.getResponse().statusCode());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    void signatureCounterIncrementTest() throws Exception {
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        HashBasedCounter counter = new HashBasedCounter();
        for (int i = 1; i <= 10; i++) {
            ObjectStepLogger stepLoggerLoop = new ObjectStepLogger();
            new VerifySignatureStep().execute(stepLoggerLoop, model.toMap());
            assertTrue(stepLoggerLoop.getResult().success());
            assertEquals(200, stepLoggerLoop.getResponse().statusCode());

            // Verify hash based counter
            ctrData = counter.next(ctrData);
            assertArrayEquals(ctrData, CounterUtil.getCtrData(model, stepLoggerLoop));
        }
    }

    @Test
    void signatureLargeDataTest() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        File dataFileLarge = File.createTempFile("data_large_v3", ".dat");
        dataFileLarge.deleteOnExit();
        FileWriter fw = new FileWriter(dataFileLarge);
        for (int i = 0; i < 10000; i++) {
            fw.write(secureRandom.nextInt());
        }
        fw.close();

        model.setData(Files.readAllBytes(Paths.get(dataFileLarge.getAbsolutePath())));

        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Response responseOK = (Response) stepLogger.getResponse().responseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    @Test
    void signatureOfflinePersonalizedValidTest() throws Exception {
        final CreatePersonalizedOfflineSignaturePayloadResponse offlineResponse = powerAuthClient.createPersonalizedOfflineSignaturePayload(
                config.getActivationIdV3(), offlineData);
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
        final byte[] serverPublicKeyBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("serverPublicKey"));
        final ECPublicKey serverPublicKey = (ECPublicKey) config.getKeyConvertor().convertBytesToPublicKey(serverPublicKeyBytes);

        // Prepare offline data without signature
        String offlineDataWithoutSignature = offlineData.substring(0, offlineData.length() - ecdsaSignature.length());

        // Validate ECDSA signature of data using server public key
        assertTrue(signatureUtils.validateECDSASignature(offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(ecdsaSignature), serverPublicKey));

        // Prepare data for PowerAuth signature
        String dataForSignature = operationId + "&" + operationData;

        // Prepare normalized data for signature
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/operation/authorize/offline", Base64.getDecoder().decode(nonce), dataForSignature.getBytes(StandardCharsets.UTF_8));

        // Prepare keys
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));

        // Get the signature keys
        SecretKey signaturePossessionKey = config.getKeyConvertor().convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, new KeyGenerator());

        // Put keys into a list
        List<SecretKey> signatureKeys = new ArrayList<>();
        signatureKeys.add(signaturePossessionKey);
        signatureKeys.add(signatureKnowledgeKey);

        // Calculate signature of normalized signature base string with 'offline' as application secret
        String signature = signatureUtils.computePowerAuthSignature((signatureBaseString + "&offline").getBytes(StandardCharsets.UTF_8), signatureKeys, CounterUtil.getCtrData(model, stepLogger), SignatureConfiguration.decimal());

        final VerifyOfflineSignatureResponse signatureResponse = powerAuthClient.verifyOfflineSignature(config.getActivationIdV3(), signatureBaseString, signature, true);
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
    void testSignatureOfflinePersonalizedProximityCheckValid() throws Exception {
        testSignatureOfflinePersonalizedProximityCheck(true);
    }
    @Test
    void testSignatureOfflinePersonalizedProximityCheckInvalid() throws Exception {
        testSignatureOfflinePersonalizedProximityCheck(false);
    }

    private void testSignatureOfflinePersonalizedProximityCheck(final boolean expectedResult) throws Exception {
        final String seed = "LtxE0f0RWNx3hy7ISjUPWA==";

        final CreatePersonalizedOfflineSignaturePayloadRequest request = new CreatePersonalizedOfflineSignaturePayloadRequest();
        request.setActivationId(config.getActivationIdV3());
        request.setData(offlineData);
        request.setProximityCheck(new CreatePersonalizedOfflineSignaturePayloadRequest.ProximityCheck());
        request.getProximityCheck().setSeed(seed);
        request.getProximityCheck().setStepLength(30);

        final CreatePersonalizedOfflineSignaturePayloadResponse offlineResponse = powerAuthClient.createPersonalizedOfflineSignaturePayload(request);
        final String nonce = offlineResponse.getNonce();
        final String offlineDataResponse = offlineResponse.getOfflineData();

        final String[] parts = offlineDataResponse.split("\n");

        // Extract last line which contains information about key and ECDSA signature
        final String lastLine = parts[parts.length - 1];

        // 1 = KEY_SERVER_PRIVATE was used to sign data (personalized offline signature)
        assertEquals("1", lastLine.substring(0, 1));

        // The remainder of last line is Base64 encoded ECDSA signature
        final String ecdsaSignature = lastLine.substring(1);
        final byte[] serverPublicKeyBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("serverPublicKey"));
        final ECPublicKey serverPublicKey = (ECPublicKey) config.getKeyConvertor().convertBytesToPublicKey(serverPublicKeyBytes);

        // Prepare offline data without signature
        final String offlineDataWithoutSignature = offlineDataResponse.substring(0, offlineDataResponse.length() - ecdsaSignature.length());

        // Validate ECDSA signature of data using server public key
        assertTrue(signatureUtils.validateECDSASignature(offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(ecdsaSignature), serverPublicKey));

        // Prepare data for PowerAuth signature
        final String proximityTotp = parts[5];
        final String dataForSignatureWithOtp = operationId + "&" + operationData + "&" + proximityTotp;

        // Prepare normalized data for signature
        final String signatureBaseStringWithOtp = PowerAuthHttpBody.getSignatureBaseString("POST", "/operation/authorize/offline", Base64.getDecoder().decode(nonce), dataForSignatureWithOtp.getBytes(StandardCharsets.UTF_8));

        // Prepare keys
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));

        // Get the signature keys
        final SecretKey signaturePossessionKey = config.getKeyConvertor().convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        final SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, new KeyGenerator());

        // Put keys into a list
        final List<SecretKey> signatureKeys = new ArrayList<>();
        signatureKeys.add(signaturePossessionKey);
        signatureKeys.add(signatureKnowledgeKey);

        // Calculate signature of normalized signature base string with 'offline' as application secret
        final String signature = signatureUtils.computePowerAuthSignature((signatureBaseStringWithOtp + "&offline").getBytes(StandardCharsets.UTF_8), signatureKeys, CounterUtil.getCtrData(model, stepLogger), SignatureConfiguration.decimal());

        final String dataForSignature= operationId + "&" + operationData;
        final String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/operation/authorize/offline", Base64.getDecoder().decode(nonce), dataForSignature.getBytes(StandardCharsets.UTF_8));

        final VerifyOfflineSignatureRequest verifyRequest = new VerifyOfflineSignatureRequest();
        verifyRequest.setActivationId(config.getActivationIdV3());
        verifyRequest.setData(signatureBaseString);
        verifyRequest.setSignature(signature);
        verifyRequest.setAllowBiometry(true);
        verifyRequest.setProximityCheck(new VerifyOfflineSignatureRequest.ProximityCheck());
        verifyRequest.getProximityCheck().setSeed(expectedResult ? seed : "bGlnaHQgd28=");
        verifyRequest.getProximityCheck().setStepLength(30);
        verifyRequest.getProximityCheck().setStepCount(2);

        final VerifyOfflineSignatureResponse signatureResponse = powerAuthClient.verifyOfflineSignature(verifyRequest);
        assertEquals(expectedResult, signatureResponse.isSignatureValid());
        assertEquals(config.getActivationIdV3(), signatureResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, signatureResponse.getActivationStatus());
        final BigInteger expectedRemainingAttempts = BigInteger.valueOf(expectedResult ? 5 : 4);
        assertEquals(expectedRemainingAttempts, signatureResponse.getRemainingAttempts());
        assertEquals(SignatureType.POSSESSION_KNOWLEDGE, signatureResponse.getSignatureType());
        assertEquals(config.getApplicationId(), signatureResponse.getApplicationId());

        CounterUtil.incrementCounter(model);
    }

    @Test
    void signatureOfflinePersonalizedInvalidTest() throws Exception {

        CreatePersonalizedOfflineSignaturePayloadResponse offlineResponse = powerAuthClient.createPersonalizedOfflineSignaturePayload(
                config.getActivationIdV3(), offlineData);
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
        final byte[] serverPublicKeyBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("serverPublicKey"));
        final ECPublicKey serverPublicKey = (ECPublicKey) config.getKeyConvertor().convertBytesToPublicKey(serverPublicKeyBytes);

        // Prepare offline data without signature
        String offlineDataWithoutSignature = offlineData.substring(0, offlineData.length() - ecdsaSignature.length());

        // Validate ECDSA signature of data using server public key
        assertTrue(signatureUtils.validateECDSASignature(offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(ecdsaSignature), serverPublicKey));

        // Prepare data for PowerAuth signature
        String dataForSignature = operationId + "&" + operationData;

        // Prepare normalized data for signature
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/operation/authorize/offline", Base64.getDecoder().decode(nonce), dataForSignature.getBytes(StandardCharsets.UTF_8));

        // Prepare keys
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));

        // Get the signature keys
        SecretKey signaturePossessionKey = config.getKeyConvertor().convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, new KeyGenerator());

        // Put keys into a list
        List<SecretKey> signatureKeys = new ArrayList<>();
        signatureKeys.add(signaturePossessionKey);
        signatureKeys.add(signatureKnowledgeKey);

        // Calculate signature of normalized signature base string with 'offline' as application secret
        String signature = signatureUtils.computePowerAuthSignature((signatureBaseString + "&offline").getBytes(StandardCharsets.UTF_8), signatureKeys, CounterUtil.getCtrData(model, stepLogger), SignatureConfiguration.decimal());

        // Cripple signature
        String digitToReplace = signature.substring(0, 1);
        final String replacedDigit = String.valueOf((Integer.parseInt(digitToReplace) + 1) % 10);
        signature = signature.replace(digitToReplace, replacedDigit);

        VerifyOfflineSignatureResponse signatureResponse = powerAuthClient.verifyOfflineSignature(config.getActivationIdV3(), signatureBaseString, signature, true);
        assertFalse(signatureResponse.isSignatureValid());
        assertEquals(config.getActivationIdV3(), signatureResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, signatureResponse.getActivationStatus());
        assertTrue(signatureResponse.getRemainingAttempts().intValue() < 5);
        assertEquals(SignatureType.POSSESSION_KNOWLEDGE, signatureResponse.getSignatureType());
        assertEquals(config.getApplicationId(), signatureResponse.getApplicationId());
    }

    @Test
    void signatureOfflineNonPersonalizedValidTest() throws Exception {
        CreateNonPersonalizedOfflineSignaturePayloadResponse offlineResponse = powerAuthClient.createNonPersonalizedOfflineSignaturePayload(
                config.getApplicationId(), offlineData);
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
        assertTrue(signatureUtils.validateECDSASignature(offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(ecdsaSignature), config.getMasterPublicKey()));

        // Prepare data for PowerAuth signature
        String dataForSignature = operationId + "&" + operationData;

        // Prepare normalized data for signature
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/operation/authorize/offline", Base64.getDecoder().decode(nonce), dataForSignature.getBytes(StandardCharsets.UTF_8));

        // Prepare keys
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));

        // Get the signature keys
        SecretKey signaturePossessionKey = config.getKeyConvertor().convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, new KeyGenerator());

        // Put keys into a list
        List<SecretKey> signatureKeys = new ArrayList<>();
        signatureKeys.add(signaturePossessionKey);
        signatureKeys.add(signatureKnowledgeKey);

        // Calculate signature of normalized signature base string with 'offline' as application secret
        String signature = signatureUtils.computePowerAuthSignature((signatureBaseString + "&offline").getBytes(StandardCharsets.UTF_8), signatureKeys, CounterUtil.getCtrData(model, stepLogger), SignatureConfiguration.decimal());

        VerifyOfflineSignatureResponse signatureResponse = powerAuthClient.verifyOfflineSignature(config.getActivationIdV3(), signatureBaseString, signature, true);
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
    void signatureOfflineNonPersonalizedInvalidTest() throws Exception {
        CreateNonPersonalizedOfflineSignaturePayloadResponse offlineResponse = powerAuthClient.createNonPersonalizedOfflineSignaturePayload(
                config.getApplicationId(), offlineData);
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
        assertTrue(signatureUtils.validateECDSASignature(offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(ecdsaSignature), config.getMasterPublicKey()));

        // Prepare data for PowerAuth signature
        String dataForSignature = operationId + "&" + operationData;

        // Prepare normalized data for signature
        String signatureBaseString = PowerAuthHttpBody.getSignatureBaseString("POST", "/operation/authorize/offline", Base64.getDecoder().decode(nonce), dataForSignature.getBytes(StandardCharsets.UTF_8));

        // Prepare keys
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));

        // Get the signature keys
        SecretKey signaturePossessionKey = config.getKeyConvertor().convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getSignatureKnowledgeKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, new KeyGenerator());

        // Put keys into a list
        List<SecretKey> signatureKeys = new ArrayList<>();
        signatureKeys.add(signaturePossessionKey);
        signatureKeys.add(signatureKnowledgeKey);

        // Calculate signature of normalized signature base string with 'offline' as application secret
        String signature = signatureUtils.computePowerAuthSignature((signatureBaseString + "&offline").getBytes(StandardCharsets.UTF_8), signatureKeys, CounterUtil.getCtrData(model, stepLogger), SignatureConfiguration.decimal());

        // Cripple signature
        String digitToReplace = signature.substring(0, 1);
        final String replacedDigit = String.valueOf((Integer.parseInt(digitToReplace) + 1) % 10);
        signature = signature.replace(digitToReplace, replacedDigit);

        VerifyOfflineSignatureResponse signatureResponse = powerAuthClient.verifyOfflineSignature(config.getActivationIdV3(), signatureBaseString, signature, true);
        assertFalse(signatureResponse.isSignatureValid());
        assertEquals(config.getActivationIdV3(), signatureResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, signatureResponse.getActivationStatus());
        assertTrue(signatureResponse.getRemainingAttempts().intValue() < 5);
        assertEquals(SignatureType.POSSESSION_KNOWLEDGE, signatureResponse.getSignatureType());
        assertEquals(config.getApplicationId(), signatureResponse.getApplicationId());
    }

    @Test
    void signatureSwappedKeyTest() throws Exception {
        // Save biometry key
        String biometryKeyOrig = (String) model.getResultStatusObject().get("signatureBiometryKey");
        // Set possession key as biometry key
        model.getResultStatusObject().put("signatureBiometryKey", model.getResultStatusObject().get("signaturePossessionKey"));
        // Verify three factor signature
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY);

        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);

        // Revert biometry key change
        model.getResultStatusObject().put("signatureBiometryKey", biometryKeyOrig);
    }

    @Test
    void signatureInvalidResourceIdTest() throws Exception {
        // Set invalid resource ID
        model.setResourceId("/pa/signature/invalid");

        // Verify two factor signature
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);

        new VerifySignatureStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);

        // Revert resource ID
        model.setResourceId("/pa/signature/validate");
    }

    private void checkSignatureError(ErrorResponse errorResponse) {
        // Errors differ when Web Flow is used because of its Exception handler
        assertTrue("POWERAUTH_AUTH_FAIL".equals(errorResponse.getResponseObject().getCode()) || "ERR_AUTHENTICATION".equals(errorResponse.getResponseObject().getCode()));
        assertTrue("Signature validation failed".equals(errorResponse.getResponseObject().getMessage()) || "POWER_AUTH_SIGNATURE_INVALID".equals(errorResponse.getResponseObject().getMessage()));
    }

}
