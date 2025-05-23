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
import com.wultra.security.powerauth.client.model.response.v3.GetActivationStatusResponse;
import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.v3.SignatureType;
import com.wultra.security.powerauth.client.model.request.v3.CreatePersonalizedOfflineSignaturePayloadRequest;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.v3.VerifyOfflineSignatureRequest;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.client.model.response.v3.CreateNonPersonalizedOfflineSignaturePayloadResponse;
import com.wultra.security.powerauth.client.model.response.v3.CreatePersonalizedOfflineSignaturePayloadResponse;
import com.wultra.security.powerauth.client.model.response.v3.VerifyOfflineSignatureResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.core.rest.model.base.response.ErrorResponse;
import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.crypto.lib.config.AuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.AuthenticationCodeLegacyUtils;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.http.PowerAuthHttpBody;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.VerifyAuthenticationStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyAuthenticationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.PrepareActivationStep;
import com.wultra.security.powerauth.lib.cmd.util.CounterUtil;
import com.wultra.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import org.apache.commons.text.CharacterPredicates;
import org.apache.commons.text.RandomStringGenerator;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth signature test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthSignatureShared {

    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();
    private static final AuthenticationCodeLegacyUtils AUTHENTICATION_CODE_LEGACY_UTILS = new AuthenticationCodeLegacyUtils();

    // Data for offline signatures
    private static final String operationId = "5ff1b1ed-a3cc-45a3-8ab0-ed60950312b6";
    private static final String operationData = "A1*A100CZK*ICZ2730300000001165254011*D20180425";
    private static final String title = "Payment";
    private static final String message = "Please confirm this payment";
    private static final String flags = "B";
    private static final String offlineData = operationId + "\n" + title + "\n" + message + "\n" + operationData + "\n" + flags;

    public static void signatureValidTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Response responseOK = (Response) stepLogger.getResponse().responseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    public static void signatureInvalidPasswordTest(final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setPassword("1111");
        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkError(errorResponse);
    }

    public static void signatureIncorrectPasswordFormatTest(final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setPassword("*");
        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkError(errorResponse);
    }

    public static void signatureCounterLookAheadTest(final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model) throws Exception {
        // Move counter by 1-4, next signature should succeed thanks to counter lookahead and it is still in max failure limit
        for (int i = 1; i < 4; i++) {
            for (int j=0; j < i; j++) {
                model.setPassword("1111");
                ObjectStepLogger stepLogger = new ObjectStepLogger();
                new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
                assertFalse(stepLogger.getResult().success());
                assertEquals(401, stepLogger.getResponse().statusCode());
            }

            ObjectStepLogger stepLogger = new ObjectStepLogger();
            model.setPassword(config.getPassword());
            new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
            assertTrue(stepLogger.getResult().success());
            assertEquals(200, stepLogger.getResponse().statusCode());

            final Response responseOK = (Response) stepLogger.getResponse().responseObject();
            assertEquals("OK", responseOK.getStatus());
        }

    }

    public static void signatureBlockedActivationTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final PowerAuthVersion version) throws Exception {
        powerAuthClient.blockActivation(config.getActivationId(version), "test", "test");

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new VerifyAuthenticationStep().execute(stepLogger1, model.toMap());
        assertFalse(stepLogger1.getResult().success());
        assertEquals(401, stepLogger1.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkError(errorResponse);

        powerAuthClient.unblockActivation(config.getActivationId(version), "test");

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifyAuthenticationStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());
    }

    public static void signatureSingleFactorTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION);

        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void signatureBiometryTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_BIOMETRY);

        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void signatureThreeFactorTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY);

        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void signatureEmptyDataTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        File dataFile = File.createTempFile("data_empty" + version, ".json");
        dataFile.deleteOnExit();
        FileWriter fw = new FileWriter(dataFile);
        fw.close();
        model.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));

        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Response responseOK = (Response) stepLogger.getResponse().responseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    public static void signatureValidGetTest(final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setHttpMethod("GET");
        model.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate?who=John_Tramonta&when=now");
        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Response responseOK = (Response) stepLogger.getResponse().responseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    public static void signatureValidGetNoParamTest(final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setHttpMethod("GET");
        model.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate");
        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Response responseOK = (Response) stepLogger.getResponse().responseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    public static void signatureGetInvalidPasswordTest(final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setHttpMethod("GET");
        model.setPassword("0000");
        model.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate?who=John_Tramonta&when=now");
        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkError(errorResponse);
    }

    public static void signatureUnsupportedApplicationTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model) throws Exception {
        powerAuthClient.unsupportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new VerifyAuthenticationStep().execute(stepLogger1, model.toMap());
        assertFalse(stepLogger1.getResult().success());
        assertEquals(401, stepLogger1.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkError(errorResponse);

        powerAuthClient.supportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        ObjectStepLogger stepLogger2 = new ObjectStepLogger(System.out);
        new VerifyAuthenticationStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        final Response responseOK = (Response) stepLogger2.getResponse().responseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    public static void signatureMaxFailedAttemptsTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final PowerAuthVersion version) throws Exception {
        // Create temp status file
        File tempStatusFile = File.createTempFile("pa_status", ".json");
        tempStatusFile.deleteOnExit();

        final JSONObject resultStatusObject = new JSONObject();

        // Init activation
        final InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        initRequest.setMaxFailureCount(3L);
        final InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        PrepareActivationStepModel modelPrepare = new PrepareActivationStepModel();
        modelPrepare.setActivationCode(initResponse.getActivationCode());
        modelPrepare.setActivationName("test v" + version);
        modelPrepare.setApplicationKey(config.getApplicationKey());
        modelPrepare.setApplicationSecret(config.getApplicationSecret());
        modelPrepare.setMasterPublicKeyP256(config.getMasterPublicKeyP256());
        modelPrepare.setHeaders(new HashMap<>());
        modelPrepare.setPassword(config.getPassword());
        modelPrepare.setStatusFileName(tempStatusFile.getAbsolutePath());
        modelPrepare.setResultStatusObject(resultStatusObject);
        modelPrepare.setUriString(config.getPowerAuthIntegrationUrl());
        modelPrepare.setVersion(version);
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

        // Fail two signatures
        for (int i = 0; i < 2; i++) {
            ObjectStepLogger stepLoggerSignature = new ObjectStepLogger();
            new VerifyAuthenticationStep().execute(stepLoggerSignature, model.toMap());
            assertFalse(stepLoggerSignature.getResult().success());
            assertEquals(401, stepLoggerSignature.getResponse().statusCode());
        }

        // Last signature before max failed attempts should be successful
        model.setPassword(config.getPassword());
        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifyAuthenticationStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        // Fail three signatures
        model.setPassword("1111");
        for (int i = 0; i < 3; i++) {
            ObjectStepLogger stepLoggerSignature = new ObjectStepLogger();
            new VerifyAuthenticationStep().execute(stepLoggerSignature, model.toMap());
            assertFalse(stepLoggerSignature.getResult().success());
            assertEquals(401, stepLoggerSignature.getResponse().statusCode());
        }

        // Activation should be blocked
        final GetActivationStatusResponse statusResponseBlocked = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.BLOCKED, statusResponseBlocked.getActivationStatus());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    public static void signatureLookAheadTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final PowerAuthVersion version) throws Exception {
        // Create temp status file
        File tempStatusFile = File.createTempFile("pa_status_lookahead", ".json");
        tempStatusFile.deleteOnExit();

        final JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        // High limit to test lookahead
        initRequest.setMaxFailureCount(100L);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        PrepareActivationStepModel modelPrepare = new PrepareActivationStepModel();
        modelPrepare.setActivationCode(initResponse.getActivationCode());
        modelPrepare.setActivationName("test v" + version);
        modelPrepare.setApplicationKey(config.getApplicationKey());
        modelPrepare.setApplicationSecret(config.getApplicationSecret());
        modelPrepare.setMasterPublicKeyP256(config.getMasterPublicKeyP256());
        modelPrepare.setHeaders(new HashMap<>());
        modelPrepare.setPassword(config.getPassword());
        modelPrepare.setStatusFileName(tempStatusFile.getAbsolutePath());
        modelPrepare.setResultStatusObject(resultStatusObject);
        modelPrepare.setUriString(config.getPowerAuthIntegrationUrl());
        modelPrepare.setVersion(version);
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

        // Fail 19 signatures
        for (int i = 0; i < 19; i++) {
            ObjectStepLogger stepLoggerSignature = new ObjectStepLogger();
            new VerifyAuthenticationStep().execute(stepLoggerSignature, model.toMap());
            assertFalse(stepLoggerSignature.getResult().success());
            assertEquals(401, stepLoggerSignature.getResponse().statusCode());
        }

        // Last signature before lookahead failure should be successful and should fix counter
        model.setPassword(config.getPassword());
        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifyAuthenticationStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        // Fail 20 signatures
        model.setPassword("1111");
        for (int i = 0; i < 20; i++) {
            ObjectStepLogger stepLoggerSignature = new ObjectStepLogger();
            new VerifyAuthenticationStep().execute(stepLoggerSignature, model.toMap());
            assertFalse(stepLoggerSignature.getResult().success());
            assertEquals(401, stepLoggerSignature.getResponse().statusCode());
        }

        // Signature after lookahead failure should be fail
        model.setPassword(config.getPassword());
        ObjectStepLogger stepLogger3 = new ObjectStepLogger();
        new VerifyAuthenticationStep().execute(stepLogger3, model.toMap());
        assertFalse(stepLogger3.getResult().success());
        assertEquals(401, stepLogger3.getResponse().statusCode());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    public static void signatureCounterIncrementTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        HashBasedCounter counter = new HashBasedCounter(version.value());
        for (int i = 1; i <= 10; i++) {
            ObjectStepLogger stepLoggerLoop = new ObjectStepLogger();
            new VerifyAuthenticationStep().execute(stepLoggerLoop, model.toMap());
            assertTrue(stepLoggerLoop.getResult().success());
            assertEquals(200, stepLoggerLoop.getResponse().statusCode());

            // Verify hash based counter
            ctrData = counter.next(ctrData);
            assertArrayEquals(ctrData, CounterUtil.getCtrData(model, stepLoggerLoop));
        }
    }

    public static void signatureLargeDataTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        final File dataFileLarge = File.createTempFile("data_large" + version, ".dat");
        dataFileLarge.deleteOnExit();
        final FileWriter fw = new FileWriter(dataFileLarge);
        final RandomStringGenerator randomStringGenerator =
                new RandomStringGenerator.Builder()
                        .withinRange('0', 'z')
                        .filteredBy(CharacterPredicates.LETTERS, CharacterPredicates.DIGITS)
                        .get();
        final String randomString = randomStringGenerator.generate(10000);
        fw.write(randomString);
        fw.close();

        model.setData(Files.readAllBytes(Paths.get(dataFileLarge.getAbsolutePath())));

        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Response responseOK = (Response) stepLogger.getResponse().responseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    public static void signatureOfflinePersonalizedValidTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        final CreatePersonalizedOfflineSignaturePayloadResponse offlineResponse = powerAuthClient.createPersonalizedOfflineSignaturePayload(
                config.getActivationId(version), offlineData);
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
        final PublicKey serverPublicKey = config.getKeyConvertor().convertBytesToPublicKey(EcCurve.P256, serverPublicKeyBytes);

        // Prepare offline data without signature
        String offlineDataWithoutSignature = offlineData.substring(0, offlineData.length() - ecdsaSignature.length());

        // Validate ECDSA signature of data using server public key
        assertTrue(SIGNATURE_UTILS.validateECDSASignature(EcCurve.P256, offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(ecdsaSignature), serverPublicKey));

        // Prepare data for PowerAuth signature
        String dataForSignature = operationId + "&" + operationData;

        // Prepare normalized data for signature
        String signatureBaseString = PowerAuthHttpBody.getAuthenticationBaseString("POST", "/operation/authorize/offline", Base64.getDecoder().decode(nonce), dataForSignature.getBytes(StandardCharsets.UTF_8));

        // Prepare keys
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));

        // Get the signature keys
        SecretKey signaturePossessionKey = config.getKeyConvertor().convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getKnowledgeFactorKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, new KeyGenerator());

        // Put keys into a list
        List<SecretKey> signatureKeys = new ArrayList<>();
        signatureKeys.add(signaturePossessionKey);
        signatureKeys.add(signatureKnowledgeKey);

        // Calculate signature of normalized signature base string with 'offline' as application secret
        String signature = AUTHENTICATION_CODE_LEGACY_UTILS.computePowerAuthCode((signatureBaseString + "&offline").getBytes(StandardCharsets.UTF_8), signatureKeys, CounterUtil.getCtrData(model, stepLogger), AuthenticationCodeConfiguration.decimal());

        final VerifyOfflineSignatureResponse signatureResponse = powerAuthClient.verifyOfflineSignature(config.getActivationId(version), signatureBaseString, signature, true);
        assertTrue(signatureResponse.isSignatureValid());
        assertEquals(config.getActivationId(version), signatureResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, signatureResponse.getActivationStatus());
        assertEquals(BigInteger.valueOf(5), signatureResponse.getRemainingAttempts());
        assertEquals(SignatureType.POSSESSION_KNOWLEDGE, signatureResponse.getSignatureType());
        assertEquals(config.getApplicationId(), signatureResponse.getApplicationId());

        // Increment counter
        CounterUtil.incrementCounter(model);
    }

    public static void signatureOfflinePersonalizedInvalidTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {

        CreatePersonalizedOfflineSignaturePayloadResponse offlineResponse = powerAuthClient.createPersonalizedOfflineSignaturePayload(
                config.getActivationId(version), offlineData);
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
        final PublicKey serverPublicKey = config.getKeyConvertor().convertBytesToPublicKey(EcCurve.P256, serverPublicKeyBytes);

        // Prepare offline data without signature
        String offlineDataWithoutSignature = offlineData.substring(0, offlineData.length() - ecdsaSignature.length());

        // Validate ECDSA signature of data using server public key
        assertTrue(SIGNATURE_UTILS.validateECDSASignature(EcCurve.P256, offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(ecdsaSignature), serverPublicKey));

        // Prepare data for PowerAuth signature
        String dataForSignature = operationId + "&" + operationData;

        // Prepare normalized data for signature
        String signatureBaseString = PowerAuthHttpBody.getAuthenticationBaseString("POST", "/operation/authorize/offline", Base64.getDecoder().decode(nonce), dataForSignature.getBytes(StandardCharsets.UTF_8));

        // Prepare keys
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));

        // Get the signature keys
        SecretKey signaturePossessionKey = config.getKeyConvertor().convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getKnowledgeFactorKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, new KeyGenerator());

        // Put keys into a list
        List<SecretKey> signatureKeys = new ArrayList<>();
        signatureKeys.add(signaturePossessionKey);
        signatureKeys.add(signatureKnowledgeKey);

        // Calculate signature of normalized signature base string with 'offline' as application secret
        String signature = AUTHENTICATION_CODE_LEGACY_UTILS.computePowerAuthCode((signatureBaseString + "&offline").getBytes(StandardCharsets.UTF_8), signatureKeys, CounterUtil.getCtrData(model, stepLogger), AuthenticationCodeConfiguration.decimal());

        // Cripple signature
        String digitToReplace = signature.substring(0, 1);
        final String replacedDigit = String.valueOf((Integer.parseInt(digitToReplace) + 1) % 10);
        signature = signature.replace(digitToReplace, replacedDigit);

        VerifyOfflineSignatureResponse signatureResponse = powerAuthClient.verifyOfflineSignature(config.getActivationId(version), signatureBaseString, signature, true);
        assertFalse(signatureResponse.isSignatureValid());
        assertEquals(config.getActivationId(version), signatureResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, signatureResponse.getActivationStatus());
        assertTrue(signatureResponse.getRemainingAttempts().intValue() < 5);
        assertEquals(SignatureType.POSSESSION_KNOWLEDGE, signatureResponse.getSignatureType());
        assertEquals(config.getApplicationId(), signatureResponse.getApplicationId());
    }

    public static void signatureOfflineNonPersonalizedValidTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
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
        assertTrue(SIGNATURE_UTILS.validateECDSASignature(EcCurve.P256, offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(ecdsaSignature), config.getMasterPublicKeyP256()));

        // Prepare data for PowerAuth signature
        String dataForSignature = operationId + "&" + operationData;

        // Prepare normalized data for signature
        String signatureBaseString = PowerAuthHttpBody.getAuthenticationBaseString("POST", "/operation/authorize/offline", Base64.getDecoder().decode(nonce), dataForSignature.getBytes(StandardCharsets.UTF_8));

        // Prepare keys
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));

        // Get the signature keys
        SecretKey signaturePossessionKey = config.getKeyConvertor().convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getKnowledgeFactorKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, new KeyGenerator());

        // Put keys into a list
        List<SecretKey> signatureKeys = new ArrayList<>();
        signatureKeys.add(signaturePossessionKey);
        signatureKeys.add(signatureKnowledgeKey);

        // Calculate signature of normalized signature base string with 'offline' as application secret
        String signature = AUTHENTICATION_CODE_LEGACY_UTILS.computePowerAuthCode((signatureBaseString + "&offline").getBytes(StandardCharsets.UTF_8), signatureKeys, CounterUtil.getCtrData(model, stepLogger), AuthenticationCodeConfiguration.decimal());

        VerifyOfflineSignatureResponse signatureResponse = powerAuthClient.verifyOfflineSignature(config.getActivationId(version), signatureBaseString, signature, true);
        assertTrue(signatureResponse.isSignatureValid());
        assertEquals(config.getActivationId(version), signatureResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, signatureResponse.getActivationStatus());
        assertEquals(BigInteger.valueOf(5), signatureResponse.getRemainingAttempts());
        assertEquals(SignatureType.POSSESSION_KNOWLEDGE, signatureResponse.getSignatureType());
        assertEquals(config.getApplicationId(), signatureResponse.getApplicationId());

        // Increment counter
        CounterUtil.incrementCounter(model);
    }

    public static void signatureOfflineNonPersonalizedInvalidTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
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
        assertTrue(SIGNATURE_UTILS.validateECDSASignature(EcCurve.P256, offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(ecdsaSignature), config.getMasterPublicKeyP256()));

        // Prepare data for PowerAuth signature
        String dataForSignature = operationId + "&" + operationData;

        // Prepare normalized data for signature
        String signatureBaseString = PowerAuthHttpBody.getAuthenticationBaseString("POST", "/operation/authorize/offline", Base64.getDecoder().decode(nonce), dataForSignature.getBytes(StandardCharsets.UTF_8));

        // Prepare keys
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));

        // Get the signature keys
        SecretKey signaturePossessionKey = config.getKeyConvertor().convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getKnowledgeFactorKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, new KeyGenerator());

        // Put keys into a list
        List<SecretKey> signatureKeys = new ArrayList<>();
        signatureKeys.add(signaturePossessionKey);
        signatureKeys.add(signatureKnowledgeKey);

        // Calculate signature of normalized signature base string with 'offline' as application secret
        String signature = AUTHENTICATION_CODE_LEGACY_UTILS.computePowerAuthCode((signatureBaseString + "&offline").getBytes(StandardCharsets.UTF_8), signatureKeys, CounterUtil.getCtrData(model, stepLogger), AuthenticationCodeConfiguration.decimal());

        // Cripple signature
        String digitToReplace = signature.substring(0, 1);
        final String replacedDigit = String.valueOf((Integer.parseInt(digitToReplace) + 1) % 10);
        signature = signature.replace(digitToReplace, replacedDigit);

        VerifyOfflineSignatureResponse signatureResponse = powerAuthClient.verifyOfflineSignature(config.getActivationId(version), signatureBaseString, signature, true);
        assertFalse(signatureResponse.isSignatureValid());
        assertEquals(config.getActivationId(version), signatureResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, signatureResponse.getActivationStatus());
        assertTrue(signatureResponse.getRemainingAttempts().intValue() < 5);
        assertEquals(SignatureType.POSSESSION_KNOWLEDGE, signatureResponse.getSignatureType());
        assertEquals(config.getApplicationId(), signatureResponse.getApplicationId());
    }

    public static void signatureSwappedKeyTest(final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        // Save biometry key
        String biometryKeyOrig = (String) model.getResultStatusObject().get("signatureBiometryKey");
        // Set possession key as biometry key
        model.getResultStatusObject().put("signatureBiometryKey", model.getResultStatusObject().get("signaturePossessionKey"));
        // Verify three factor signature
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY);

        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkError(errorResponse);

        // Revert biometry key change
        model.getResultStatusObject().put("signatureBiometryKey", biometryKeyOrig);
    }

    public static void signatureInvalidResourceIdTest(final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        // Set invalid resource ID
        model.setResourceId("/pa/signature/invalid");

        // Verify two factor signature
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE);

        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkError(errorResponse);

        // Revert resource ID
        model.setResourceId("/pa/signature/validate");
    }

    public static void testSignatureOfflinePersonalizedProximityCheckValid(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        testSignatureOfflinePersonalizedProximityCheck(powerAuthClient, config, model, stepLogger, version, true);
    }

    public static void testSignatureOfflinePersonalizedProximityCheckInvalid(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        testSignatureOfflinePersonalizedProximityCheck(powerAuthClient, config, model, stepLogger, version, false);
    }

    private static void checkError(ErrorResponse errorResponse) {
        // Errors differ when Web Flow is used because of its Exception handler
        assertTrue("ERR_AUTHENTICATION".equals(errorResponse.getResponseObject().getCode()));
        assertTrue("POWER_AUTH_CODE_INVALID".equals(errorResponse.getResponseObject().getMessage()));
    }

    private static void testSignatureOfflinePersonalizedProximityCheck(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version, final boolean expectedResult) throws Exception {
        final String seed = "LtxE0f0RWNx3hy7ISjUPWA==";

        final CreatePersonalizedOfflineSignaturePayloadRequest request = new CreatePersonalizedOfflineSignaturePayloadRequest();
        request.setActivationId(config.getActivationId(version));
        request.setData(offlineData);
        request.setProximityCheck(new CreatePersonalizedOfflineSignaturePayloadRequest.CreateProximityCheck());
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
        final byte[] serverPublicKeyBytes = Base64.getDecoder().decode(model.getResultStatus().getEcServerPublicKey());
        final PublicKey serverPublicKey = config.getKeyConvertor().convertBytesToPublicKey(EcCurve.P256, serverPublicKeyBytes);

        // Prepare offline data without signature
        final String offlineDataWithoutSignature = offlineDataResponse.substring(0, offlineDataResponse.length() - ecdsaSignature.length());

        // Validate ECDSA signature of data using server public key
        assertTrue(SIGNATURE_UTILS.validateECDSASignature(EcCurve.P256, offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(ecdsaSignature), serverPublicKey));

        // Prepare data for PowerAuth signature
        final String proximityTotp = parts[5];
        final String dataForSignatureWithOtp = operationId + "&" + operationData + "&" + proximityTotp;

        // Prepare normalized data for signature
        final String signatureBaseStringWithOtp = PowerAuthHttpBody.getAuthenticationBaseString("POST", "/operation/authorize/offline", Base64.getDecoder().decode(nonce), dataForSignatureWithOtp.getBytes(StandardCharsets.UTF_8));

        // Prepare keys
        byte[] signaturePossessionKeyBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signaturePossessionKey"));
        byte[] signatureKnowledgeKeySalt = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeySalt"));
        byte[] signatureKnowledgeKeyEncryptedBytes = Base64.getDecoder().decode((String) model.getResultStatusObject().get("signatureKnowledgeKeyEncrypted"));

        // Get the signature keys
        final SecretKey signaturePossessionKey = config.getKeyConvertor().convertBytesToSharedSecretKey(signaturePossessionKeyBytes);
        final SecretKey signatureKnowledgeKey = EncryptedStorageUtil.getKnowledgeFactorKey(config.getPassword().toCharArray(), signatureKnowledgeKeyEncryptedBytes, signatureKnowledgeKeySalt, new KeyGenerator());

        // Put keys into a list
        final List<SecretKey> signatureKeys = new ArrayList<>();
        signatureKeys.add(signaturePossessionKey);
        signatureKeys.add(signatureKnowledgeKey);

        // Calculate signature of normalized signature base string with 'offline' as application secret
        final String signature = AUTHENTICATION_CODE_LEGACY_UTILS.computePowerAuthCode((signatureBaseStringWithOtp + "&offline").getBytes(StandardCharsets.UTF_8), signatureKeys, CounterUtil.getCtrData(model, stepLogger), AuthenticationCodeConfiguration.decimal());

        final String dataForSignature= operationId + "&" + operationData;
        final String signatureBaseString = PowerAuthHttpBody.getAuthenticationBaseString("POST", "/operation/authorize/offline", Base64.getDecoder().decode(nonce), dataForSignature.getBytes(StandardCharsets.UTF_8));

        final VerifyOfflineSignatureRequest verifyRequest = new VerifyOfflineSignatureRequest();
        verifyRequest.setActivationId(config.getActivationId(version));
        verifyRequest.setData(signatureBaseString);
        verifyRequest.setSignature(signature);
        verifyRequest.setAllowBiometry(true);
        verifyRequest.setProximityCheck(new VerifyOfflineSignatureRequest.VerifyProximityCheck());
        verifyRequest.getProximityCheck().setSeed(expectedResult ? seed : "bGlnaHQgd28=");
        verifyRequest.getProximityCheck().setStepLength(30);
        verifyRequest.getProximityCheck().setStepCount(2);

        final VerifyOfflineSignatureResponse signatureResponse = powerAuthClient.verifyOfflineSignature(verifyRequest);
        assertEquals(expectedResult, signatureResponse.isSignatureValid());
        assertEquals(config.getActivationId(version), signatureResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, signatureResponse.getActivationStatus());
        final BigInteger expectedRemainingAttempts = BigInteger.valueOf(expectedResult ? 5 : 4);
        assertEquals(expectedRemainingAttempts, signatureResponse.getRemainingAttempts());
        assertEquals(SignatureType.POSSESSION_KNOWLEDGE, signatureResponse.getSignatureType());
        assertEquals(config.getApplicationId(), signatureResponse.getApplicationId());

        CounterUtil.incrementCounter(model);
    }

}
