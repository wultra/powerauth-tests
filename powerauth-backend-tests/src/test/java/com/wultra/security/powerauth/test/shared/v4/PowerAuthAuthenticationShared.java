/*
 * PowerAuth test and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.core.rest.model.base.response.ErrorResponse;
import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.v4.CreatePersonalizedOfflineAuthPayloadRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyOfflineAuthenticationRequest;
import com.wultra.security.powerauth.client.model.response.CommitActivationResponse;
import com.wultra.security.powerauth.client.model.response.InitActivationResponse;
import com.wultra.security.powerauth.client.model.response.v4.CreateNonPersonalizedOfflineAuthPayloadResponse;
import com.wultra.security.powerauth.client.model.response.v4.CreatePersonalizedOfflineAuthPayloadResponse;
import com.wultra.security.powerauth.client.model.response.v4.GetActivationStatusResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyOfflineAuthenticationResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.config.AuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.AuthenticationCodeUtils;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.Kmac;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.http.PowerAuthHttpBody;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.PrepareActivationStep;
import com.wultra.security.powerauth.lib.cmd.steps.VerifyAuthenticationStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyAuthenticationStepModel;
import com.wultra.security.powerauth.lib.cmd.util.CounterUtil;
import com.wultra.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import com.wultra.security.powerauth.util.TestCounterUtil;
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
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth authentication test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthAuthenticationShared {

    private static final AuthenticationCodeUtils AUTHENTICATION_CODE_UTILS = new AuthenticationCodeUtils();
    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();

    // Data for offline authentication
    private static final String operationId = "5ff1b1ed-a3cc-45a3-8ab0-ed60950312b6";
    private static final String operationData = "A1*A100CZK*ICZ2730300000001165254011*D20180425";
    private static final String title = "Payment";
    private static final String message = "Please confirm this payment";
    private static final String flags = "B";
    private static final String offlineData = operationId + "\n" + title + "\n" + message + "\n" + operationData + "\n" + flags;
    private static final byte[] KMAC_OFFLINE_SIGNATURE_CUSTOM_BYTES = "PA4MAC-QR".getBytes(StandardCharsets.UTF_8);

    public static void authValidTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Response responseOK = (Response) stepLogger.getResponse().responseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    public static void authInvalidPasswordTest(final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setPassword("1111");
        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkError(errorResponse);
    }

    public static void authIncorrectPasswordFormatTest(final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setPassword("*");
        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkError(errorResponse);
    }

    public static void authCounterLookAheadTest(final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model) throws Exception {
        // Move counter by 1-4, next auth should succeed thanks to counter lookahead and it is still in max failure limit
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

    public static void authBlockedActivationTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final PowerAuthVersion version) throws Exception {
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

    public static void authSingleFactorTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION);

        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void authBiometryTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_BIOMETRY);

        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void authBiometryNoResponseCheckTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_BIOMETRY);
        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
    }

    public static void authThreeFactorTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY);

        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void authEmptyDataTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
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

    public static void authValidGetTest(final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setHttpMethod("GET");
        model.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v4/auth/validate?who=John_Tramonta&when=now");
        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Response responseOK = (Response) stepLogger.getResponse().responseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    public static void authValidGetNoParamTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setHttpMethod("GET");
        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Response responseOK = (Response) stepLogger.getResponse().responseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    public static void authGetInvalidPasswordTest(final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setHttpMethod("GET");
        model.setPassword("0000");
        model.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v4/auth/validate?who=John_Tramonta&when=now");
        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkError(errorResponse);
    }

    public static void authUnsupportedApplicationTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model) throws Exception {
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

    public static void authMaxFailedAttemptsTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final PowerAuthVersion version) throws Exception {
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
        modelPrepare.setMasterPublicKeyP384(config.getMasterPublicKeyP384());
        modelPrepare.setMasterPublicKeyMlDsa65(config.getMasterPublicKeyMlDsa65());
        modelPrepare.setSharedSecretAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3);
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

        // Fail two auths
        for (int i = 0; i < 2; i++) {
            ObjectStepLogger stepLoggerauth = new ObjectStepLogger();
            new VerifyAuthenticationStep().execute(stepLoggerauth, model.toMap());
            assertFalse(stepLoggerauth.getResult().success());
            assertEquals(401, stepLoggerauth.getResponse().statusCode());
        }

        // Last auth before max failed attempts should be successful
        model.setPassword(config.getPassword());
        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifyAuthenticationStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        // Fail three auths
        model.setPassword("1111");
        for (int i = 0; i < 3; i++) {
            ObjectStepLogger stepLoggerauth = new ObjectStepLogger();
            new VerifyAuthenticationStep().execute(stepLoggerauth, model.toMap());
            assertFalse(stepLoggerauth.getResult().success());
            assertEquals(401, stepLoggerauth.getResponse().statusCode());
        }

        // Activation should be blocked
        final GetActivationStatusResponse statusResponseBlocked = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.BLOCKED, statusResponseBlocked.getActivationStatus());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    public static void authLookAheadTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final PowerAuthVersion version) throws Exception {
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
        modelPrepare.setMasterPublicKeyP384(config.getMasterPublicKeyP384());
        modelPrepare.setMasterPublicKeyMlDsa65(config.getMasterPublicKeyMlDsa65());
        modelPrepare.setSharedSecretAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3);
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

        // Fail 19 auths
        for (int i = 0; i < 19; i++) {
            ObjectStepLogger stepLoggerauth = new ObjectStepLogger();
            new VerifyAuthenticationStep().execute(stepLoggerauth, model.toMap());
            assertFalse(stepLoggerauth.getResult().success());
            assertEquals(401, stepLoggerauth.getResponse().statusCode());
        }

        // Last auth before lookahead failure should be successful and should fix counter
        model.setPassword(config.getPassword());
        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifyAuthenticationStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        // Fail 20 auths
        model.setPassword("1111");
        for (int i = 0; i < 20; i++) {
            ObjectStepLogger stepLoggerauth = new ObjectStepLogger();
            new VerifyAuthenticationStep().execute(stepLoggerauth, model.toMap());
            assertFalse(stepLoggerauth.getResult().success());
            assertEquals(401, stepLoggerauth.getResponse().statusCode());
        }

        // auth after lookahead failure should be fail
        model.setPassword(config.getPassword());
        ObjectStepLogger stepLogger3 = new ObjectStepLogger();
        new VerifyAuthenticationStep().execute(stepLogger3, model.toMap());
        assertFalse(stepLogger3.getResult().success());
        assertEquals(401, stepLogger3.getResponse().statusCode());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    public static void authCounterIncrementTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        byte[] ctrData = TestCounterUtil.getCtrData(model.getResultStatus());
        HashBasedCounter counter = new HashBasedCounter(version.value());
        for (int i = 1; i <= 10; i++) {
            ObjectStepLogger stepLoggerLoop = new ObjectStepLogger();
            new VerifyAuthenticationStep().execute(stepLoggerLoop, model.toMap());
            assertTrue(stepLoggerLoop.getResult().success());
            assertEquals(200, stepLoggerLoop.getResponse().statusCode());

            // Verify hash based counter
            ctrData = counter.next(ctrData);
            assertArrayEquals(ctrData, TestCounterUtil.getCtrData(model.getResultStatus()));
        }
    }

    public static void authLargeDataTest(final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
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

    public static void authSwappedKeyTest(final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        // Save biometry key
        String biometryKeyOrig = (String) model.getResultStatusObject().get("biometryFactorKey");
        // Set possession key as biometry key
        model.getResultStatusObject().put("biometryFactorKey", model.getResultStatusObject().get("possessionFactorKey"));
        // Verify three factor auth
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY);

        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkError(errorResponse);

        // Revert biometry key change
        model.getResultStatusObject().put("biometryFactorKey", biometryKeyOrig);
    }

    public static void authInvalidResourceIdTest(final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        // Set invalid resource ID
        model.setResourceId("/pa/auth/invalid");

        // Verify two factor auth
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE);

        new VerifyAuthenticationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkError(errorResponse);

        // Revert resource ID
        model.setResourceId("/pa/auth/validate");
    }

    public static void authOfflinePersonalizedValidTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, VerifyAuthenticationStepModel model, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        final CreatePersonalizedOfflineAuthPayloadResponse offlineResponse = powerAuthClient.createPersonalizedOfflineAuthPayload(
                config.getActivationId(version),
                offlineData
        );
        final String nonce = offlineResponse.getNonce();
        final String offlineData = offlineResponse.getOfflineData();

        // Split the offline data into individual lines
        final String[] parts = offlineData.split("\n");

        // Extract the last line which contains information about key and KMAC tag
        final String lastLine = parts[parts.length-1];

        // 2 = KEY_MAC_PERSONALIZED_DATA was used to sign data (KMAC tag)
        assertEquals("2", lastLine.substring(0, 1));

        // The remainder of the last line is Base64 encoded KMAC tag
        final String kmacTag = lastLine.substring(1);
        validateKmac(offlineData, kmacTag, model);

        // Prepare data for PowerAuth authentication
        final String dataForAuthentication = operationId + "&" + operationData;

        // Prepare normalized data for authentication
        final String autheBaseString = PowerAuthHttpBody.getAuthenticationBaseString("POST", "/operation/authorize/offline", Base64.getDecoder().decode(nonce), dataForAuthentication.getBytes(StandardCharsets.UTF_8));

        final List<SecretKey> factorKeys = getFactorKeys(config, model);

        final String authCode = computeAuthCode(
                (autheBaseString + "&offline").getBytes(StandardCharsets.UTF_8),
                factorKeys,
                model
        );

        final VerifyOfflineAuthenticationResponse authResponse = powerAuthClient.verifyOfflineAuthentication(config.getActivationId(version), autheBaseString, authCode, true);
        assertTrue(authResponse.isAuthenticationValid());
        assertEquals(config.getActivationId(version), authResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, authResponse.getActivationStatus());
        assertEquals(BigInteger.valueOf(5), authResponse.getRemainingAttempts());
        assertEquals(AuthenticationCodeType.POSSESSION_KNOWLEDGE, authResponse.getAuthenticationCodeType());
        assertEquals(config.getApplicationId(), authResponse.getApplicationId());

        // Increment counter
        CounterUtil.incrementCounter(model.getResultStatus());
    }

    public static void authOfflinePersonalizedInvalidTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, VerifyAuthenticationStepModel model, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        final CreatePersonalizedOfflineAuthPayloadResponse offlineResponse = powerAuthClient.createPersonalizedOfflineAuthPayload(
                config.getActivationId(version),
                offlineData
        );
        final String nonce = offlineResponse.getNonce();
        final String offlineDataResponse = offlineResponse.getOfflineData();

        final String[] parts = offlineDataResponse.split("\n");
        final String lastLine = parts[parts.length-1];
        assertEquals("2", lastLine.substring(0, 1));
        final String kmacTag = lastLine.substring(1);
        validateKmac(offlineDataResponse, kmacTag, model);
        final String dataForAuthentication = operationId + "&" + operationData;

        final String authBaseString = PowerAuthHttpBody.getAuthenticationBaseString(
                "POST",
                "/operation/authorize/offline",
                Base64.getDecoder().decode(nonce),
                dataForAuthentication.getBytes(StandardCharsets.UTF_8)
        );

        final List<SecretKey> factorKeys = getFactorKeys(config, model);
        String authCode = computeAuthCode(
                (authBaseString + "&offline").getBytes(StandardCharsets.UTF_8),
                factorKeys,
                model
        );

        final String digitToReplace = authCode.substring(0, 1);
        final String replacedDigit = String.valueOf((Integer.parseInt(digitToReplace) + 1) % 10);
        authCode = authCode.replace(digitToReplace, replacedDigit);

        final VerifyOfflineAuthenticationResponse authResponse = powerAuthClient.verifyOfflineAuthentication(
                config.getActivationId(version),
                authBaseString,
                authCode,
                true
        );

        assertFalse(authResponse.isAuthenticationValid());
        assertEquals(config.getActivationId(version), authResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, authResponse.getActivationStatus());
        assertTrue(authResponse.getRemainingAttempts().intValue() < 5);
        assertEquals(AuthenticationCodeType.POSSESSION_KNOWLEDGE, authResponse.getAuthenticationCodeType());
        assertEquals(config.getApplicationId(), authResponse.getApplicationId());
    }

    public static void authOfflineNonPersonalizedValidTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, VerifyAuthenticationStepModel model, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        final CreateNonPersonalizedOfflineAuthPayloadResponse offlineResponse = powerAuthClient.createNonPersonalizedOfflineAuthPayload(
                config.getApplicationId(), offlineData);
        final String nonce = offlineResponse.getNonce();
        final String offlineDataResponse = offlineResponse.getOfflineData();

        // Split the offline data into individual lines
        final String[] parts = offlineDataResponse.split("\n");

        // Extract last line which contains information about key and ECDSA signature
        final String lastLine = parts[parts.length-1];

        // 0 = KEY_SERVER_MASTER_PRIVATE was used to sign data (non-personalized offline signature)
        assertEquals("0", lastLine.substring(0, 1));

        // The remainder of last line is Base64 encoded ECDSA signature
        final String ecdsaSignature = lastLine.substring(1);

        // Prepare offline data without signature
        final String offlineDataWithoutSignature = offlineDataResponse.substring(0, offlineDataResponse.length() - ecdsaSignature.length());

        // Validate ECDSA signature of data using server public key
        assertTrue(SIGNATURE_UTILS.validateECDSASignature(
                EcCurve.P384,
                offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode(ecdsaSignature),
                config.getMasterPublicKeyP384()
        ));

        // Prepare data for PowerAuth authentication
        final String dataForAuthentication = operationId + "&" + operationData;

        // Prepare normalized data for authentication
        final String authBaseString = PowerAuthHttpBody.getAuthenticationBaseString(
                "POST",
                "/operation/authorize/offline",
                Base64.getDecoder().decode(nonce),
                dataForAuthentication.getBytes(StandardCharsets.UTF_8)
        );

        final List<SecretKey> factorKeys = getFactorKeys(config, model);
        final String authCode = computeAuthCode(
                (authBaseString + "&offline").getBytes(StandardCharsets.UTF_8),
                factorKeys,
                model
        );

        final VerifyOfflineAuthenticationResponse authResponse = powerAuthClient.verifyOfflineAuthentication(
                config.getActivationId(version),
                authBaseString,
                authCode,
                true
        );

        assertTrue(authResponse.isAuthenticationValid());
        assertEquals(config.getActivationId(version), authResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, authResponse.getActivationStatus());
        assertEquals(BigInteger.valueOf(5), authResponse.getRemainingAttempts());
        assertEquals(AuthenticationCodeType.POSSESSION_KNOWLEDGE, authResponse.getAuthenticationCodeType());
        assertEquals(config.getApplicationId(), authResponse.getApplicationId());

        // Increment counter
        CounterUtil.incrementCounter(model.getResultStatus());
    }

    public static void authOfflineNonPersonalizedInvalidTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, VerifyAuthenticationStepModel model, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        final CreateNonPersonalizedOfflineAuthPayloadResponse offlineResponse = powerAuthClient.createNonPersonalizedOfflineAuthPayload(
                config.getApplicationId(), offlineData);
        final String nonce = offlineResponse.getNonce();
        final String offlineDataResponse = offlineResponse.getOfflineData();

        // Split the offline data into individual lines
        final String[] parts = offlineDataResponse.split("\n");

        // Extract last line which contains information about key and ECDSA signature
        final String lastLine = parts[parts.length-1];

        // 0 = KEY_SERVER_MASTER_PRIVATE was used to sign data (non-personalized offline signature)
        assertEquals("0", lastLine.substring(0, 1));

        // The remainder of last line is Base64 encoded ECDSA signature
        final String ecdsaSignature = lastLine.substring(1);

        // Prepare offline data without signature
        final String offlineDataWithoutSignature = offlineDataResponse.substring(0, offlineDataResponse.length() - ecdsaSignature.length());

        // Validate ECDSA signature of data using server public key
        assertTrue(SIGNATURE_UTILS.validateECDSASignature(
                EcCurve.P384,
                offlineDataWithoutSignature.getBytes(StandardCharsets.UTF_8),
                Base64.getDecoder().decode(ecdsaSignature),
                config.getMasterPublicKeyP384()
        ));

        // Prepare data for PowerAuth authentication
        final String dataForAuthentication = operationId + "&" + operationData;

        // Prepare normalized data for authentication
        final String authBaseString = PowerAuthHttpBody.getAuthenticationBaseString(
                "POST",
                "/operation/authorize/offline",
                Base64.getDecoder().decode(nonce),
                dataForAuthentication.getBytes(StandardCharsets.UTF_8)
        );
        final List<SecretKey> factorKeys = getFactorKeys(config, model);
        String authCode = computeAuthCode(
                (authBaseString + "&offline").getBytes(StandardCharsets.UTF_8),
                factorKeys,
                model
        );

        // Cripple auth code
        final String digitToReplace = authCode.substring(0, 1);
        final String replacedDigit = String.valueOf((Integer.parseInt(digitToReplace) + 1) % 10);
        authCode = authCode.replace(digitToReplace, replacedDigit);

        final VerifyOfflineAuthenticationResponse authResponse = powerAuthClient.verifyOfflineAuthentication(
                config.getActivationId(version),
                authBaseString,
                authCode,
                true
        );

        assertFalse(authResponse.isAuthenticationValid());
        assertEquals(config.getActivationId(version), authResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, authResponse.getActivationStatus());
        assertTrue(authResponse.getRemainingAttempts().intValue() < 5);
        assertEquals(AuthenticationCodeType.POSSESSION_KNOWLEDGE, authResponse.getAuthenticationCodeType());
        assertEquals(config.getApplicationId(), authResponse.getApplicationId());
    }

    public static void testAuthOfflinePersonalizedProximityCheckValid(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        testAuthOfflinePersonalizedProximityCheck(powerAuthClient, config, model, stepLogger, version, true);
    }

    public static void testAuthOfflinePersonalizedProximityCheckInvalid(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        testAuthOfflinePersonalizedProximityCheck(powerAuthClient, config, model, stepLogger, version, false);
    }

    private static void testAuthOfflinePersonalizedProximityCheck(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final VerifyAuthenticationStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version, final boolean expectedResult) throws Exception {
        final String seed = "LtxE0f0RWNx3hy7ISjUPWA==";

        final CreatePersonalizedOfflineAuthPayloadRequest request = new CreatePersonalizedOfflineAuthPayloadRequest();
        request.setActivationId(config.getActivationId(version));
        request.setData(offlineData);
        request.setProximityCheck(new CreatePersonalizedOfflineAuthPayloadRequest.CreateProximityCheck());
        request.getProximityCheck().setSeed(seed);
        request.getProximityCheck().setStepLength(30);

        final CreatePersonalizedOfflineAuthPayloadResponse offlineResponse = powerAuthClient.createPersonalizedOfflineAuthPayload(request);
        final String nonce = offlineResponse.getNonce();
        final String offlineDataResponse = offlineResponse.getOfflineData();

        final String[] parts = offlineDataResponse.split("\n");
        final String lastLine = parts[parts.length - 1];
        assertEquals("2", lastLine.substring(0, 1));
        final String kmacTag = lastLine.substring(1);
        validateKmac(offlineDataResponse, kmacTag, model);

        final String proximityTotp = parts[5];
        final String dataForAuthenticationWithOtp = operationId + "&" + operationData + "&" + proximityTotp;
        final String authBaseStringWithOtp = PowerAuthHttpBody.getAuthenticationBaseString(
                "POST",
                "/operation/authorize/offline",
                Base64.getDecoder().decode(nonce),
                dataForAuthenticationWithOtp.getBytes(StandardCharsets.UTF_8)
        );

        final List<SecretKey> factorKeys = getFactorKeys(config, model);
        final String authCode = computeAuthCode(
                (authBaseStringWithOtp + "&offline").getBytes(StandardCharsets.UTF_8),
                factorKeys,
                model
        );
        final String dataForAuthentication = operationId + "&" + operationData;
        final String authBaseString = PowerAuthHttpBody.getAuthenticationBaseString(
                "POST",
                "/operation/authorize/offline",
                Base64.getDecoder().decode(nonce),
                dataForAuthentication.getBytes(StandardCharsets.UTF_8)
        );

        final VerifyOfflineAuthenticationRequest verifyRequest = new VerifyOfflineAuthenticationRequest();
        verifyRequest.setActivationId(config.getActivationId(version));
        verifyRequest.setData(authBaseString);
        verifyRequest.setAuthenticationCode(authCode);
        verifyRequest.setAllowBiometry(true);
        verifyRequest.setProximityCheck(new VerifyOfflineAuthenticationRequest.VerifyProximityCheck());
        verifyRequest.getProximityCheck().setSeed(expectedResult ? seed : "bGlnaHQgd28=");
        verifyRequest.getProximityCheck().setStepLength(30);
        verifyRequest.getProximityCheck().setStepCount(2);

        final VerifyOfflineAuthenticationResponse signatureResponse = powerAuthClient.verifyOfflineAuthentication(verifyRequest);

        assertEquals(expectedResult, signatureResponse.isAuthenticationValid());
        assertEquals(config.getActivationId(version), signatureResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, signatureResponse.getActivationStatus());

        final BigInteger expectedRemainingAttempts = BigInteger.valueOf(expectedResult ? 5 : 4);
        assertEquals(expectedRemainingAttempts, signatureResponse.getRemainingAttempts());

        assertEquals(AuthenticationCodeType.POSSESSION_KNOWLEDGE, signatureResponse.getAuthenticationCodeType());
        assertEquals(config.getApplicationId(), signatureResponse.getApplicationId());

        CounterUtil.incrementCounter(model.getResultStatus());
    }

    private static List<SecretKey> getFactorKeys(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel model) throws Exception {
        final byte[] salt = model.getResultStatus().getKnowledgeFactorKeySaltBytes();
        final byte[] encrypted = model.getResultStatus().getKnowledgeFactorKeyEncryptedBytes();

        final SecretKey possession = model.getResultStatus().getPossessionFactorKeyObject();
        final SecretKey knowledge = EncryptedStorageUtil.getKnowledgeFactorKey(
                config.getPassword().toCharArray(),
                encrypted,
                salt,
                new KeyGenerator()
        );

        final List<SecretKey> keys = new ArrayList<>();
        keys.add(possession);
        keys.add(knowledge);
        return keys;
    }

    private static String computeAuthCode(byte[] base, List<SecretKey> keys, VerifyAuthenticationStepModel model) throws Exception {
        return AUTHENTICATION_CODE_UTILS.computeAuthCode(
                base,
                keys,
                TestCounterUtil.getCtrData(model.getResultStatus()),
                AuthenticationCodeConfiguration.decimal()
        );
    }

    private static void validateKmac(String offlineDataResponse, String kmacTag, VerifyAuthenticationStepModel model) throws Exception {
        final byte[] expected = Base64.getDecoder().decode(kmacTag);
        final String dataWithoutTag = offlineDataResponse.substring(0, offlineDataResponse.length() - kmacTag.length());
        final byte[] key = Base64.getDecoder().decode(model.getResultStatus().getMacPersonalizedDataKey());
        final byte[] calculated = Kmac.kmac256(
                key,
                dataWithoutTag.getBytes(StandardCharsets.UTF_8),
                KMAC_OFFLINE_SIGNATURE_CUSTOM_BYTES,
                32
        );

        assertArrayEquals(expected, calculated);
    }
    private static void checkError(ErrorResponse errorResponse) {
        assertTrue("ERR_AUTHENTICATION".equals(errorResponse.getResponseObject().getCode()));
        assertTrue("POWER_AUTH_CODE_INVALID".equals(errorResponse.getResponseObject().getMessage()));
    }

}
