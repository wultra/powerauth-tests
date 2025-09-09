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
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.response.CommitActivationResponse;
import com.wultra.security.powerauth.client.model.response.InitActivationResponse;
import com.wultra.security.powerauth.client.model.response.v4.GetActivationStatusResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.PrepareActivationStep;
import com.wultra.security.powerauth.lib.cmd.steps.VerifyAuthenticationStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyAuthenticationStepModel;
import com.wultra.security.powerauth.lib.cmd.util.CounterUtil;
import org.apache.commons.text.CharacterPredicates;
import org.apache.commons.text.RandomStringGenerator;
import org.json.simple.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth authentication test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthAuthenticationShared {

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
        modelPrepare.setMasterPublicKeyP256(config.getMasterPublicKeyP256());
        if (version.getMajorVersion() == 4) {
            modelPrepare.setMasterPublicKeyP384(config.getMasterPublicKeyP384());
            modelPrepare.setMasterPublicKeyMlDsa65(config.getMasterPublicKeyMlDsa65());
            modelPrepare.setSharedSecretAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3);
        }
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
        modelPrepare.setMasterPublicKeyP256(config.getMasterPublicKeyP256());
        if (version.getMajorVersion() == 4) {
            modelPrepare.setMasterPublicKeyP384(config.getMasterPublicKeyP384());
            modelPrepare.setMasterPublicKeyMlDsa65(config.getMasterPublicKeyMlDsa65());
            modelPrepare.setSharedSecretAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3);
        }
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

    private static void checkError(ErrorResponse errorResponse) {
        // Errors differ when Web Flow is used because of its Exception handler
        assertTrue("ERR_AUTHENTICATION".equals(errorResponse.getResponseObject().getCode()));
        assertTrue("POWER_AUTH_CODE_INVALID".equals(errorResponse.getResponseObject().getMessage()));
    }

}
