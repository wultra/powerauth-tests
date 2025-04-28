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
import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.LookupActivationsRequest;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.enums.ProtocolVersion;
import com.wultra.security.powerauth.test.shared.util.ResponseVerificationUtil;
import com.wultra.core.rest.model.base.response.ErrorResponse;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.model.StepItem;
import com.wultra.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.GetStatusStep;
import com.wultra.security.powerauth.lib.cmd.steps.PrepareActivationStep;
import com.wultra.security.powerauth.lib.cmd.util.CounterUtil;
import com.wultra.security.powerauth.rest.api.model.request.v3.ActivationStatusRequest;
import com.wultra.security.powerauth.rest.api.model.response.v3.ActivationStatusResponse;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth activation test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthActivationShared {

    private static final PowerAuthClientActivation CLIENT_ACTIVATION = new PowerAuthClientActivation();

    public static void activationPrepareTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config,
                                             PrepareActivationStepModel model, PowerAuthVersion version) throws Exception {
        // Init activation
        final InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        final InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Verify activation status
        final GetActivationStatusResponse statusResponseCreated = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponseCreated.getActivationStatus());

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

        final EciesEncryptedResponse eciesResponse = (EciesEncryptedResponse) stepLoggerPrepare.getResponse().responseObject();
        assertNotNull(eciesResponse.getEncryptedData());
        assertNotNull(eciesResponse.getMac());

        // Verify decrypted activationId
        String activationIdPrepareResponse = null;
        for (StepItem item: stepLoggerPrepare.getItems()) {
            if (item.name().equals("Activation Done")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                activationIdPrepareResponse = (String) responseMap.get("activationId");
                break;
            }
        }

        assertEquals(initResponse.getActivationId(), activationIdPrepareResponse);

        // Verify activation status
        GetActivationStatusResponse statusResponseOtpUsed = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.PENDING_COMMIT, statusResponseOtpUsed.getActivationStatus());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Verify activation status
        GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, statusResponseActive.getActivationStatus());

        // Block activation
        final BlockActivationResponse blockResponse = powerAuthClient.blockActivation(initResponse.getActivationId(), "test", "test");
        assertEquals(initResponse.getActivationId(), blockResponse.getActivationId());
        assertEquals("test", blockResponse.getBlockedReason());

        // Verify activation status
        GetActivationStatusResponse statusResponseBlocked = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.BLOCKED, statusResponseBlocked.getActivationStatus());

        // Unblock activation
        final UnblockActivationResponse unblockResponse = powerAuthClient.unblockActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), unblockResponse.getActivationId());

        // Verify activation status
        GetActivationStatusResponse statusResponseActive2 = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, statusResponseActive2.getActivationStatus());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");

        // Verify activation status
        GetActivationStatusResponse statusResponseRemoved = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.REMOVED, statusResponseRemoved.getActivationStatus());
    }

    public static void activationNonExistentTest(PowerAuthClient powerAuthClient) throws PowerAuthClientException {
        // Verify activation status
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus("AAAAA-BBBBB-CCCCC-DDDDD");
        assertEquals(ActivationStatus.REMOVED, statusResponse.getActivationStatus());
    }

    public static void activationPrepareUnsupportedApplicationTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config,
                                                                   PrepareActivationStepModel model, PowerAuthVersion version) throws Exception {
        // Unsupport application version
        powerAuthClient.unsupportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        // Verify that application version is unsupported
        final GetApplicationDetailResponse detailResponse = powerAuthClient.getApplicationDetail(config.getApplicationId());
        for (ApplicationVersion appVersion: detailResponse.getVersions()) {
            if (appVersion.getApplicationVersionId().equals(config.getApplicationVersion())) {
                assertFalse(appVersion.isSupported());
            }
        }

        // Init activation should not fail, because application version is not known (applicationKey is not sent in InitActivationRequest)
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Verify activation status
        GetActivationStatusResponse statusResponseCreated = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponseCreated.getActivationStatus());

        // PrepareActivation should fail
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertFalse(stepLoggerPrepare.getResult().success());
        // Verify BAD_REQUEST status code
        assertEquals(400, stepLoggerPrepare.getResponse().statusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLoggerPrepare.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        ResponseVerificationUtil.verifyErrorResponse(model, errorResponse);

        // Support application version
        powerAuthClient.supportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        // Verify that application version is supported
        GetApplicationDetailResponse detailResponse2 = powerAuthClient.getApplicationDetail(config.getApplicationId());
        for (ApplicationVersion appVersion: detailResponse2.getVersions()) {
            if (appVersion.getApplicationVersionId().equals(config.getApplicationVersion())) {
                assertTrue(appVersion.isSupported());
            }
        }
    }

    public static void activationPrepareExpirationTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config,
                                                       PrepareActivationStepModel model, PowerAuthVersion version) throws Exception {
        // Init activation should not fail, because application version is not known (applicationKey is not sent in InitActivationRequest)
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        // Expire activation with 1 hour in the past
        final Date expirationTime = Date.from(Instant.now().minus(Duration.ofHours(1)));
        initRequest.setTimestampActivationExpire(expirationTime);
        final Exception error = assertThrows(PowerAuthClientException.class, () -> powerAuthClient.initActivation(initRequest));
        assertEquals("requestObject.timestampActivationExpire - The activation expiration timestamp must be in the future when initiating activation", error.getMessage());
    }

    public static void activationPrepareWithoutInitTest(PowerAuthTestConfiguration config, PrepareActivationStepModel model) throws Exception {
        // Prepare non-existent activation
        model.setActivationCode("AAAAA-BBBBB-CCCCC-EEEEE");
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertFalse(stepLoggerPrepare.getResult().success());
        assertEquals(400, stepLoggerPrepare.getResponse().statusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLoggerPrepare.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
    }

    public static void activationPrepareBadMasterPublicKeyTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config,
                                                               PrepareActivationStepModel model, PowerAuthVersion version) throws Exception {
        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Verify activation status
        GetActivationStatusResponse statusResponseCreated = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponseCreated.getActivationStatus());

        KeyPair keyPair = new KeyGenerator().generateKeyPair(EcCurve.P256);
        PublicKey originalKey = model.getMasterPublicKeyP256();

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setMasterPublicKeyP256(keyPair.getPublic());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertFalse(stepLoggerPrepare.getResult().success());
        assertEquals(400, stepLoggerPrepare.getResponse().statusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLoggerPrepare.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());

        // Revert master public key change
        model.setMasterPublicKeyP256(originalKey);
    }

    public static void activationStatusTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config,
                                            PrepareActivationStepModel model, PowerAuthVersion version) throws Exception {
        final JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        initRequest.setMaxFailureCount(10L);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setResultStatusObject(resultStatusObject);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

        final EciesEncryptedResponse eciesResponse = (EciesEncryptedResponse) stepLoggerPrepare.getResponse().responseObject();
        assertNotNull(eciesResponse.getEncryptedData());
        assertNotNull(eciesResponse.getMac());

        // Verify activation status
        GetStatusStepModel statusModel = new GetStatusStepModel();
        statusModel.setResultStatusObject(resultStatusObject);
        statusModel.setHeaders(new HashMap<>());
        statusModel.setUriString(config.getPowerAuthIntegrationUrl());
        statusModel.setVersion(version);

        ObjectStepLogger stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());
        ActivationStatusRequest request = (ActivationStatusRequest) stepLoggerStatus.getRequest().requestObject();
        if (version != PowerAuthVersion.V3_0) {
            assertNotNull(request.getChallenge());
        }
        ObjectResponse<ActivationStatusResponse> responseObject = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().responseObject();
        ActivationStatusResponse response = responseObject.getResponseObject();
        assertEquals(initResponse.getActivationId(), response.getActivationId());
        if (version != PowerAuthVersion.V3_0) {
            assertNotNull(response.getNonce());
        }

        // Get transport key
        String transportMasterKeyBase64 = (String) model.getResultStatusObject().get("transportMasterKey");
        SecretKey transportMasterKey = config.getKeyConvertor().convertBytesToSharedSecretKey(Base64.getDecoder().decode(transportMasterKeyBase64));
        byte[] cStatusBlob = Base64.getDecoder().decode(response.getEncryptedStatusBlob());

        // Verify activation status blob
        ActivationStatusBlobInfo statusBlob;
        byte[] challengeData = null;
        byte[] nonceData = null;
        if (version == PowerAuthVersion.V3_0) {
            statusBlob = CLIENT_ACTIVATION.getStatusFromEncryptedBlob(cStatusBlob, null, null, transportMasterKey);
        } else {
            challengeData = Base64.getDecoder().decode(request.getChallenge());
            nonceData = Base64.getDecoder().decode(response.getNonce());
            statusBlob = CLIENT_ACTIVATION.getStatusFromEncryptedBlob(cStatusBlob, challengeData, nonceData, transportMasterKey);
            // Added in V3.1
            assertEquals(20, statusBlob.getCtrLookAhead());
            assertTrue(CLIENT_ACTIVATION.verifyHashForHashBasedCounter(statusBlob.getCtrDataHash(), CounterUtil.getCtrData(model, stepLoggerStatus), transportMasterKey, ProtocolVersion.fromValue(version.value())));
        }

        assertTrue(statusBlob.isValid());
        assertEquals(0x2, statusBlob.getActivationStatus());
        assertEquals(10, statusBlob.getMaxFailedAttempts());
        assertEquals(0, statusBlob.getFailedAttempts());
        assertEquals(3, statusBlob.getCurrentVersion());
        assertEquals(3, statusBlob.getUpgradeVersion());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Get status
        stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());
        request = (ActivationStatusRequest) stepLoggerStatus.getRequest().requestObject();
        responseObject = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().responseObject();
        response = responseObject.getResponseObject();
        assertEquals(initResponse.getActivationId(), response.getActivationId());

        // Verify activation status blob
        if (version != PowerAuthVersion.V3_0) {
            challengeData = Base64.getDecoder().decode(request.getChallenge());
            nonceData = Base64.getDecoder().decode(response.getNonce());
        }
        cStatusBlob = Base64.getDecoder().decode(response.getEncryptedStatusBlob());
        statusBlob = CLIENT_ACTIVATION.getStatusFromEncryptedBlob(cStatusBlob, challengeData, nonceData, transportMasterKey);
        assertTrue(statusBlob.isValid());
        assertEquals(0x3, statusBlob.getActivationStatus());

        // Block activation
        BlockActivationResponse blockResponse = powerAuthClient.blockActivation(initResponse.getActivationId(), "test", "test");
        assertEquals(initResponse.getActivationId(), blockResponse.getActivationId());
        assertEquals("test", blockResponse.getBlockedReason());

        // Get status
        stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());
        request = (ActivationStatusRequest) stepLoggerStatus.getRequest().requestObject();
        responseObject = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().responseObject();
        response = responseObject.getResponseObject();
        assertEquals(initResponse.getActivationId(), response.getActivationId());

        // Verify activation status blob
        if (version != PowerAuthVersion.V3_0) {
            challengeData = Base64.getDecoder().decode(request.getChallenge());
            nonceData = Base64.getDecoder().decode(response.getNonce());
        }
        cStatusBlob = Base64.getDecoder().decode(response.getEncryptedStatusBlob());
        statusBlob = CLIENT_ACTIVATION.getStatusFromEncryptedBlob(cStatusBlob, challengeData, nonceData, transportMasterKey);
        assertTrue(statusBlob.isValid());
        assertEquals(0x4, statusBlob.getActivationStatus());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");

        // Get status
        stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());
        request = (ActivationStatusRequest) stepLoggerStatus.getRequest().requestObject();
        responseObject = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().responseObject();
        response = responseObject.getResponseObject();
        assertEquals(initResponse.getActivationId(), response.getActivationId());

        // Verify activation status blob
        if (version != PowerAuthVersion.V3_0) {
            challengeData = Base64.getDecoder().decode(request.getChallenge());
            nonceData = Base64.getDecoder().decode(response.getNonce());
        }
        cStatusBlob = Base64.getDecoder().decode(response.getEncryptedStatusBlob());
        statusBlob = CLIENT_ACTIVATION.getStatusFromEncryptedBlob(cStatusBlob, challengeData, nonceData, transportMasterKey);
        assertTrue(statusBlob.isValid());
        assertEquals(0x5, statusBlob.getActivationStatus());
    }

    public static void activationInvalidApplicationKeyTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config,
                                                           PrepareActivationStepModel model, PowerAuthVersion version) throws Exception {
        // Init activation should not fail, because application version is not known (applicationKey is not sent in InitActivationRequest)
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Verify activation status
        GetActivationStatusResponse statusResponseCreated = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponseCreated.getActivationStatus());

        // PrepareActivation should fail
        model.setActivationCode(initResponse.getActivationCode());
        model.setApplicationKey("invalid");

        // Verify that PrepareActivation fails
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertFalse(stepLoggerPrepare.getResult().success());
        // Verify BAD_REQUEST status code
        assertEquals(400, stepLoggerPrepare.getResponse().statusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLoggerPrepare.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        ResponseVerificationUtil.verifyErrorResponse(model, errorResponse);
    }

    public static void activationInvalidApplicationSecretTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config,
                                                              PrepareActivationStepModel model, PowerAuthVersion version) throws Exception {
        // Init activation should not fail, because application version is not known (applicationKey is not sent in InitActivationRequest)
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Verify activation status
        GetActivationStatusResponse statusResponseCreated = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponseCreated.getActivationStatus());

        // PrepareActivation should fail
        model.setActivationCode(initResponse.getActivationCode());
        model.setApplicationSecret("invalid");

        // Verify that PrepareActivation fails
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertFalse(stepLoggerPrepare.getResult().success());
        // Verify BAD_REQUEST status code
        assertEquals(400, stepLoggerPrepare.getResponse().statusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLoggerPrepare.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        ResponseVerificationUtil.verifyErrorResponse(model, errorResponse);
    }

    public static void lookupActivationsTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws Exception {
        InitActivationResponse response = powerAuthClient.initActivation(config.getUser(version), config.getApplicationId());
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(response.getActivationId());
        final Date timestampCreated = statusResponse.getTimestampCreated();
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());
        final List<Activation> activations = powerAuthClient.lookupActivations(Collections.singletonList(config.getUser(version)), Collections.singletonList(config.getApplicationId()),
                null, timestampCreated, ActivationStatus.CREATED, null);
        assertTrue(activations.size() >= 1);
    }

    public static void lookupActivationsNonExistentUserTest(PowerAuthClient powerAuthClient) throws Exception {
        LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        lookupActivationsRequest.getUserIds().add("nonexistent");
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertEquals(0, response.getActivations().size());
    }

    public static void lookupActivationsApplicationTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws Exception {
        LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        lookupActivationsRequest.getUserIds().add(config.getUser(version));
        lookupActivationsRequest.getApplicationIds().add(config.getApplicationId());
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertTrue(response.getActivations().size() >= 1);
    }

    public static void lookupActivationsNonExistentApplicationTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws Exception {
        final LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        lookupActivationsRequest.getUserIds().add(config.getUser(version));
        lookupActivationsRequest.getApplicationIds().add("10000000");
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertEquals(0, response.getActivations().size());
    }

    public static void lookupActivationsStatusTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws Exception {
        LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        lookupActivationsRequest.getUserIds().add(config.getUser(version));
        lookupActivationsRequest.setActivationStatus(ActivationStatus.ACTIVE);
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertTrue(response.getActivations().size() >= 1);
    }

    public static void lookupActivationsInvalidStatusTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws Exception {
        //
        // This test may fail in case that our battery of tests leaves some activation in the blocked state.
        // Try to re-run the test alone, or fix the new test case that collides with this one.
        //
        LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        lookupActivationsRequest.getUserIds().add(config.getUser(version));
        lookupActivationsRequest.setActivationStatus(ActivationStatus.BLOCKED);
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertEquals(0, response.getActivations().size());
    }

    public static void lookupActivationsDateValidTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws Exception {
        LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        lookupActivationsRequest.getUserIds().add(config.getUser(version));
        final Date timestampLastUsedAfter = Date.from(Instant.now().minus(Duration.ofMinutes(1)));
        lookupActivationsRequest.setTimestampLastUsedAfter(timestampLastUsedAfter);
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertTrue(response.getActivations().size() >= 1);
    }

    public static void lookupActivationsDateInvalidTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws Exception {
        LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        lookupActivationsRequest.getUserIds().add(config.getUser(version));
        final Date timestampLastUsedAfter = Date.from(Instant.now().plus(Duration.ofMinutes(1)));
        lookupActivationsRequest.setTimestampLastUsedAfter(timestampLastUsedAfter);
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertEquals(0, response.getActivations().size());
    }

    public static void updateActivationStatusTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config,
                                                  PrepareActivationStepModel model, PowerAuthVersion version) throws Exception {
        final JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        initRequest.setMaxFailureCount(10L);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setResultStatusObject(resultStatusObject);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

        final EciesEncryptedResponse eciesResponse = (EciesEncryptedResponse) stepLoggerPrepare.getResponse().responseObject();
        assertNotNull(eciesResponse.getEncryptedData());
        assertNotNull(eciesResponse.getMac());

        // Verify activation status
        GetStatusStepModel statusModel = new GetStatusStepModel();
        statusModel.setResultStatusObject(resultStatusObject);
        statusModel.setHeaders(new HashMap<>());
        statusModel.setUriString(config.getPowerAuthIntegrationUrl());
        statusModel.setVersion(version);

        ObjectStepLogger stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());
        final ActivationStatusRequest request = (ActivationStatusRequest) stepLoggerStatus.getRequest().requestObject();
        if (version != PowerAuthVersion.V3_0) {
            assertNotNull(request.getChallenge());
        }
        final ObjectResponse<ActivationStatusResponse> responseObject = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().responseObject();
        ActivationStatusResponse response = responseObject.getResponseObject();
        assertEquals(initResponse.getActivationId(), response.getActivationId());
        if (version != PowerAuthVersion.V3_0) {
            assertNotNull(response.getNonce());
        }

        // Get transport key
        String transportMasterKeyBase64 = (String) model.getResultStatusObject().get("transportMasterKey");
        SecretKey transportMasterKey = config.getKeyConvertor().convertBytesToSharedSecretKey(Base64.getDecoder().decode(transportMasterKeyBase64));

        // Verify activation status blob
        byte[] challengeData = null;
        byte[] nonceData = null;
        byte[] cStatusBlob = Base64.getDecoder().decode(response.getEncryptedStatusBlob());
        ActivationStatusBlobInfo statusBlob;
        if (version == PowerAuthVersion.V3_0) {
            statusBlob = CLIENT_ACTIVATION.getStatusFromEncryptedBlob(cStatusBlob, null, null, transportMasterKey);
        } else {
            challengeData = Base64.getDecoder().decode(request.getChallenge());
            nonceData = Base64.getDecoder().decode(response.getNonce());
            statusBlob = CLIENT_ACTIVATION.getStatusFromEncryptedBlob(cStatusBlob, challengeData, nonceData, transportMasterKey);
            // Added in V3.1
            assertEquals(20, statusBlob.getCtrLookAhead());
            System.out.println("VAL: " + version.value());
            assertTrue(CLIENT_ACTIVATION.verifyHashForHashBasedCounter(statusBlob.getCtrDataHash(), CounterUtil.getCtrData(model, stepLoggerStatus), transportMasterKey, ProtocolVersion.fromValue(version.value())));
        }

        assertTrue(statusBlob.isValid());
        assertEquals(0x2, statusBlob.getActivationStatus());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Block activation using UpdateStatusForActivations method
        powerAuthClient.updateStatusForActivations(Collections.singletonList(initResponse.getActivationId()), ActivationStatus.BLOCKED);

        GetActivationStatusResponse statusResponseBlocked = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.BLOCKED, statusResponseBlocked.getActivationStatus());

        // Remove activation using UpdateStatusForActivations method
        powerAuthClient.updateStatusForActivations(Collections.singletonList(initResponse.getActivationId()), ActivationStatus.ACTIVE);

        GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, statusResponseActive.getActivationStatus());
    }

}
