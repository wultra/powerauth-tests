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
import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.LookupActivationsRequest;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.client.model.response.v4.GetActivationStatusResponse;
import com.wultra.security.powerauth.client.model.response.v4.GetApplicationDetailResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.client.v4.activation.PowerAuthClientActivation;
import com.wultra.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.model.StepItem;
import com.wultra.security.powerauth.lib.cmd.steps.ConfirmActivationStep;
import com.wultra.security.powerauth.lib.cmd.steps.GetStatusStep;
import com.wultra.security.powerauth.lib.cmd.steps.PrepareActivationStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.ConfirmActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.AssertionFailureBuilder;

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

        checkEncryptedResponse(stepLoggerPrepare.getResponse().responseObject());

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

    public static void activationConfirmTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config,
                                             PrepareActivationStepModel model, PowerAuthVersion version, boolean enableBiometry) throws Exception {
        // Init activation
        final InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        final InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

        // Verify activation status including status bits
        GetActivationStatusResponse statusResponseBeforeConfirm = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.PENDING_COMMIT, statusResponseBeforeConfirm.getActivationStatus());
        byte[] statusBlob = Base64.getDecoder().decode(statusResponseBeforeConfirm.getStatusBlob());
        ActivationStatusBlobInfo statusBlobInfo = new PowerAuthClientActivation().getStatusFromBlob(statusBlob);
        assertTrue(statusBlobInfo.isValid());
        // Status bits are set to 0001 (pending confirmation)
        assertEquals(1, statusBlobInfo.getStatusFlags());

        // Confirm activation
        ConfirmActivationStepModel confirmModel = new ConfirmActivationStepModel();
        confirmModel.setApplicationKey(config.getApplicationKey());
        confirmModel.setApplicationSecret(config.getApplicationSecret());
        confirmModel.setEnableBiometry(enableBiometry);
        confirmModel.setPassword(config.getPassword());
        confirmModel.setVersion(version);
        confirmModel.setStatusFileName(model.getStatusFileName());
        confirmModel.setResultStatusObject(model.getResultStatusObject());
        confirmModel.setUriString(config.getPowerAuthIntegrationUrl());
        ObjectStepLogger stepLoggerConfirm = new ObjectStepLogger(System.out);
        new ConfirmActivationStep().execute(stepLoggerConfirm, confirmModel.toMap());
        assertTrue(stepLoggerConfirm.getResult().success());

        // Verify activation status including status bits
        GetActivationStatusResponse statusResponseConfirmed = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.PENDING_COMMIT, statusResponseConfirmed.getActivationStatus());
        byte[] statusBlobConfirmed = Base64.getDecoder().decode(statusResponseConfirmed.getStatusBlob());
        ActivationStatusBlobInfo statusBlobInfoConfirmed = new PowerAuthClientActivation().getStatusFromBlob(statusBlobConfirmed);
        assertTrue(statusBlobInfoConfirmed.isValid());
        if (enableBiometry) {
            // Status bits are 1000 (biometry enabled, confirmed)
            assertEquals(8, statusBlobInfoConfirmed.getStatusFlags());
        } else {
            // Status bits are 0000 (biometry disabled, confirmed)
            assertEquals(0, statusBlobInfoConfirmed.getStatusFlags());
        }

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Verify activation status
        GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, statusResponseActive.getActivationStatus());
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
        assertEquals("ERR_TEMPORARY_KEY", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_TEMPORARY_KEY_FAILURE", errorResponse.getResponseObject().getMessage());

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

        checkEncryptedResponse(stepLoggerPrepare.getResponse().responseObject());

        // Verify activation status
        GetStatusStepModel statusModel = new GetStatusStepModel();
        statusModel.setResultStatusObject(resultStatusObject);
        statusModel.setHeaders(new HashMap<>());
        statusModel.setUriString(config.getPowerAuthIntegrationUrl());
        statusModel.setApplicationKey(config.getApplicationKey());
        statusModel.setApplicationSecret(config.getApplicationSecret());
        statusModel.setVersion(version);

        ObjectStepLogger stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());

        ActivationStatusBlobInfo statusBlob = extractStatusBlob(stepLoggerStatus);
        assertTrue(statusBlob.isValid());
        assertEquals(0x2, statusBlob.getActivationStatus());
        assertEquals(10, statusBlob.getMaxFailedAttempts());
        assertEquals(0, statusBlob.getFailedAttempts());
        assertEquals(4, statusBlob.getCurrentVersion());
        assertEquals(4, statusBlob.getUpgradeVersion());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Check status
        stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());
        statusBlob = extractStatusBlob(stepLoggerStatus);
        assertTrue(statusBlob.isValid());
        assertEquals(0x3, statusBlob.getActivationStatus());

        // Block activation
        BlockActivationResponse blockResponse = powerAuthClient.blockActivation(initResponse.getActivationId(), "test", "test");
        assertEquals(initResponse.getActivationId(), blockResponse.getActivationId());
        assertEquals("test", blockResponse.getBlockedReason());

        // Check status
        stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());
        statusBlob = extractStatusBlob(stepLoggerStatus);
        assertTrue(statusBlob.isValid());
        assertEquals(0x4, statusBlob.getActivationStatus());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");

        // Check status
        stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());
        statusBlob = extractStatusBlob(stepLoggerStatus);
        assertTrue(statusBlob.isValid());
        assertEquals(0x5, statusBlob.getActivationStatus());
    }

    private static ActivationStatusBlobInfo extractStatusBlob(ObjectStepLogger stepLogger) {
        Object responseObject = stepLogger.getItems().stream()
                .filter(item -> "Activation Status".equals(item.name()))
                .map(StepItem::object)
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure().message("Activation Status response is invalid").build());

        @SuppressWarnings("unchecked")
        final Map<String, Object> responseObjectMap = (Map<String, Object>) responseObject;
        return (ActivationStatusBlobInfo) responseObjectMap.get("statusBlob");
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
        assertEquals("ERR_TEMPORARY_KEY", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_TEMPORARY_KEY_FAILURE", errorResponse.getResponseObject().getMessage());
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
        assertEquals("ERR_TEMPORARY_KEY", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_TEMPORARY_KEY_FAILURE", errorResponse.getResponseObject().getMessage());
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

        checkEncryptedResponse(stepLoggerPrepare.getResponse().responseObject());

        // Verify activation status
        GetStatusStepModel statusModel = new GetStatusStepModel();
        statusModel.setResultStatusObject(resultStatusObject);
        statusModel.setHeaders(new HashMap<>());
        statusModel.setUriString(config.getPowerAuthIntegrationUrl());
        statusModel.setApplicationKey(config.getApplicationKey());
        statusModel.setApplicationSecret(config.getApplicationSecret());
        statusModel.setVersion(version);
        ObjectStepLogger stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());

        ActivationStatusBlobInfo statusBlob = extractStatusBlob(stepLoggerStatus);
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

    private static void checkEncryptedResponse(Object response) {
        final AeadEncryptedResponse aeadResponse = (AeadEncryptedResponse) response;
        assertNotNull(aeadResponse.getEncryptedData());
        assertNotNull(aeadResponse.getTimestamp());
    }

}
