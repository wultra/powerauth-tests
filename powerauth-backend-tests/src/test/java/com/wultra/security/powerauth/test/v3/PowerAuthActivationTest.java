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
import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.LookupActivationsRequest;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.GetStatusStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import io.getlime.security.powerauth.rest.api.model.response.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthActivationTest {

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private PrepareActivationStepModel model;
    private File tempStatusFile;

    private static final PowerAuthClientActivation activation = new PowerAuthClientActivation();

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @BeforeEach
    void setUp() throws IOException {
        // Create temp status file
        tempStatusFile = File.createTempFile("pa_status_v3", ".json");

        // Model shared among tests
        model = new PrepareActivationStepModel();
        model.setActivationName("test v3");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(new JSONObject());
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("3.0");
        model.setDeviceInfo("backend-tests");
    }

    @AfterEach
    void tearDown() {
        assertTrue(tempStatusFile.delete());
    }

    @Test
    void activationPrepareTest() throws Exception {
        // Init activation
        final InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV3());
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
        for (StepItem item : stepLoggerPrepare.getItems()) {
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
        final CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Verify activation status
        GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, statusResponseActive.getActivationStatus());

        // Block activation
        BlockActivationResponse blockResponse = powerAuthClient.blockActivation(initResponse.getActivationId(), "test", "test");
        assertEquals(initResponse.getActivationId(), blockResponse.getActivationId());
        assertEquals("test", blockResponse.getBlockedReason());

        // Verify activation status
        GetActivationStatusResponse statusResponseBlocked = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.BLOCKED, statusResponseBlocked.getActivationStatus());

        // Unblock activation
        UnblockActivationResponse unblockResponse = powerAuthClient.unblockActivation(initResponse.getActivationId(), "test");
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

    @Test
    void activationNonExistentTest() throws PowerAuthClientException {
        // Verify activation status
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus("AAAAA-BBBBB-CCCCC-DDDDD");
        assertEquals(ActivationStatus.REMOVED, statusResponse.getActivationStatus());
    }

    @Test
    void activationPrepareUnsupportedApplicationTest() throws Exception {
        // Unsupport application version
        powerAuthClient.unsupportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        // Verify that application version is unsupported
        GetApplicationDetailResponse detailResponse = powerAuthClient.getApplicationDetail(config.getApplicationId());
        for (ApplicationVersion version : detailResponse.getVersions()) {
            if (version.getApplicationVersionId().equals(config.getApplicationVersion())) {
                assertFalse(version.isSupported());
            }
        }

        // Init activation should not fail, because application version is not known (applicationKey is not sent in InitActivationRequest)
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV3());
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
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());

        // Support application version
        powerAuthClient.supportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        // Verify that application version is supported
        GetApplicationDetailResponse detailResponse2 = powerAuthClient.getApplicationDetail(config.getApplicationId());
        for (ApplicationVersion version : detailResponse2.getVersions()) {
            if (version.getApplicationVersionId().equals(config.getApplicationVersion())) {
                assertTrue(version.isSupported());
            }
        }
    }

    @Test
    void activationPrepareExpirationTest() throws Exception {
        // Init activation should not fail, because application version is not known (applicationKey is not sent in InitActivationRequest)
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV3());
        // Expire activation with 1 hour in the past
        final Date expirationTime = Date.from(Instant.now().minus(Duration.ofHours(1)));
        initRequest.setTimestampActivationExpire(expirationTime);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());

        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        // Verify BAD_REQUEST status code
        assertFalse(stepLoggerPrepare.getResult().success());
        assertEquals(400, stepLoggerPrepare.getResponse().statusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLoggerPrepare.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
    }

    @Test
    void activationPrepareWithoutInitTest() throws Exception {
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

    @Test
    void activationPrepareBadMasterPublicKeyTest() throws Exception {
        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV3());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Verify activation status
        GetActivationStatusResponse statusResponseCreated = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponseCreated.getActivationStatus());

        KeyPair keyPair = new KeyGenerator().generateKeyPair();
        PublicKey originalKey = model.getMasterPublicKey();

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setMasterPublicKey(keyPair.getPublic());
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
        model.setMasterPublicKey(originalKey);
    }

    @Test
    void activationStatusTest() throws Exception {
        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV3());
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
        statusModel.setVersion("3.0");

        ObjectStepLogger stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());
        ObjectResponse<ActivationStatusResponse> responseObject = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().responseObject();
        ActivationStatusResponse response = responseObject.getResponseObject();
        assertEquals(initResponse.getActivationId(), response.getActivationId());

        // Get transport key
        String transportMasterKeyBase64 = (String) model.getResultStatusObject().get("transportMasterKey");
        SecretKey transportMasterKey = config.getKeyConvertor().convertBytesToSharedSecretKey(Base64.getDecoder().decode(transportMasterKeyBase64));

        // Verify activation status blob
        byte[] cStatusBlob = Base64.getDecoder().decode(response.getEncryptedStatusBlob());
        ActivationStatusBlobInfo statusBlob = activation.getStatusFromEncryptedBlob(cStatusBlob, null, null, transportMasterKey);
        assertTrue(statusBlob.isValid());
        assertEquals(0x2, statusBlob.getActivationStatus());
        assertEquals(10, statusBlob.getMaxFailedAttempts());
        assertEquals(0, statusBlob.getFailedAttempts());
        assertEquals(3, statusBlob.getCurrentVersion());
        assertEquals(3, statusBlob.getUpgradeVersion());
        // For V3.0 protocol CTR_DATA has no actual meaning. We can skip this assertion.
        // assertArrayEquals(CounterUtil.getCtrData(model, stepLoggerStatus), statusBlob.getCtrData());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Get status
        stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());
        responseObject = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().responseObject();
        response = responseObject.getResponseObject();
        assertEquals(initResponse.getActivationId(), response.getActivationId());

        // Verify activation status blob
        cStatusBlob = Base64.getDecoder().decode(response.getEncryptedStatusBlob());
        statusBlob = activation.getStatusFromEncryptedBlob(cStatusBlob, null, null, transportMasterKey);
        assertTrue(statusBlob.isValid());
        assertEquals(0x3, statusBlob.getActivationStatus());

        // Block activation
        final BlockActivationResponse blockResponse = powerAuthClient.blockActivation(initResponse.getActivationId(), "test", "test");
        assertEquals(initResponse.getActivationId(), blockResponse.getActivationId());
        assertEquals("test", blockResponse.getBlockedReason());

        // Get status
        stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());
        responseObject = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().responseObject();
        response = responseObject.getResponseObject();
        assertEquals(initResponse.getActivationId(), response.getActivationId());

        // Verify activation status blob
        cStatusBlob = Base64.getDecoder().decode(response.getEncryptedStatusBlob());
        statusBlob = activation.getStatusFromEncryptedBlob(cStatusBlob, null, null, transportMasterKey);
        assertTrue(statusBlob.isValid());
        assertEquals(0x4, statusBlob.getActivationStatus());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");

        // Get status
        stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());
        responseObject = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().responseObject();
        response = responseObject.getResponseObject();
        assertEquals(initResponse.getActivationId(), response.getActivationId());

        // Verify activation status blob
        cStatusBlob = Base64.getDecoder().decode(response.getEncryptedStatusBlob());
        statusBlob = activation.getStatusFromEncryptedBlob(cStatusBlob, null, null, transportMasterKey);
        assertTrue(statusBlob.isValid());
        assertEquals(0x5, statusBlob.getActivationStatus());
    }

    @Test
    void activationInvalidApplicationKeyTest() throws Exception {
        // Init activation should not fail, because application version is not known (applicationKey is not sent in InitActivationRequest)
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV3());
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
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
    }

    @Test
    void activationInvalidApplicationSecretTest() throws Exception {
        // Init activation should not fail, because application version is not known (applicationKey is not sent in InitActivationRequest)
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV3());
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
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
    }

    @Test
    void lookupActivationsTest() throws Exception {
        InitActivationResponse response = powerAuthClient.initActivation(config.getUserV3(), config.getApplicationId());
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(response.getActivationId());
        final Date timestampCreated = statusResponse.getTimestampCreated();
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());
        List<Activation> activations = powerAuthClient.lookupActivations(Collections.singletonList(config.getUserV3()), Collections.singletonList(config.getApplicationId()),
                null, timestampCreated, ActivationStatus.CREATED, null);
        assertTrue(activations.size() >= 1);
    }

    @Test
    void lookupActivationsNonExistentUserTest() throws Exception {
        LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        lookupActivationsRequest.getUserIds().add("nonexistent");
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertEquals(0, response.getActivations().size());
    }

    @Test
    void lookupActivationsApplicationTest() throws Exception {
        final LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        lookupActivationsRequest.getUserIds().add(config.getUserV3());
        lookupActivationsRequest.getApplicationIds().add(config.getApplicationId());
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertTrue(response.getActivations().size() >= 1);
    }

    @Test
    void lookupActivationsNonExistentApplicationTest() throws Exception {
        LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        lookupActivationsRequest.getUserIds().add(config.getUserV3());
        lookupActivationsRequest.getApplicationIds().add("10000000");
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertEquals(0, response.getActivations().size());
    }

    @Test
    void lookupActivationsStatusTest() throws Exception {
        LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        lookupActivationsRequest.getUserIds().add(config.getUserV3());
        lookupActivationsRequest.setActivationStatus(ActivationStatus.ACTIVE);
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertTrue(response.getActivations().size() >= 1);
    }

    @Test
    void lookupActivationsInvalidStatusTest() throws Exception {
        //
        // This test may fail in case that our battery of tests leaves some activation in the blocked state.
        // Try to re-run the test alone, or fix the new test case that collides with this one.
        //
        LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        lookupActivationsRequest.getUserIds().add(config.getUserV3());
        lookupActivationsRequest.setActivationStatus(ActivationStatus.BLOCKED);
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertEquals(0, response.getActivations().size());
    }

    @Test
    void lookupActivationsDateValidTest() throws Exception {
        LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        lookupActivationsRequest.getUserIds().add(config.getUserV3());
        final Date timestampLastUsedAfter = Date.from(Instant.now().minus(Duration.ofMinutes(1)));
        lookupActivationsRequest.setTimestampLastUsedAfter(timestampLastUsedAfter);
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertTrue(response.getActivations().size() >= 1);
    }

    @Test
    void lookupActivationsDateInvalidTest() throws Exception {
        LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        lookupActivationsRequest.getUserIds().add(config.getUserV3());
        final Date timestampLastUsedAfter = Date.from(Instant.now().plus(Duration.ofMinutes(1)));
        lookupActivationsRequest.setTimestampLastUsedAfter(timestampLastUsedAfter);
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertEquals(0, response.getActivations().size());
    }

    @Test
    void updateActivationStatusTest() throws Exception {
        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV3());
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
        statusModel.setVersion("3.0");

        ObjectStepLogger stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());
        final ObjectResponse<ActivationStatusResponse> responseObject = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().responseObject();
        ActivationStatusResponse response = responseObject.getResponseObject();
        assertEquals(initResponse.getActivationId(), response.getActivationId());

        // Get transport key
        String transportMasterKeyBase64 = (String) model.getResultStatusObject().get("transportMasterKey");
        SecretKey transportMasterKey = config.getKeyConvertor().convertBytesToSharedSecretKey(Base64.getDecoder().decode(transportMasterKeyBase64));

        // Verify activation status blob
        byte[] cStatusBlob = Base64.getDecoder().decode(response.getEncryptedStatusBlob());
        ActivationStatusBlobInfo statusBlob = activation.getStatusFromEncryptedBlob(cStatusBlob, null, null, transportMasterKey);
        assertTrue(statusBlob.isValid());
        assertEquals(0x2, statusBlob.getActivationStatus());
        // For V3.0 protocol CTR_DATA has no actual meaning. We can skip this assertion.
        // assertArrayEquals(CounterUtil.getCtrData(model, stepLoggerStatus), statusBlob.getCtrData());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Block activation using UpdateStatusForActivations method
        powerAuthClient.updateStatusForActivations(Collections.singletonList(initResponse.getActivationId()), ActivationStatus.BLOCKED);

        GetActivationStatusResponse statusResponseBlocked = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.BLOCKED, statusResponseBlocked.getActivationStatus());

        // Remove activation using UpdateStatusForActivations method
        powerAuthClient.updateStatusForActivations(Collections.singletonList(initResponse.getActivationId()), ActivationStatus.ACTIVE);

        GetActivationStatusResponse statusResponseRemoved = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, statusResponseRemoved.getActivationStatus());
    }


}