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
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.powerauth.soap.v3.*;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.v3.GetStatusStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import io.getlime.security.powerauth.lib.cmd.util.CounterUtil;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.json.simple.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import javax.crypto.SecretKey;
import javax.xml.datatype.DatatypeFactory;
import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthActivationTest {

    private PowerAuthServiceClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private PrepareActivationStepModel model;
    private File tempStatusFile;

    private static final PowerAuthClientActivation activation = new PowerAuthClientActivation();

    @Autowired
    public void setPowerAuthServiceClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Before
    public void setUp() throws IOException {
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
    }

    @After
    public void tearDown() {
        assertTrue(tempStatusFile.delete());
    }

    @Test
    public void activationPrepareTest() throws Exception {
        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV3());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Verify activation status
        GetActivationStatusResponse statusResponseCreated = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponseCreated.getActivationStatus());

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        EciesEncryptedResponse eciesResponse = (EciesEncryptedResponse) stepLoggerPrepare.getResponse().getResponseObject();
        assertNotNull(eciesResponse.getEncryptedData());
        assertNotNull(eciesResponse.getMac());

        // Verify decrypted activationId
        String activationIdPrepareResponse = null;
        for (StepItem item: stepLoggerPrepare.getItems()) {
            if (item.getName().equals("Activation Done")) {
                Map<String, Object> responseMap = (Map<String, Object>) item.getObject();
                activationIdPrepareResponse = (String) responseMap.get("activationId");
                break;
            }
        }

        assertEquals(initResponse.getActivationId(), activationIdPrepareResponse);

        // Verify activation status
        GetActivationStatusResponse statusResponseOtpUsed = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.OTP_USED, statusResponseOtpUsed.getActivationStatus());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId());
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Verify activation status
        GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, statusResponseActive.getActivationStatus());

        // Block activation
        BlockActivationResponse blockResponse = powerAuthClient.blockActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), blockResponse.getActivationId());
        assertEquals("test", blockResponse.getBlockedReason());

        // Verify activation status
        GetActivationStatusResponse statusResponseBlocked = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.BLOCKED, statusResponseBlocked.getActivationStatus());

        // Unblock activation
        UnblockActivationResponse unblockResponse = powerAuthClient.unblockActivation(initResponse.getActivationId());
        assertEquals(initResponse.getActivationId(), unblockResponse.getActivationId());

        // Verify activation status
        GetActivationStatusResponse statusResponseActive2 = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, statusResponseActive2.getActivationStatus());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId());

        // Verify activation status
        GetActivationStatusResponse statusResponseRemoved = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.REMOVED, statusResponseRemoved.getActivationStatus());
    }

    @Test
    public void activationNonExistentTest() {
        // Verify activation status
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus("AAAAA-BBBBB-CCCCC-DDDDD");
        assertEquals(ActivationStatus.REMOVED, statusResponse.getActivationStatus());
    }

    @Test
    public void activationPrepareUnsupportedApplicationTest() throws Exception {
        // Unsupport application version
        powerAuthClient.unsupportApplicationVersion(config.getApplicationVersionId());

        // Verify that application version is unsupported
        GetApplicationDetailResponse detailResponse = powerAuthClient.getApplicationDetail(config.getApplicationId());
        for (GetApplicationDetailResponse.Versions version: detailResponse.getVersions()) {
            if (version.getApplicationVersionName().equals(config.getApplicationVersion())) {
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
        assertFalse(stepLoggerPrepare.getResult().isSuccess());
        // Verify BAD_REQUEST status code
        assertEquals(400, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLoggerPrepare.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());

        // Support application version
        powerAuthClient.supportApplicationVersion(config.getApplicationVersionId());

        // Verify that application version is supported
        GetApplicationDetailResponse detailResponse2 = powerAuthClient.getApplicationDetail(config.getApplicationId());
        for (GetApplicationDetailResponse.Versions version: detailResponse2.getVersions()) {
            if (version.getApplicationVersionName().equals(config.getApplicationVersion())) {
                assertTrue(version.isSupported());
            }
        }
    }

    @Test
    public void activationPrepareExpirationTest() throws Exception {
        // Init activation should not fail, because application version is not known (applicationKey is not sent in InitActivationRequest)
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV3());
        // Expire activation with 1 second in the past
        GregorianCalendar gregorianCalendar = new GregorianCalendar();
        gregorianCalendar.setTimeInMillis(System.currentTimeMillis() - 1000);
        initRequest.setTimestampActivationExpire(DatatypeFactory.newInstance().newXMLGregorianCalendar(gregorianCalendar));
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());

        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        // Verify BAD_REQUEST status code
        assertFalse(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(400, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLoggerPrepare.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
    }

    @Test
    public void activationPrepareWithoutInitTest() throws Exception {
        // Prepare non-existent activation
        model.setActivationCode("AAAAA-BBBBB-CCCCC-EEEEE");
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertFalse(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(400, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLoggerPrepare.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
    }

    @Test
    public void activationPrepareBadMasterPublicKeyTest() throws Exception {
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
        assertFalse(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(400, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLoggerPrepare.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());

        // Revert master public key change
        model.setMasterPublicKey(originalKey);
    }

    @Test
    public void activationStatusTest() throws Exception {
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
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        EciesEncryptedResponse eciesResponse = (EciesEncryptedResponse) stepLoggerPrepare.getResponse().getResponseObject();
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
        assertTrue(stepLoggerStatus.getResult().isSuccess());
        assertEquals(200, stepLoggerStatus.getResponse().getStatusCode());
        ObjectResponse<ActivationStatusResponse> responseObject = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().getResponseObject();
        ActivationStatusResponse response = responseObject.getResponseObject();
        assertEquals(initResponse.getActivationId(), response.getActivationId());
        assertNull(response.getCustomObject());

        // Get transport key
        String transportMasterKeyBase64 = (String) model.getResultStatusObject().get("transportMasterKey");
        SecretKey transportMasterKey = config.getKeyConversion().convertBytesToSharedSecretKey(BaseEncoding.base64().decode(transportMasterKeyBase64));

        // Verify activation status blob
        byte[] cStatusBlob = BaseEncoding.base64().decode(response.getEncryptedStatusBlob());
        ActivationStatusBlobInfo statusBlob = activation.getStatusFromEncryptedBlob(cStatusBlob, transportMasterKey);
        assertTrue(statusBlob.isValid());
        assertEquals(0x2, statusBlob.getActivationStatus());
        assertEquals(10, statusBlob.getMaxFailedAttempts());
        assertEquals(0, statusBlob.getFailedAttempts());
        assertEquals(3, statusBlob.getCurrentVersion());
        assertEquals(3, statusBlob.getUpgradeVersion());
        assertArrayEquals(CounterUtil.getCtrData(model, stepLoggerStatus), statusBlob.getCtrData());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId());
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Get status
        stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().isSuccess());
        assertEquals(200, stepLoggerStatus.getResponse().getStatusCode());
        responseObject = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().getResponseObject();
        response = responseObject.getResponseObject();
        assertEquals(initResponse.getActivationId(), response.getActivationId());

        // Verify activation status blob
        cStatusBlob = BaseEncoding.base64().decode(response.getEncryptedStatusBlob());
        statusBlob = activation.getStatusFromEncryptedBlob(cStatusBlob, transportMasterKey);
        assertTrue(statusBlob.isValid());
        assertEquals(0x3, statusBlob.getActivationStatus());

        // Block activation
        BlockActivationResponse blockResponse = powerAuthClient.blockActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), blockResponse.getActivationId());
        assertEquals("test", blockResponse.getBlockedReason());

        // Get status
        stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().isSuccess());
        assertEquals(200, stepLoggerStatus.getResponse().getStatusCode());
        responseObject = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().getResponseObject();
        response = responseObject.getResponseObject();
        assertEquals(initResponse.getActivationId(), response.getActivationId());

        // Verify activation status blob
        cStatusBlob = BaseEncoding.base64().decode(response.getEncryptedStatusBlob());
        statusBlob = activation.getStatusFromEncryptedBlob(cStatusBlob, transportMasterKey);
        assertTrue(statusBlob.isValid());
        assertEquals(0x4, statusBlob.getActivationStatus());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId());

        // Get status
        stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().isSuccess());
        assertEquals(200, stepLoggerStatus.getResponse().getStatusCode());
        responseObject = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().getResponseObject();
        response = responseObject.getResponseObject();
        assertEquals(initResponse.getActivationId(), response.getActivationId());

        // Verify activation status blob
        cStatusBlob = BaseEncoding.base64().decode(response.getEncryptedStatusBlob());
        statusBlob = activation.getStatusFromEncryptedBlob(cStatusBlob, transportMasterKey);
        assertTrue(statusBlob.isValid());
        assertEquals(0x5, statusBlob.getActivationStatus());
    }

    @Test
    public void activationInvalidApplicationKeyTest() throws Exception {
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
        assertFalse(stepLoggerPrepare.getResult().isSuccess());
        // Verify BAD_REQUEST status code
        assertEquals(400, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLoggerPrepare.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
    }

    @Test
    public void activationInvalidApplicationSecretTest() throws Exception {
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
        assertFalse(stepLoggerPrepare.getResult().isSuccess());
        // Verify BAD_REQUEST status code
        assertEquals(400, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLoggerPrepare.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
    }

}
