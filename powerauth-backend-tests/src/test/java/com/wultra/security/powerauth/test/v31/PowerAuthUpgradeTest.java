/*
 * PowerAuth test and related software components
 * Copyright (C) 2019 Wultra s.r.o.
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
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.powerauth.soap.v3.*;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.VerifySignatureStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.CommitUpgradeStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.StartUpgradeStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.CommitUpgradeStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.StartUpgradeStep;
import io.getlime.security.powerauth.lib.cmd.util.CounterUtil;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.json.simple.JSONObject;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
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
import java.util.*;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthUpgradeTest {

    private PowerAuthServiceClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private File tempStatusFile;
    private File dataFile;

    private static final PowerAuthClientActivation activation = new PowerAuthClientActivation();
    private static final KeyGenerator keyGenerator = new KeyGenerator();

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
        tempStatusFile = File.createTempFile("pa_status", ".json");

        // Create temp data file
        dataFile = File.createTempFile("data", ".json");
        FileWriter fw = new FileWriter(dataFile);
        fw.write("All your base are belong to us!");
        fw.close();
    }

    @After
    public void tearDown() {
        assertTrue(tempStatusFile.delete());
        assertTrue(dataFile.delete());
    }

    @Test
    public void upgradeValidTest() throws Exception {
        // Shared resultStatus object
        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV2());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Verify activation status
        GetActivationStatusResponse statusResponseCreated = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponseCreated.getActivationStatus());

        // Prepare activation model
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationName("upgrade test");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(resultStatusObject);
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("2.1");

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new io.getlime.security.powerauth.lib.cmd.steps.v2.PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify activation status
        GetActivationStatusResponse statusResponseOtpUsed = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.OTP_USED, statusResponseOtpUsed.getActivationStatus());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Verify activation status and version
        GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatusWithEncryptedStatusBlob(initResponse.getActivationId(), null);
        assertEquals(ActivationStatus.ACTIVE, statusResponseActive.getActivationStatus());
        assertEquals(2, statusResponseActive.getVersion());

        // Get transport key
        String transportMasterKeyBase64 = (String) model.getResultStatusObject().get("transportMasterKey");
        SecretKey transportMasterKey = config.getKeyConversion().convertBytesToSharedSecretKey(BaseEncoding.base64().decode(transportMasterKeyBase64));

        // Verify activation status blob
        byte[] cStatusBlob = BaseEncoding.base64().decode(statusResponseActive.getEncryptedStatusBlob());
        ActivationStatusBlobInfo statusBlob = activation.getStatusFromEncryptedBlob(cStatusBlob, null, null, transportMasterKey);
        assertTrue(statusBlob.isValid());
        assertEquals(0x3, statusBlob.getActivationStatus());
        assertEquals(5, statusBlob.getMaxFailedAttempts());
        assertEquals(0, statusBlob.getFailedAttempts());
        assertEquals(2, statusBlob.getCurrentVersion());
        assertEquals(3, statusBlob.getUpgradeVersion());
        // Do not verify counter data, it is valid only for v3

        // Prepare signature model
        VerifySignatureStepModel modelSig = new VerifySignatureStepModel();
        modelSig.setApplicationKey(config.getApplicationKey());
        modelSig.setApplicationSecret(config.getApplicationSecret());
        modelSig.setDataFileName(dataFile.getAbsolutePath());
        modelSig.setHeaders(new HashMap<>());
        modelSig.setHttpMethod("POST");
        modelSig.setPassword(config.getPassword());
        modelSig.setResourceId("/pa/signature/validate");
        modelSig.setResultStatusObject(resultStatusObject);
        modelSig.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        modelSig.setStatusFileName(tempStatusFile.getAbsolutePath());
        modelSig.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/signature/validate");
        modelSig.setVersion("2.1");

        // Check counter values
        long counter0 = (long) model.getResultStatusObject().get("counter");
        String ctrData0 = (String) model.getResultStatusObject().get("ctrData");
        assertEquals(0, counter0);
        assertNull(ctrData0);

        // Verify version 2.1 signature
        ObjectStepLogger stepLoggerSig1 = new ObjectStepLogger(System.out);
        new VerifySignatureStep().execute(stepLoggerSig1, modelSig.toMap());
        assertTrue(stepLoggerSig1.getResult().isSuccess());
        assertEquals(200, stepLoggerSig1.getResponse().getStatusCode());

        // Check counter values
        long counter1 = (long) model.getResultStatusObject().get("counter");
        String ctrData1 = (String) model.getResultStatusObject().get("ctrData");
        assertEquals(1, counter1);
        assertNull(ctrData1);

        // Prepare start upgrade model
        StartUpgradeStepModel model1 = new StartUpgradeStepModel();
        model1.setApplicationKey(config.getApplicationKey());
        model1.setApplicationSecret(config.getApplicationSecret());
        model1.setStatusFileName(tempStatusFile.getAbsolutePath());
        model1.setHeaders(new HashMap<>());
        model1.setResultStatusObject(resultStatusObject);
        model1.setUriString(config.getPowerAuthIntegrationUrl());
        model1.setVersion("3.1");

        // Start upgrade of activation to version 3.1
        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new StartUpgradeStep().execute(stepLogger1, model1.toMap());
        assertTrue(stepLogger1.getResult().isSuccess());
        assertEquals(200, stepLogger1.getResponse().getStatusCode());

        // Check counter values
        long counter2 = (long) model.getResultStatusObject().get("counter");
        String ctrData2 = (String) model.getResultStatusObject().get("ctrData");
        assertEquals(1, counter2);
        assertNotNull(ctrData2);

        // Prepare commit upgrade model
        CommitUpgradeStepModel model2 = new CommitUpgradeStepModel();
        model2.setApplicationKey(config.getApplicationKey());
        model2.setApplicationSecret(config.getApplicationSecret());
        model2.setStatusFileName(tempStatusFile.getAbsolutePath());
        model2.setHeaders(new HashMap<>());
        model2.setResultStatusObject(resultStatusObject);
        model2.setUriString(config.getPowerAuthIntegrationUrl());
        model2.setVersion("3.1");

        // Commit upgrade of activation to version 3.1
        ObjectStepLogger stepLogger2 = new ObjectStepLogger(System.out);
        new CommitUpgradeStep().execute(stepLogger2, model2.toMap());
        assertTrue(stepLogger2.getResult().isSuccess());
        assertEquals(200, stepLogger2.getResponse().getStatusCode());

        // Check counter values
        long counter3 = (long) model.getResultStatusObject().get("counter");
        String ctrData3 = (String) model.getResultStatusObject().get("ctrData");
        assertEquals(2, counter3);
        assertArrayEquals(new HashBasedCounter().next(BaseEncoding.base64().decode(ctrData2)), BaseEncoding.base64().decode(ctrData3));

        // Verify activation status and version
        byte[] statusChallenge = keyGenerator.generateRandomBytes(16);
        GetActivationStatusResponse statusResponseMigrated = powerAuthClient.getActivationStatusWithEncryptedStatusBlob(initResponse.getActivationId(), BaseEncoding.base64().encode(statusChallenge));
        assertEquals(ActivationStatus.ACTIVE, statusResponseMigrated.getActivationStatus());
        assertNotNull(statusResponseMigrated.getEncryptedStatusBlobNonce());
        assertEquals(3, statusResponseMigrated.getVersion());
        byte[] statusNonce = BaseEncoding.base64().decode(statusResponseMigrated.getEncryptedStatusBlobNonce());

        // Verify activation status blob
        cStatusBlob = BaseEncoding.base64().decode(statusResponseMigrated.getEncryptedStatusBlob());
        statusBlob = activation.getStatusFromEncryptedBlob(cStatusBlob, statusChallenge,  statusNonce, transportMasterKey);
        assertTrue(statusBlob.isValid());
        assertEquals(0x3, statusBlob.getActivationStatus());
        assertEquals(5, statusBlob.getMaxFailedAttempts());
        assertEquals(0, statusBlob.getFailedAttempts());
        assertEquals(3, statusBlob.getCurrentVersion());
        assertEquals(3, statusBlob.getUpgradeVersion());
        assertEquals(20, statusBlob.getCtrLookAhead());
        assertTrue(activation.verifyHashForHasBasedCounter(statusBlob.getCtrDataHash(), CounterUtil.getCtrData(model, stepLoggerPrepare), transportMasterKey));

        // Verify version 3.1 signature
        modelSig.setVersion("3.1");
        modelSig.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate");
        ObjectStepLogger stepLoggerSig2 = new ObjectStepLogger(System.out);
        new VerifySignatureStep().execute(stepLoggerSig2, modelSig.toMap());
        assertTrue(stepLoggerSig2.getResult().isSuccess());
        assertEquals(200, stepLoggerSig1.getResponse().getStatusCode());

        // Check counter values
        long counter4 = (long) model.getResultStatusObject().get("counter");
        String ctrData4 = (String) model.getResultStatusObject().get("ctrData");
        assertEquals(3, counter4);
        assertArrayEquals(new HashBasedCounter().next(BaseEncoding.base64().decode(ctrData3)), BaseEncoding.base64().decode(ctrData4));

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    public void upgradeUnsupportedApplicationVersionTest() throws Exception {
        // Shared resultStatus object
        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV2());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation model
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationName("upgrade test");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(resultStatusObject);
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("3.1");

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Unsupport application version
        powerAuthClient.unsupportApplicationVersion(config.getApplicationVersionId());

        // Prepare start upgrade model
        StartUpgradeStepModel model1 = new StartUpgradeStepModel();
        model1.setApplicationKey(config.getApplicationKey());
        model1.setApplicationSecret(config.getApplicationSecret());
        model1.setStatusFileName(tempStatusFile.getAbsolutePath());
        model1.setHeaders(new HashMap<>());
        model1.setResultStatusObject(resultStatusObject);
        model1.setUriString(config.getPowerAuthIntegrationUrl());
        model1.setVersion("3.1");

        // Verify that it is not possible to migrate the activation
        ObjectStepLogger stepLoggerMig = new ObjectStepLogger(System.out);
        new StartUpgradeStep().execute(stepLoggerMig, model1.toMap());
        assertFalse(stepLoggerMig.getResult().isSuccess());
        assertEquals(400, stepLoggerMig.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLoggerMig.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_UPGRADE", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_UPGRADE_FAILED", errorResponse.getResponseObject().getMessage());

        // Support application version
        powerAuthClient.supportApplicationVersion(config.getApplicationVersionId());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    public void upgradeInvalidActivationVersionTest() throws Exception {
        // Shared resultStatus object
        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV2());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Verify activation status
        GetActivationStatusResponse statusResponseCreated = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponseCreated.getActivationStatus());

        // Prepare activation model
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationName("upgrade test");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(resultStatusObject);
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("3.1");

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify activation status
        GetActivationStatusResponse statusResponseOtpUsed = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.OTP_USED, statusResponseOtpUsed.getActivationStatus());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Verify activation status and version
        GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, statusResponseActive.getActivationStatus());
        assertEquals(3, statusResponseActive.getVersion());

        // Prepare start upgrade model
        StartUpgradeStepModel model1 = new StartUpgradeStepModel();
        model1.setApplicationKey(config.getApplicationKey());
        model1.setApplicationSecret(config.getApplicationSecret());
        model1.setStatusFileName(tempStatusFile.getAbsolutePath());
        model1.setHeaders(new HashMap<>());
        model1.setResultStatusObject(resultStatusObject);
        model1.setUriString(config.getPowerAuthIntegrationUrl());
        model1.setVersion("3.1");

        // Verify that it is not possible to migrate the activation
        ObjectStepLogger stepLoggerMig = new ObjectStepLogger(System.out);
        new StartUpgradeStep().execute(stepLoggerMig, model1.toMap());
        assertFalse(stepLoggerMig.getResult().isSuccess());
        assertEquals(400, stepLoggerMig.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLoggerMig.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_UPGRADE", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_UPGRADE_FAILED", errorResponse.getResponseObject().getMessage());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    public void upgradeActivationRemovedTest() throws Exception {
        // Shared resultStatus object
        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV2());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Verify activation status
        GetActivationStatusResponse statusResponseCreated = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponseCreated.getActivationStatus());

        // Prepare activation model
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationName("upgrade test");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(resultStatusObject);
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("3.1");

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Prepare start upgrade model
        StartUpgradeStepModel model1 = new StartUpgradeStepModel();
        model1.setApplicationKey(config.getApplicationKey());
        model1.setApplicationSecret(config.getApplicationSecret());
        model1.setStatusFileName(tempStatusFile.getAbsolutePath());
        model1.setHeaders(new HashMap<>());
        model1.setResultStatusObject(resultStatusObject);
        model1.setUriString(config.getPowerAuthIntegrationUrl());
        model1.setVersion("3.1");

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");

        // Verify that it is not possible to migrate the activation (it is removed)
        ObjectStepLogger stepLoggerMig = new ObjectStepLogger(System.out);
        new StartUpgradeStep().execute(stepLoggerMig, model1.toMap());
        assertFalse(stepLoggerMig.getResult().isSuccess());
        assertEquals(400, stepLoggerMig.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLoggerMig.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_UPGRADE", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_UPGRADE_FAILED", errorResponse.getResponseObject().getMessage());
    }

    @Test
    public void upgradeActivationBlockedTest() throws Exception {
        // Shared resultStatus object
        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV2());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Verify activation status
        GetActivationStatusResponse statusResponseCreated = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponseCreated.getActivationStatus());

        // Prepare activation model
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationName("upgrade test");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(resultStatusObject);
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("3.1");

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new io.getlime.security.powerauth.lib.cmd.steps.v2.PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Prepare start upgrade model
        StartUpgradeStepModel model1 = new StartUpgradeStepModel();
        model1.setApplicationKey(config.getApplicationKey());
        model1.setApplicationSecret(config.getApplicationSecret());
        model1.setStatusFileName(tempStatusFile.getAbsolutePath());
        model1.setHeaders(new HashMap<>());
        model1.setResultStatusObject(resultStatusObject);
        model1.setUriString(config.getPowerAuthIntegrationUrl());
        model1.setVersion("3.1");

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Block activation
        powerAuthClient.blockActivation(initResponse.getActivationId(), "test", "test");

        // Verify that it is not possible to migrate the activation (it is blocked)
        ObjectStepLogger stepLoggerMig = new ObjectStepLogger(System.out);
        new StartUpgradeStep().execute(stepLoggerMig, model1.toMap());
        assertFalse(stepLoggerMig.getResult().isSuccess());
        assertEquals(400, stepLoggerMig.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLoggerMig.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_UPGRADE", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_UPGRADE_FAILED", errorResponse.getResponseObject().getMessage());

        // Unlock activation
        powerAuthClient.unblockActivation(initResponse.getActivationId(), "test");

        // Start upgrade of activation to version 3.1
        ObjectStepLogger stepLogger3 = new ObjectStepLogger(System.out);
        new StartUpgradeStep().execute(stepLogger3, model1.toMap());
        assertTrue(stepLogger3.getResult().isSuccess());
        assertEquals(200, stepLogger3.getResponse().getStatusCode());

        // Prepare commit upgrade model
        CommitUpgradeStepModel model2 = new CommitUpgradeStepModel();
        model2.setApplicationKey(config.getApplicationKey());
        model2.setApplicationSecret(config.getApplicationSecret());
        model2.setStatusFileName(tempStatusFile.getAbsolutePath());
        model2.setHeaders(new HashMap<>());
        model2.setResultStatusObject(resultStatusObject);
        model2.setUriString(config.getPowerAuthIntegrationUrl());
        model2.setVersion("3.1");

        // Commit upgrade of activation to version 3.1
        ObjectStepLogger stepLogger4 = new ObjectStepLogger(System.out);
        new CommitUpgradeStep().execute(stepLogger4, model2.toMap());
        assertTrue(stepLogger4.getResult().isSuccess());
        assertEquals(200, stepLogger4.getResponse().getStatusCode());

        // Verify activation status and version
        GetActivationStatusResponse statusResponseMigrated = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, statusResponseMigrated.getActivationStatus());
        assertEquals(3, statusResponseMigrated.getVersion());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    public void upgradeActivationNotCommittedTest() throws Exception {
        // Shared resultStatus object
        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV2());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Verify activation status
        GetActivationStatusResponse statusResponseCreated = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponseCreated.getActivationStatus());

        // Prepare activation model
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationName("upgrade test");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(resultStatusObject);
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("3.1");

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Prepare start upgrade model
        StartUpgradeStepModel model1 = new StartUpgradeStepModel();
        model1.setApplicationKey(config.getApplicationKey());
        model1.setApplicationSecret(config.getApplicationSecret());
        model1.setStatusFileName(tempStatusFile.getAbsolutePath());
        model1.setHeaders(new HashMap<>());
        model1.setResultStatusObject(resultStatusObject);
        model1.setUriString(config.getPowerAuthIntegrationUrl());
        model1.setVersion("3.1");

        // Verify that it is not possible to migrate the activation (it is not committed yet)
        ObjectStepLogger stepLoggerMig = new ObjectStepLogger(System.out);
        new StartUpgradeStep().execute(stepLoggerMig, model1.toMap());
        assertFalse(stepLoggerMig.getResult().isSuccess());
        assertEquals(400, stepLoggerMig.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLoggerMig.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_UPGRADE", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_UPGRADE_FAILED", errorResponse.getResponseObject().getMessage());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    public void upgradeDoubleCommitFailTest() throws Exception {
        // Shared resultStatus object
        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV2());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Verify activation status
        GetActivationStatusResponse statusResponseCreated = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.CREATED, statusResponseCreated.getActivationStatus());

        // Prepare activation model
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationName("upgrade test");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(resultStatusObject);
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("2.1");

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new io.getlime.security.powerauth.lib.cmd.steps.v2.PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Prepare signature model
        VerifySignatureStepModel modelSig = new VerifySignatureStepModel();
        modelSig.setApplicationKey(config.getApplicationKey());
        modelSig.setApplicationSecret(config.getApplicationSecret());
        modelSig.setDataFileName(dataFile.getAbsolutePath());
        modelSig.setHeaders(new HashMap<>());
        modelSig.setHttpMethod("POST");
        modelSig.setPassword(config.getPassword());
        modelSig.setResourceId("/pa/signature/validate");
        modelSig.setResultStatusObject(resultStatusObject);
        modelSig.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        modelSig.setStatusFileName(tempStatusFile.getAbsolutePath());
        modelSig.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/signature/validate");
        modelSig.setVersion("2.1");

        // Prepare start upgrade model
        StartUpgradeStepModel model1 = new StartUpgradeStepModel();
        model1.setApplicationKey(config.getApplicationKey());
        model1.setApplicationSecret(config.getApplicationSecret());
        model1.setStatusFileName(tempStatusFile.getAbsolutePath());
        model1.setHeaders(new HashMap<>());
        model1.setResultStatusObject(resultStatusObject);
        model1.setUriString(config.getPowerAuthIntegrationUrl());
        model1.setVersion("3.1");

        // Start upgrade of activation to version 3.1
        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new StartUpgradeStep().execute(stepLogger1, model1.toMap());
        assertTrue(stepLogger1.getResult().isSuccess());
        assertEquals(200, stepLogger1.getResponse().getStatusCode());

        // Prepare commit upgrade model
        CommitUpgradeStepModel model2 = new CommitUpgradeStepModel();
        model2.setApplicationKey(config.getApplicationKey());
        model2.setApplicationSecret(config.getApplicationSecret());
        model2.setStatusFileName(tempStatusFile.getAbsolutePath());
        model2.setHeaders(new HashMap<>());
        model2.setResultStatusObject(resultStatusObject);
        model2.setUriString(config.getPowerAuthIntegrationUrl());
        model2.setVersion("3.1");

        // Commit upgrade of activation to version 3.1 (first time - success)
        ObjectStepLogger stepLogger2 = new ObjectStepLogger(System.out);
        new CommitUpgradeStep().execute(stepLogger2, model2.toMap());
        assertTrue(stepLogger2.getResult().isSuccess());
        assertEquals(200, stepLogger2.getResponse().getStatusCode());

        // Commit upgrade of activation to version 3.1 (second time - fail, upgrade to version 3.1 is already committed)
        ObjectStepLogger stepLogger3 = new ObjectStepLogger(System.out);
        new CommitUpgradeStep().execute(stepLogger3, model2.toMap());
        assertFalse(stepLogger3.getResult().isSuccess());
        assertEquals(400, stepLogger3.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger3.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_UPGRADE", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_UPGRADE_FAILED", errorResponse.getResponseObject().getMessage());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    public void upgradeInvalidCommitSignatureTest() throws Exception {
        // Shared resultStatus object
        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV2());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation model
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationName("upgrade test");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(resultStatusObject);
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("2.1");

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new io.getlime.security.powerauth.lib.cmd.steps.v2.PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Prepare start upgrade model
        StartUpgradeStepModel model1 = new StartUpgradeStepModel();
        model1.setApplicationKey(config.getApplicationKey());
        model1.setApplicationSecret(config.getApplicationSecret());
        model1.setStatusFileName(tempStatusFile.getAbsolutePath());
        model1.setHeaders(new HashMap<>());
        model1.setResultStatusObject(resultStatusObject);
        model1.setUriString(config.getPowerAuthIntegrationUrl());
        model1.setVersion("3.1");

        // Start upgrade of activation to version 3.1
        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new StartUpgradeStep().execute(stepLogger1, model1.toMap());
        assertTrue(stepLogger1.getResult().isSuccess());
        assertEquals(200, stepLogger1.getResponse().getStatusCode());

        // Prepare commit upgrade model
        CommitUpgradeStepModel model2 = new CommitUpgradeStepModel();
        model2.setApplicationKey(config.getApplicationKey());
        model2.setApplicationSecret(config.getApplicationSecret());
        model2.setStatusFileName(tempStatusFile.getAbsolutePath());
        model2.setHeaders(new HashMap<>());
        model2.setResultStatusObject(resultStatusObject);
        model2.setUriString(config.getPowerAuthIntegrationUrl());
        model2.setVersion("3.1");

        // Save possession key
        String signaturePossessionKeyOrig = (String) model.getResultStatusObject().get("signaturePossessionKey");
        // Set biometry key as possession key
        model.getResultStatusObject().put("signaturePossessionKey", model.getResultStatusObject().get("signatureBiometryKey"));

        // Commit upgrade of activation to version 3.1 should fail
        ObjectStepLogger stepLogger2 = new ObjectStepLogger(System.out);
        new CommitUpgradeStep().execute(stepLogger2, model2.toMap());
        assertFalse(stepLogger2.getResult().isSuccess());
        assertEquals(401, stepLogger2.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger2.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);

        // Revert possession key change
        model.getResultStatusObject().put("signaturePossessionKey", signaturePossessionKeyOrig);

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    public void upgradeStartSameCtrDataTest() throws Exception {
        // Shared resultStatus object
        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV2());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation model
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationName("upgrade test");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(resultStatusObject);
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("2.1");

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new io.getlime.security.powerauth.lib.cmd.steps.v2.PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Prepare start upgrade model
        StartUpgradeStepModel model1 = new StartUpgradeStepModel();
        model1.setApplicationKey(config.getApplicationKey());
        model1.setApplicationSecret(config.getApplicationSecret());
        model1.setStatusFileName(tempStatusFile.getAbsolutePath());
        model1.setHeaders(new HashMap<>());
        model1.setResultStatusObject(resultStatusObject);
        model1.setUriString(config.getPowerAuthIntegrationUrl());
        model1.setVersion("3.1");

        // Start upgrade of activation to version 3.1
        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new StartUpgradeStep().execute(stepLogger1, model1.toMap());
        assertTrue(stepLogger1.getResult().isSuccess());
        assertEquals(200, stepLogger1.getResponse().getStatusCode());

        // Extract ctr_data
        byte[] ctrData = CounterUtil.getCtrData(model1, stepLogger1);

        // Start upgrade of activation to version 3.1 again
        ObjectStepLogger stepLogger2 = new ObjectStepLogger(System.out);
        new StartUpgradeStep().execute(stepLogger2, model1.toMap());
        assertTrue(stepLogger2.getResult().isSuccess());
        assertEquals(200, stepLogger2.getResponse().getStatusCode());

        // Extract ctr_data
        byte[] ctrData2 = CounterUtil.getCtrData(model1, stepLogger1);

        // Compare ctr_data - it needs to be the same to prevent replay attacks
        assertArrayEquals(ctrData, ctrData2);

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    public void upgradeSignatureVerificationDuringUpgradeTest() throws Exception {
        // Shared resultStatus object
        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV2());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation model
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationName("upgrade test");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(resultStatusObject);
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("2.1");

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new io.getlime.security.powerauth.lib.cmd.steps.v2.PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Check counter values
        long counter0 = (long) model.getResultStatusObject().get("counter");
        String ctrData0 = (String) model.getResultStatusObject().get("ctrData");
        assertEquals(0, counter0);
        assertNull(ctrData0);

        // Prepare start upgrade model
        StartUpgradeStepModel model1 = new StartUpgradeStepModel();
        model1.setApplicationKey(config.getApplicationKey());
        model1.setApplicationSecret(config.getApplicationSecret());
        model1.setStatusFileName(tempStatusFile.getAbsolutePath());
        model1.setHeaders(new HashMap<>());
        model1.setResultStatusObject(resultStatusObject);
        model1.setUriString(config.getPowerAuthIntegrationUrl());
        model1.setVersion("3.1");

        // Start upgrade of activation to version 3.1
        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new StartUpgradeStep().execute(stepLogger1, model1.toMap());
        assertTrue(stepLogger1.getResult().isSuccess());
        assertEquals(200, stepLogger1.getResponse().getStatusCode());

        // Check counter values
        long counter1 = (long) model.getResultStatusObject().get("counter");
        String ctrData1 = (String) model.getResultStatusObject().get("ctrData");
        assertEquals(0, counter1);
        assertNotNull(ctrData1);

        // Prepare signature model
        VerifySignatureStepModel modelSig = new VerifySignatureStepModel();
        modelSig.setApplicationKey(config.getApplicationKey());
        modelSig.setApplicationSecret(config.getApplicationSecret());
        modelSig.setDataFileName(dataFile.getAbsolutePath());
        modelSig.setHeaders(new HashMap<>());
        modelSig.setHttpMethod("POST");
        modelSig.setPassword(config.getPassword());
        modelSig.setResourceId("/pa/signature/validate");
        modelSig.setResultStatusObject(resultStatusObject);
        modelSig.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        modelSig.setStatusFileName(tempStatusFile.getAbsolutePath());
        modelSig.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/signature/validate");
        modelSig.setVersion("2.1");

        // Verify version signature - version 2.1 signatures should still work during upgrade
        ObjectStepLogger stepLoggerSig1 = new ObjectStepLogger(System.out);
        new VerifySignatureStep().execute(stepLoggerSig1, modelSig.toMap());
        assertTrue(stepLoggerSig1.getResult().isSuccess());
        assertEquals(200, stepLoggerSig1.getResponse().getStatusCode());

        // Check counter values
        long counter2 = (long) model.getResultStatusObject().get("counter");
        String ctrData2 = (String) model.getResultStatusObject().get("ctrData");
        assertEquals(1, counter2);
        assertEquals(ctrData1, ctrData2);

        // Prepare commit upgrade model
        CommitUpgradeStepModel model2 = new CommitUpgradeStepModel();
        model2.setApplicationKey(config.getApplicationKey());
        model2.setApplicationSecret(config.getApplicationSecret());
        model2.setStatusFileName(tempStatusFile.getAbsolutePath());
        model2.setHeaders(new HashMap<>());
        model2.setResultStatusObject(resultStatusObject);
        model2.setUriString(config.getPowerAuthIntegrationUrl());
        model2.setVersion("3.1");

        // Commit upgrade of activation to version 3.1
        ObjectStepLogger stepLogger2 = new ObjectStepLogger(System.out);
        new CommitUpgradeStep().execute(stepLogger2, model2.toMap());
        assertTrue(stepLogger2.getResult().isSuccess());
        assertEquals(200, stepLogger2.getResponse().getStatusCode());

        // Check counter values
        long counter3 = (long) model.getResultStatusObject().get("counter");
        String ctrData3 = (String) model.getResultStatusObject().get("ctrData");
        assertEquals(2, counter3);
        assertArrayEquals(new HashBasedCounter().next(BaseEncoding.base64().decode(ctrData2)), BaseEncoding.base64().decode(ctrData3));

        // Verify version 3.1 signature
        modelSig.setVersion("3.1");
        modelSig.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate");
        ObjectStepLogger stepLoggerSig2 = new ObjectStepLogger(System.out);
        new VerifySignatureStep().execute(stepLoggerSig2, modelSig.toMap());
        assertTrue(stepLoggerSig2.getResult().isSuccess());
        assertEquals(200, stepLoggerSig1.getResponse().getStatusCode());

        // Check counter values
        long counter4 = (long) model.getResultStatusObject().get("counter");
        String ctrData4 = (String) model.getResultStatusObject().get("ctrData");
        assertEquals(3, counter4);
        assertArrayEquals(new HashBasedCounter().next(BaseEncoding.base64().decode(ctrData3)), BaseEncoding.base64().decode(ctrData4));

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    public void upgradeConcurrencyTest() throws Exception {
        // Shared resultStatus object
        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV2());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation model
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationName("upgrade test");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(resultStatusObject);
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("2.1");

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new io.getlime.security.powerauth.lib.cmd.steps.v2.PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Prepare start upgrade model
        StartUpgradeStepModel model1 = new StartUpgradeStepModel();
        model1.setApplicationKey(config.getApplicationKey());
        model1.setApplicationSecret(config.getApplicationSecret());
        model1.setStatusFileName(tempStatusFile.getAbsolutePath());
        model1.setHeaders(new HashMap<>());
        model1.setResultStatusObject(resultStatusObject);
        model1.setUriString(config.getPowerAuthIntegrationUrl());
        model1.setVersion("3.1");

        // Prepare Runnable for upgrade of activation to version 3.1
        Set<String> allCtrData = Collections.synchronizedSet(new HashSet<>());
        Runnable startUpgradeRunnable = () -> {
            try {
                ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
                new StartUpgradeStep().execute(stepLogger1, model1.toMap());
                assertTrue(stepLogger1.getResult().isSuccess());
                assertEquals(200, stepLogger1.getResponse().getStatusCode());
                byte[] ctrData = CounterUtil.getCtrData(model1, stepLogger1);
                allCtrData.add(BaseEncoding.base64().encode(ctrData));
            } catch (Exception e) {
                Assert.fail();
            }
        };

        // Start 10 upgrade threads
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            Thread t = new Thread(startUpgradeRunnable);
            threads.add(t);
            t.start();
        }

        // Wait for 10 upgrade threads to complete
        for (int i = 0; i < 10; i++) {
            threads.get(i).join();
        }

        // Make sure only 1 distinct ctr_data is present
        assertEquals(1, allCtrData.size());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    private void checkSignatureError(ErrorResponse errorResponse) {
        // Errors differ when Web Flow is used because of its Exception handler
        assertTrue("POWERAUTH_AUTH_FAIL".equals(errorResponse.getResponseObject().getCode()) || "ERR_AUTHENTICATION".equals(errorResponse.getResponseObject().getCode()));
        assertTrue("Signature validation failed".equals(errorResponse.getResponseObject().getMessage()) || "POWER_AUTH_SIGNATURE_INVALID_VALUE".equals(errorResponse.getResponseObject().getMessage()));
    }

}
