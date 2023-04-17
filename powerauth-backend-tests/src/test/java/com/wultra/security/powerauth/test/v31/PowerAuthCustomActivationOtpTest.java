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
package com.wultra.security.powerauth.test.v31;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.v3.*;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.provider.CustomActivationProviderForTests;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.ActivationRecoveryStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.ActivationRecoveryStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.CreateActivationStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.GetStatusStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationRecovery;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnableConfigurationProperties
@ComponentScan(basePackages = {"com.wultra.security.powerauth", "io.getlime.security.powerauth"})
class PowerAuthCustomActivationOtpTest {

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private CreateActivationStepModel createModel;
    private ActivationRecoveryStepModel recoveryModel;
    private GetStatusStepModel statusModel;

    private static File dataFile;
    private File tempStatusFile;
    private ObjectStepLogger stepLogger;

    private final String validOtpValue = "1234-5678";
    private final String invalidOtpValue = "8765-4321";

    @LocalServerPort
    private int port;

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
        // Create temp status files
        tempStatusFile = File.createTempFile("pa_status_v31", ".json");

        // Models shared among tests
        createModel = new CreateActivationStepModel();
        createModel.setActivationName("test v3.1");
        createModel.setApplicationKey(config.getApplicationKey());
        createModel.setApplicationSecret(config.getApplicationSecret());
        createModel.setMasterPublicKey(config.getMasterPublicKey());
        createModel.setHeaders(new HashMap<>());
        createModel.setPassword(config.getPassword());
        createModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        createModel.setResultStatusObject(config.getResultStatusObjectV31());
        createModel.setUriString("http://localhost:" + port);
        createModel.setVersion("3.1");
        createModel.setDeviceInfo("backend-tests");

        recoveryModel = new ActivationRecoveryStepModel();
        recoveryModel.setActivationName("test v3.1");
        recoveryModel.setApplicationKey(config.getApplicationKey());
        recoveryModel.setApplicationSecret(config.getApplicationSecret());
        recoveryModel.setMasterPublicKey(config.getMasterPublicKey());
        recoveryModel.setHeaders(new HashMap<>());
        recoveryModel.setPassword(config.getPassword());
        recoveryModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        recoveryModel.setResultStatusObject(config.getResultStatusObjectV31());
        recoveryModel.setUriString("http://localhost:" + port);
        recoveryModel.setVersion("3.1");
        recoveryModel.setDeviceInfo("backend-tests");

        statusModel = new GetStatusStepModel();
        statusModel.setHeaders(new HashMap<>());
        statusModel.setResultStatusObject(config.getResultStatusObjectV31());
        statusModel.setUriString(config.getPowerAuthIntegrationUrl());
        statusModel.setVersion("3.1");

        // Prepare step logger
        stepLogger = new ObjectStepLogger(System.out);
    }

    @AfterEach
    void tearDown() {
        assertTrue(tempStatusFile.delete());
    }

    /**
     * Helper function creates a temporary activation just to extract an activation recovery data.
     *
     * @return Object containing recovery code and recovery puk.
     * @throws Exception In case of failure.
     */
    private ActivationRecovery getRecoveryData() throws Exception {

        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV31());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation, assume recovery is enabled on server
        PrepareActivationStepModel prepareModel = new PrepareActivationStepModel();

        prepareModel.setActivationName("test_recovery_v31");
        prepareModel.setApplicationKey(config.getApplicationKey());
        prepareModel.setApplicationSecret(config.getApplicationSecret());
        prepareModel.setMasterPublicKey(config.getMasterPublicKey());
        prepareModel.setHeaders(new HashMap<>());
        prepareModel.setPassword(config.getPassword());
        prepareModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        prepareModel.setResultStatusObject(resultStatusObject);
        prepareModel.setUriString(config.getPowerAuthIntegrationUrl());
        prepareModel.setVersion("3.1");
        prepareModel.setActivationCode(initResponse.getActivationCode());
        prepareModel.setDeviceInfo("backend-tests");

        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, prepareModel.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify decrypted activationId
        String activationId = null;
        ActivationRecovery activationRecovery = null;
        for (StepItem item: stepLoggerPrepare.getItems()) {
            if (item.getName().equals("Activation Done")) {
                Map<String, Object> responseMap = (Map<String, Object>) item.getObject();
                activationId = (String) responseMap.get("activationId");
                break;
            }
            if (item.getName().equals("Decrypted Layer 2 Response")) {
                activationRecovery = ((ActivationLayer2Response)item.getObject()).getActivationRecovery();
            }
        }

        // Verify extracted data
        assertEquals(initResponse.getActivationId(), activationId);
        assertNotNull(activationId);
        assertNotNull(activationRecovery);
        assertNotNull(activationRecovery.getRecoveryCode());
        assertNotNull(activationRecovery.getPuk());

        // Commit activation
        powerAuthClient.commitActivation(activationId, null);

        // Remove this activation
        powerAuthClient.removeActivation(activationId, null);

        return activationRecovery;
    }

    @Test
    void customActivationOtpValidTest() throws Exception {

        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_2_STATIC_NOCOMMIT_NOPROCESS");

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("key", "value");

        createModel.setIdentityAttributes(identityAttributes);
        createModel.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, createModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        String activationId = null;
        boolean layer2ResponseOk = false;
        boolean layer1ResponseOk = false;
        // Verify decrypted responses
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Layer 2 Response")) {
                ActivationLayer2Response layer2Response = (ActivationLayer2Response) item.getObject();
                activationId = layer2Response.getActivationId();
                assertNotNull(activationId);
                assertNotNull(layer2Response.getCtrData());
                assertNotNull(layer2Response.getServerPublicKey());
                // Verify activation status - activation was not automatically committed
                GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(activationId);
                assertEquals(ActivationStatus.PENDING_COMMIT, statusResponseActive.getActivationStatus());
                assertEquals("static_username", statusResponseActive.getUserId());
                layer2ResponseOk = true;
                continue;
            }
            if (item.getName().equals("Decrypted Layer 1 Response")) {
                ActivationLayer1Response layer1Response = (ActivationLayer1Response) item.getObject();
                // Verify custom attributes, there should be no change
                assertEquals("value", layer1Response.getCustomAttributes().get("key"));
                layer1ResponseOk = true;
            }
        }

        assertTrue(layer1ResponseOk);
        assertTrue(layer2ResponseOk);

        // Now update activation OTP for the pending activation
        powerAuthClient.updateActivationOtp(activationId, null, validOtpValue);

        // Try commit activation with wrong OTP, but the very last attempt is valid.
        final int maxIterations = CustomActivationProviderForTests.MAX_FAILED_ATTEMPTS;
        for (int iteration = 1; iteration <= maxIterations; iteration++) {
            boolean lastIteration = iteration == maxIterations;
            boolean isActivated;
            try {
                CommitActivationRequest commitRequest = new CommitActivationRequest();
                commitRequest.setActivationId(activationId);
                commitRequest.setActivationOtp(lastIteration ? validOtpValue : invalidOtpValue);
                CommitActivationResponse commitResponse = powerAuthClient.commitActivation(commitRequest);
                isActivated = commitResponse.isActivated();
            } catch (Throwable t) {
                isActivated = false;
            }
            assertEquals(lastIteration, isActivated);

            // Verify activation status
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.ACTIVE : ActivationStatus.PENDING_COMMIT;
            GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(activationId);
            assertEquals(expectedActivationStatus, activationStatusResponse.getActivationStatus());
        }

        // Try to get activation status via RESTful API
        ObjectStepLogger stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().isSuccess());
        assertEquals(200, stepLoggerStatus.getResponse().getStatusCode());

        // Validate failed attempts counter.
        Map<String, Object> statusResponseMap = (Map<String, Object>) stepLoggerStatus.getFirstItem("activation-status-obtained").getObject();
        ActivationStatusBlobInfo statusBlobInfo = (ActivationStatusBlobInfo) statusResponseMap.get("statusBlob");
        assertEquals(0L, statusBlobInfo.getFailedAttempts());

        // Remove activation
        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void customActivationOtpInvalidTest() throws Exception {

        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_2_STATIC_NOCOMMIT_NOPROCESS");

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("key", "value");

        createModel.setIdentityAttributes(identityAttributes);
        createModel.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, createModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        String activationId = null;
        boolean layer2ResponseOk = false;
        boolean layer1ResponseOk = false;
        // Verify decrypted responses
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Layer 2 Response")) {
                ActivationLayer2Response layer2Response = (ActivationLayer2Response) item.getObject();
                activationId = layer2Response.getActivationId();
                assertNotNull(activationId);
                assertNotNull(layer2Response.getCtrData());
                assertNotNull(layer2Response.getServerPublicKey());
                // Verify activation status - activation was not automatically committed
                GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(activationId);
                assertEquals(ActivationStatus.PENDING_COMMIT, statusResponseActive.getActivationStatus());
                assertEquals("static_username", statusResponseActive.getUserId());
                layer2ResponseOk = true;
                continue;
            }
            if (item.getName().equals("Decrypted Layer 1 Response")) {
                ActivationLayer1Response layer1Response = (ActivationLayer1Response) item.getObject();
                // Verify custom attributes, there should be no change
                assertEquals("value", layer1Response.getCustomAttributes().get("key"));
                layer1ResponseOk = true;
            }
        }

        assertTrue(layer1ResponseOk);
        assertTrue(layer2ResponseOk);

        // Now update activation OTP for the pending activation
        powerAuthClient.updateActivationOtp(activationId, null, validOtpValue);

        // Try commit activation with wrong OTP
        final int maxIterations = CustomActivationProviderForTests.MAX_FAILED_ATTEMPTS;
        for (int iteration = 1; iteration <= maxIterations; iteration++) {
            boolean lastIteration = iteration == maxIterations;
            boolean isActivated;
            try {
                CommitActivationRequest commitRequest = new CommitActivationRequest();
                commitRequest.setActivationId(activationId);
                commitRequest.setActivationOtp(invalidOtpValue);
                CommitActivationResponse commitResponse = powerAuthClient.commitActivation(commitRequest);
                isActivated = commitResponse.isActivated();
            } catch (Throwable t) {
                isActivated = false;
            }
            assertFalse(isActivated);

            // Verify activation status
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.REMOVED : ActivationStatus.PENDING_COMMIT;
            GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(activationId);
            assertEquals(expectedActivationStatus, activationStatusResponse.getActivationStatus());
        }

        // Remove activation
        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void activationRecoveryOtpValidTest() throws Exception {

        ActivationRecovery activationRecovery = getRecoveryData();

        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("recoveryCode", activationRecovery.getRecoveryCode());
        identityAttributes.put("puk", activationRecovery.getPuk());

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("TEST_SHOULD_AUTOCOMMIT", "NO");

        recoveryModel.setIdentityAttributes(identityAttributes);
        recoveryModel.setCustomAttributes(customAttributes);

        ObjectStepLogger stepLoggerRecovery = new ObjectStepLogger(System.out);

        new ActivationRecoveryStep().execute(stepLoggerRecovery, recoveryModel.toMap());
        assertTrue(stepLoggerRecovery.getResult().isSuccess());
        assertEquals(200, stepLoggerRecovery.getResponse().getStatusCode());

        // Extract activation ID
        String activationId = null;
        ActivationRecovery activationRecoveryNew = null;
        for (StepItem item: stepLoggerRecovery.getItems()) {
            if (item.getName().equals("Activation Done")) {
                Map<String, Object> responseMap = (Map<String, Object>) item.getObject();
                activationId = (String) responseMap.get("activationId");
                break;
            }
        }

        // Now update activation OTP for the pending activation
        powerAuthClient.updateActivationOtp(activationId, null, validOtpValue);

        // Try commit activation with wrong OTP, but the very last attempt is valid.
        final int maxIterations = CustomActivationProviderForTests.MAX_FAILED_ATTEMPTS;
        for (int iteration = 1; iteration <= maxIterations; iteration++) {
            boolean lastIteration = iteration == maxIterations;
            boolean isActivated;
            try {
                CommitActivationRequest commitRequest = new CommitActivationRequest();
                commitRequest.setActivationId(activationId);
                commitRequest.setActivationOtp(lastIteration ? validOtpValue : invalidOtpValue);
                CommitActivationResponse commitResponse = powerAuthClient.commitActivation(commitRequest);
                isActivated = commitResponse.isActivated();
            } catch (Throwable t) {
                isActivated = false;
            }
            assertEquals(lastIteration, isActivated);

            // Verify activation status
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.ACTIVE : ActivationStatus.PENDING_COMMIT;
            GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(activationId);
            assertEquals(expectedActivationStatus, activationStatusResponse.getActivationStatus());
        }

        // Try to get activation status via RESTful API
        ObjectStepLogger stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().isSuccess());
        assertEquals(200, stepLoggerStatus.getResponse().getStatusCode());

        // Validate failed attempts counter.
        Map<String, Object> statusResponseMap = (Map<String, Object>) stepLoggerStatus.getFirstItem("activation-status-obtained").getObject();
        ActivationStatusBlobInfo statusBlobInfo = (ActivationStatusBlobInfo) statusResponseMap.get("statusBlob");
        assertEquals(0L, statusBlobInfo.getFailedAttempts());

        // Remove activation
        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void activationRecoveryOtpInvalidTest() throws Exception {

        ActivationRecovery activationRecovery = getRecoveryData();

        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("recoveryCode", activationRecovery.getRecoveryCode());
        identityAttributes.put("puk", activationRecovery.getPuk());

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("TEST_SHOULD_AUTOCOMMIT", "NO");

        recoveryModel.setIdentityAttributes(identityAttributes);
        recoveryModel.setCustomAttributes(customAttributes);

        ObjectStepLogger stepLoggerRecovery = new ObjectStepLogger(System.out);

        new ActivationRecoveryStep().execute(stepLoggerRecovery, recoveryModel.toMap());
        assertTrue(stepLoggerRecovery.getResult().isSuccess());
        assertEquals(200, stepLoggerRecovery.getResponse().getStatusCode());

        // Extract activation ID
        String activationId = null;
        ActivationRecovery activationRecoveryNew = null;
        for (StepItem item: stepLoggerRecovery.getItems()) {
            if (item.getName().equals("Activation Done")) {
                Map<String, Object> responseMap = (Map<String, Object>) item.getObject();
                activationId = (String) responseMap.get("activationId");
                break;
            }
        }

        // Now update activation OTP for the pending activation
        powerAuthClient.updateActivationOtp(activationId, null, validOtpValue);

        // Try commit activation with wrong OTP, but the very last attempt is valid.
        final int maxIterations = CustomActivationProviderForTests.MAX_FAILED_ATTEMPTS;
        for (int iteration = 1; iteration <= maxIterations; iteration++) {
            boolean lastIteration = iteration == maxIterations;
            boolean isActivated;
            try {
                CommitActivationRequest commitRequest = new CommitActivationRequest();
                commitRequest.setActivationId(activationId);
                commitRequest.setActivationOtp(invalidOtpValue);
                CommitActivationResponse commitResponse = powerAuthClient.commitActivation(commitRequest);
                isActivated = commitResponse.isActivated();
            } catch (Throwable t) {
                isActivated = false;
            }
            assertFalse(isActivated);

            // Verify activation status
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.REMOVED : ActivationStatus.PENDING_COMMIT;
            GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(activationId);
            assertEquals(expectedActivationStatus, activationStatusResponse.getActivationStatus());
        }
    }

}
