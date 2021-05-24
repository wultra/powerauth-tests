/*
 * PowerAuth test and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.v3.*;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.GetStatusStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthActivationOtpTest {

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private PrepareActivationStepModel model;
    private GetStatusStepModel statusModel;
    private File tempStatusFile;

    private final String validOtpValue = "1234-5678";
    private final String invalidOtpValue = "8765-4321";

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
    public void setUp() throws IOException {
        // Create temp status file
        tempStatusFile = File.createTempFile("pa_status_v31", ".json");

        // Models shared among tests
        model = new PrepareActivationStepModel();
        model.setActivationName("test v31");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(config.getResultStatusObjectV31());
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("3.1");
        model.setDeviceInfo("backend-tests");

        statusModel = new GetStatusStepModel();
        statusModel.setHeaders(new HashMap<>());
        statusModel.setResultStatusObject(config.getResultStatusObjectV31());
        statusModel.setUriString(config.getPowerAuthIntegrationUrl());
        statusModel.setVersion("3.1");
    }

    @AfterEach
    public void tearDown() {
        assertTrue(tempStatusFile.delete());
    }

    @Test
    public void validOtpOnKeysExchangeTest() throws Exception {

        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV31());
        initRequest.setMaxFailureCount(5L);
        initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_KEY_EXCHANGE);
        initRequest.setActivationOtp(validOtpValue);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setResultStatusObject(resultStatusObject);
        model.setAdditionalActivationOtp(validOtpValue);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify activation status
        GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertNotNull(activationStatusResponse);
        assertEquals(ActivationStatus.ACTIVE, activationStatusResponse.getActivationStatus());

        // Verify associated recovery code
        LookupRecoveryCodesResponse recoveryCodes = powerAuthClient.lookupRecoveryCodes(config.getUserV31(), initResponse.getActivationId(), config.getApplicationId(), null, null);
        assertEquals(1, recoveryCodes.getRecoveryCodes().size());
        assertEquals(RecoveryCodeStatus.ACTIVE, recoveryCodes.getRecoveryCodes().get(0).getStatus());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    public void invalidOtpOnKeysExchangeTest() throws Exception {

        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV31());
        initRequest.setMaxFailureCount(5L);
        initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_KEY_EXCHANGE);
        initRequest.setActivationOtp(validOtpValue);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        for (int iteration = 1; iteration <= 5; iteration++) {
            final boolean lastIteration = iteration == 5;
            // Prepare activation
            model.setActivationCode(initResponse.getActivationCode());
            model.setResultStatusObject(resultStatusObject);
            model.setAdditionalActivationOtp(invalidOtpValue);
            ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
            new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
            assertFalse(stepLoggerPrepare.getResult().isSuccess());
            assertEquals(400, stepLoggerPrepare.getResponse().getStatusCode());

            // Verify activation status
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.REMOVED : ActivationStatus.CREATED;
            GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
            assertNotNull(activationStatusResponse);
            assertEquals(expectedActivationStatus, activationStatusResponse.getActivationStatus());
        }
    }

    @Test
    public void validOtpOnCommitTest() throws Exception {

        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV31());
        initRequest.setMaxFailureCount(5L);
        initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_COMMIT);
        initRequest.setActivationOtp(validOtpValue);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setResultStatusObject(resultStatusObject);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify activation status
        GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertNotNull(activationStatusResponse);
        assertEquals(ActivationStatus.PENDING_COMMIT, activationStatusResponse.getActivationStatus());

        // Try commit activation with wrong OTP. Last attempt is valid.
        for (int iteration = 1; iteration <= 5; iteration++) {
            boolean lastIteration = iteration == 5;
            CommitActivationRequest commitRequest = new CommitActivationRequest();
            commitRequest.setActivationId(initResponse.getActivationId());
            commitRequest.setActivationOtp(lastIteration ? validOtpValue : invalidOtpValue);

            boolean isActivated;
            try {
                CommitActivationResponse commitResponse = powerAuthClient.commitActivation(commitRequest);
                isActivated = commitResponse.isActivated();
            } catch (Throwable t) {
                isActivated = false;
            }
            assertEquals(lastIteration, isActivated);

            // Verify activation status
            activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
            assertEquals(lastIteration ? ActivationStatus.ACTIVE : ActivationStatus.PENDING_COMMIT, activationStatusResponse.getActivationStatus());
        }

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }


    @Test
    public void invalidOtpOnCommitTest() throws Exception {

        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV31());
        initRequest.setMaxFailureCount(5L);
        initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_COMMIT);
        initRequest.setActivationOtp(validOtpValue);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setResultStatusObject(resultStatusObject);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify activation status
        GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertNotNull(activationStatusResponse);
        assertEquals(ActivationStatus.PENDING_COMMIT, activationStatusResponse.getActivationStatus());

        // Try commit activation with wrong OTP. Last attempt is valid.
        for (int iteration = 1; iteration <= 5; iteration++) {
            boolean lastIteration = iteration == 5;
            CommitActivationRequest commitRequest = new CommitActivationRequest();
            commitRequest.setActivationId(initResponse.getActivationId());
            commitRequest.setActivationOtp(invalidOtpValue);

            boolean isActivated;
            try {
                CommitActivationResponse commitResponse = powerAuthClient.commitActivation(commitRequest);
                isActivated = commitResponse.isActivated();
            } catch (Throwable t) {
                isActivated = false;
            }
            assertFalse(isActivated);

            // Verify activation status
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.REMOVED : ActivationStatus.PENDING_COMMIT;
            activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
            assertEquals(expectedActivationStatus, activationStatusResponse.getActivationStatus());
        }
    }

    @Test
    public void updateValidOtpOnCommitTest() throws Exception {

        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV31());
        initRequest.setMaxFailureCount(5L);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setResultStatusObject(resultStatusObject);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify activation status
        GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.PENDING_COMMIT, activationStatusResponse.getActivationStatus());

        // Update OTP
        powerAuthClient.updateActivationOtp(initResponse.getActivationId(), null, validOtpValue);

        // Try commit activation with wrong OTP. Last attempt is valid.
        for (int iteration = 1; iteration <= 5; iteration++) {
            boolean lastIteration = iteration == 5;
            boolean isActivated;
            try {
                CommitActivationRequest commitRequest = new CommitActivationRequest();
                commitRequest.setActivationId(initResponse.getActivationId());
                commitRequest.setActivationOtp(lastIteration ? validOtpValue : invalidOtpValue);
                CommitActivationResponse commitResponse = powerAuthClient.commitActivation(commitRequest);
                isActivated = commitResponse.isActivated();
            } catch (Throwable t) {
                isActivated = false;
            }
            assertEquals(lastIteration, isActivated);

            // Verify activation status
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.ACTIVE : ActivationStatus.PENDING_COMMIT;
            activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
            assertEquals(expectedActivationStatus, activationStatusResponse.getActivationStatus());
        }

        // Try to get activation status via RESTful API
        ObjectStepLogger stepLoggerStatus = new ObjectStepLogger(System.out);
        statusModel.setResultStatusObject(resultStatusObject);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().isSuccess());
        assertEquals(200, stepLoggerStatus.getResponse().getStatusCode());

        // Validate failed and max failed attempts.
        Map<String, Object> statusResponseMap = (Map<String, Object>) stepLoggerStatus.getFirstItem("activation-status-obtained").getObject();
        ActivationStatusBlobInfo statusBlobInfo = (ActivationStatusBlobInfo) statusResponseMap.get("statusBlob");
        assertEquals(5L, statusBlobInfo.getMaxFailedAttempts());
        assertEquals(0L, statusBlobInfo.getFailedAttempts());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    public void updateInvalidOtpOnCommitTest() throws Exception {

        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV31());
        initRequest.setMaxFailureCount(5L);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setResultStatusObject(resultStatusObject);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify activation status
        GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.PENDING_COMMIT, activationStatusResponse.getActivationStatus());

        // Update OTP
        powerAuthClient.updateActivationOtp(initResponse.getActivationId(), null, validOtpValue);

        // Try commit activation with wrong OTP. Last attempt is valid.
        for (int iteration = 1; iteration <= 5; iteration++) {
            boolean lastIteration = iteration == 5;
            boolean isActivated;
            try {
                CommitActivationRequest commitRequest = new CommitActivationRequest();
                commitRequest.setActivationId(initResponse.getActivationId());
                commitRequest.setActivationOtp(invalidOtpValue);
                CommitActivationResponse commitResponse = powerAuthClient.commitActivation(commitRequest);
                isActivated = commitResponse.isActivated();
            } catch (Throwable t) {
                isActivated = false;
            }
            assertFalse(isActivated);

            // Verify activation status
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.REMOVED : ActivationStatus.PENDING_COMMIT;
            activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
            assertEquals(expectedActivationStatus, activationStatusResponse.getActivationStatus());
        }
    }

    @Test
    public void wrongActivationInitParamTest1() {
        assertThrows(PowerAuthClientException.class, () -> {
            // Init activation
            InitActivationRequest initRequest = new InitActivationRequest();
            initRequest.setApplicationId(config.getApplicationId());
            initRequest.setUserId(config.getUserV31());
            initRequest.setMaxFailureCount(5L);
            // Set ON_KEY_EXCHANGE but no OTP
            initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_KEY_EXCHANGE);
            powerAuthClient.initActivation(initRequest);
        });
    }

    @Test
    public void wrongActivationInitParamTest2() {
        assertThrows(PowerAuthClientException.class, () -> {
            // Init activation
            InitActivationRequest initRequest = new InitActivationRequest();
            initRequest.setApplicationId(config.getApplicationId());
            initRequest.setUserId(config.getUserV31());
            initRequest.setMaxFailureCount(5L);
            // Set ON_COMMIT but no OTP
            initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_COMMIT);
            powerAuthClient.initActivation(initRequest);
        });
    }

    @Test
    public void wrongActivationInitParamTest3() {
        assertThrows(PowerAuthClientException.class, () -> {
            // Init activation
            InitActivationRequest initRequest = new InitActivationRequest();
            initRequest.setApplicationId(config.getApplicationId());
            initRequest.setUserId(config.getUserV31());
            initRequest.setMaxFailureCount(5L);
            // Set OTP with no validation specified
            initRequest.setActivationOtp(validOtpValue);
            powerAuthClient.initActivation(initRequest);
        });
    }

    @Test
    public void wrongActivationInitParamTest4() {
        assertThrows(PowerAuthClientException.class, () -> {
            // Init activation
            InitActivationRequest initRequest = new InitActivationRequest();
            initRequest.setApplicationId(config.getApplicationId());
            initRequest.setUserId(config.getUserV31());
            initRequest.setMaxFailureCount(5L);
            // Set ON_KEY_EXCHANGE but empty OTP
            initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_KEY_EXCHANGE);
            initRequest.setActivationOtp("");
            powerAuthClient.initActivation(initRequest);
        });
    }

    @Test
    public void wrongActivationInitParamTest5() {
        assertThrows(PowerAuthClientException.class, () -> {
            // Init activation
            InitActivationRequest initRequest = new InitActivationRequest();
            initRequest.setApplicationId(config.getApplicationId());
            initRequest.setUserId(config.getUserV31());
            initRequest.setMaxFailureCount(5L);
            // Set ON_COMMIT but empty OTP
            initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_COMMIT);
            initRequest.setActivationOtp("");
            powerAuthClient.initActivation(initRequest);
        });
    }

    @Test
    public void missingOtpOnCommitTest() throws Exception {

        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV31());
        initRequest.setMaxFailureCount(5L);
        initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_COMMIT);
        initRequest.setActivationOtp(validOtpValue);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setResultStatusObject(resultStatusObject);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify activation status
        GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.PENDING_COMMIT, activationStatusResponse.getActivationStatus());

        // Try commit with no OTP for more than max failed attempts. Use OTP in the last iteration, that should pass.
        for (int iteration = 1; iteration <= 6; iteration++) {
            boolean lastIteration = iteration == 6;
            boolean isActivated;
            try {
                CommitActivationRequest commitRequest = new CommitActivationRequest();
                commitRequest.setActivationId(initResponse.getActivationId());
                if (lastIteration) {
                    commitRequest.setActivationOtp(validOtpValue);
                }
                CommitActivationResponse commitResponse = powerAuthClient.commitActivation(commitRequest);
                isActivated = commitResponse.isActivated();
            } catch (Throwable t) {
                isActivated = false;
            }
            assertEquals(lastIteration, isActivated);

            // Verify activation status again
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.ACTIVE : ActivationStatus.PENDING_COMMIT;
            activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
            assertEquals(expectedActivationStatus, activationStatusResponse.getActivationStatus());
        }

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    @Test
    public void missingOtpOnKeysExchangeTest() throws Exception {

        JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV31());
        initRequest.setMaxFailureCount(5L);
        initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_KEY_EXCHANGE);
        initRequest.setActivationOtp(validOtpValue);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setResultStatusObject(resultStatusObject);
        model.setAdditionalActivationOtp(null);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertFalse(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(400, stepLoggerPrepare.getResponse().getStatusCode());
    }
}
