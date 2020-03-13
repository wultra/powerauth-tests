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

import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.powerauth.soap.v3.*;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.CreateActivationStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response;
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
import org.springframework.ws.soap.client.SoapFaultClientException;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthActivationOtpTest {

    private PowerAuthServiceClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private PrepareActivationStepModel model;
    private File tempStatusFile;

    private final String validOtpValue = "1234-5678";
    private final String invalidOtpValue = "8765-4321";

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
        tempStatusFile = File.createTempFile("pa_status_v31", ".json");

        // Model shared among tests
        model = new PrepareActivationStepModel();
        model.setActivationName("test v31");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(new JSONObject());
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("3.1");
        model.setDeviceInfo("backend-tests");
    }

    @After
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
        initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_KEYS_EXCHANGE);
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
        initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_KEYS_EXCHANGE);
        initRequest.setActivationOtp(validOtpValue);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setResultStatusObject(resultStatusObject);
        model.setAdditionalActivationOtp(invalidOtpValue);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertFalse(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(400, stepLoggerPrepare.getResponse().getStatusCode());

        // Verify activation status
        GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertNotNull(activationStatusResponse);
        assertEquals(ActivationStatus.REMOVED, activationStatusResponse.getActivationStatus());
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
        assertEquals(ActivationStatus.OTP_USED, activationStatusResponse.getActivationStatus());

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
            assertEquals(lastIteration ? ActivationStatus.ACTIVE : ActivationStatus.OTP_USED, activationStatusResponse.getActivationStatus());
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
        assertEquals(ActivationStatus.OTP_USED, activationStatusResponse.getActivationStatus());

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
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.REMOVED : ActivationStatus.OTP_USED;
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
        assertEquals(ActivationStatus.OTP_USED, activationStatusResponse.getActivationStatus());

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
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.ACTIVE : ActivationStatus.OTP_USED;
            activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
            assertEquals(expectedActivationStatus, activationStatusResponse.getActivationStatus());
        }

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
        assertEquals(ActivationStatus.OTP_USED, activationStatusResponse.getActivationStatus());

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
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.REMOVED : ActivationStatus.OTP_USED;
            activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
            assertEquals(expectedActivationStatus, activationStatusResponse.getActivationStatus());
        }
    }

    @Test(expected = SoapFaultClientException.class)
    public void wrongActivationInitParamTest1() throws Exception {
        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV31());
        initRequest.setMaxFailureCount(5L);
        // Set ON_KEYS_EXCHANGE but no OTP
        initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_KEYS_EXCHANGE);
        powerAuthClient.initActivation(initRequest);
    }

    @Test(expected = SoapFaultClientException.class)
    public void wrongActivationInitParamTest2() throws Exception {
        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV31());
        initRequest.setMaxFailureCount(5L);
        // Set ON_COMMIT but no OTP
        initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_COMMIT);
        powerAuthClient.initActivation(initRequest);
    }

    @Test(expected = SoapFaultClientException.class)
    public void wrongActivationInitParamTest3() throws Exception {
        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV31());
        initRequest.setMaxFailureCount(5L);
        // Set OTP with no validation specified
        initRequest.setActivationOtp(validOtpValue);
        powerAuthClient.initActivation(initRequest);
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
        assertEquals(ActivationStatus.OTP_USED, activationStatusResponse.getActivationStatus());

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
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.ACTIVE : ActivationStatus.OTP_USED;
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
        initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_KEYS_EXCHANGE);
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
