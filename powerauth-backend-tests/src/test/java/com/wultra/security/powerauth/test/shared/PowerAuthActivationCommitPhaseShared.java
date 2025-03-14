/*
 * PowerAuth test and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.CommitPhase;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.CommitActivationRequest;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.response.CommitActivationResponse;
import com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse;
import com.wultra.security.powerauth.client.model.response.InitActivationResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.v3.GetStatusStep;
import com.wultra.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import org.json.simple.JSONObject;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth activation commit phase shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthActivationCommitPhaseShared {

    public static void validOtpOnKeysExchangeTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config,
                                                  PrepareActivationStepModel model, String validOtpValue, PowerAuthVersion version) throws Exception {

        final JSONObject resultStatusObject = new JSONObject();

        // Init activation
        final InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        initRequest.setMaxFailureCount(5L);
        initRequest.setActivationOtp(validOtpValue);
        initRequest.setCommitPhase(CommitPhase.ON_KEY_EXCHANGE);
        final InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setResultStatusObject(resultStatusObject);
        model.setAdditionalActivationOtp(validOtpValue);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

        // Verify activation status
        final GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertNotNull(activationStatusResponse);
        assertEquals(ActivationStatus.ACTIVE, activationStatusResponse.getActivationStatus());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    public static void invalidOtpOnKeysExchangeTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config,
                                                    PrepareActivationStepModel model, String validOtpValue,
                                                    String invalidOtpValue, PowerAuthVersion version) throws Exception {

        final JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        initRequest.setMaxFailureCount(5L);
        initRequest.setActivationOtp(validOtpValue);
        initRequest.setCommitPhase(CommitPhase.ON_KEY_EXCHANGE);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        for (int iteration = 1; iteration <= 5; iteration++) {
            final boolean lastIteration = iteration == 5;
            // Prepare activation
            model.setActivationCode(initResponse.getActivationCode());
            model.setResultStatusObject(resultStatusObject);
            model.setAdditionalActivationOtp(invalidOtpValue);
            ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
            new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
            assertFalse(stepLoggerPrepare.getResult().success());
            assertEquals(400, stepLoggerPrepare.getResponse().statusCode());

            // Verify activation status
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.REMOVED : ActivationStatus.CREATED;
            GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
            assertNotNull(activationStatusResponse);
            assertEquals(expectedActivationStatus, activationStatusResponse.getActivationStatus());
        }
    }

    public static void validOtpOnCommitTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PrepareActivationStepModel model,
                                            String validOtpValue, String invalidOtpValue, PowerAuthVersion version) throws Exception {

        final JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        initRequest.setMaxFailureCount(5L);
        initRequest.setActivationOtp(validOtpValue);
        initRequest.setCommitPhase(CommitPhase.ON_COMMIT);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setResultStatusObject(resultStatusObject);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

        // Verify activation status
        GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertNotNull(activationStatusResponse);
        assertEquals(ActivationStatus.PENDING_COMMIT, activationStatusResponse.getActivationStatus());

        // Try commit activation with wrong OTP. Last attempt is valid.
        for (int iteration = 1; iteration <= 5; iteration++) {
            boolean lastIteration = iteration == 5;
            final CommitActivationRequest commitRequest = new CommitActivationRequest();
            commitRequest.setActivationId(initResponse.getActivationId());
            commitRequest.setActivationOtp(lastIteration ? validOtpValue : invalidOtpValue);

            boolean isActivated;
            try {
                final CommitActivationResponse commitResponse = powerAuthClient.commitActivation(commitRequest);
                isActivated = commitResponse.isActivated();
            } catch (PowerAuthClientException ex) {
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

    public static void invalidOtpOnCommitTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config,
                                              PrepareActivationStepModel model, String validOtpValue,
                                              String invalidOtpValue, PowerAuthVersion version) throws Exception {

        final JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        initRequest.setMaxFailureCount(5L);
        initRequest.setActivationOtp(validOtpValue);
        initRequest.setCommitPhase(CommitPhase.ON_COMMIT);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setResultStatusObject(resultStatusObject);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

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
            } catch (PowerAuthClientException ex) {
                isActivated = false;
            }
            assertFalse(isActivated);

            // Verify activation status
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.REMOVED : ActivationStatus.PENDING_COMMIT;
            activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
            assertEquals(expectedActivationStatus, activationStatusResponse.getActivationStatus());
        }
    }

    public static void updateValidOtpOnCommitTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config,
                                                  PrepareActivationStepModel model, GetStatusStepModel statusModel,
                                                  String validOtpValue, String invalidOtpValue, PowerAuthVersion version) throws Exception {

        final JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        initRequest.setMaxFailureCount(5L);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setResultStatusObject(resultStatusObject);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

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
            } catch (PowerAuthClientException ex) {
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
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());

        // Validate failed and max failed attempts.
        final Map<String, Object> statusResponseMap = (Map<String, Object>) stepLoggerStatus.getFirstItem("activation-status-obtained").object();
        ActivationStatusBlobInfo statusBlobInfo = (ActivationStatusBlobInfo) statusResponseMap.get("statusBlob");
        assertEquals(5L, statusBlobInfo.getMaxFailedAttempts());
        assertEquals(0L, statusBlobInfo.getFailedAttempts());

        // Remove activation
        powerAuthClient.removeActivation(initResponse.getActivationId(), "test");
    }

    public static void updateInvalidOtpOnCommitTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config,
                                                    PrepareActivationStepModel model, String validOtpValue,
                                                    String invalidOtpValue, PowerAuthVersion version) throws Exception {

        final JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        initRequest.setMaxFailureCount(5L);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        model.setResultStatusObject(resultStatusObject);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

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
            } catch (PowerAuthClientException ex) {
                isActivated = false;
            }
            assertFalse(isActivated);

            // Verify activation status
            ActivationStatus expectedActivationStatus = lastIteration ? ActivationStatus.REMOVED : ActivationStatus.PENDING_COMMIT;
            activationStatusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
            assertEquals(expectedActivationStatus, activationStatusResponse.getActivationStatus());
        }
    }

    public static void wrongActivationInitParamTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) {
        assertThrows(PowerAuthClientException.class, () -> {
            // Init activation
            InitActivationRequest initRequest = new InitActivationRequest();
            initRequest.setApplicationId(config.getApplicationId());
            initRequest.setUserId(config.getUser(version));
            initRequest.setMaxFailureCount(5L);
            // Set both activation OTP validation and commit phase
            initRequest.setActivationOtpValidation(ActivationOtpValidation.ON_KEY_EXCHANGE);
            initRequest.setCommitPhase(CommitPhase.ON_KEY_EXCHANGE);
            powerAuthClient.initActivation(initRequest);
        });
    }

}
