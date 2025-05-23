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

import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.CommitActivationRequest;
import com.wultra.security.powerauth.client.model.response.CommitActivationResponse;
import com.wultra.security.powerauth.client.model.response.v3.GetActivationStatusResponse;
import com.wultra.security.powerauth.provider.CustomActivationProviderForTests;
import com.wultra.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.CreateActivationStep;
import com.wultra.security.powerauth.lib.cmd.steps.GetStatusStep;
import com.wultra.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import com.wultra.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response;
import org.junit.jupiter.api.AssertionFailureBuilder;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Custom activation OTP test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthCustomActivationOtpShared {

    public static void customActivationOtpValidTest(PowerAuthClient powerAuthClient, CreateActivationStepModel createModel, GetStatusStepModel statusModel,
                                             ObjectStepLogger stepLogger, String validOtpValue, String invalidOtpValue) throws Exception {

        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_2_STATIC_NOCOMMIT_NOPROCESS");

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("key", "value");

        createModel.setIdentityAttributes(identityAttributes);
        createModel.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, createModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final ActivationLayer2Response layer2Response = fetchLayer2Response(stepLogger);

        final String activationId = layer2Response.getActivationId();
        assertNotNull(activationId);
        assertNotNull(layer2Response.getCtrData());
        assertNotNull(layer2Response.getServerPublicKey());

        // Verify activation status - activation was not automatically committed
        final GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.PENDING_COMMIT, statusResponseActive.getActivationStatus());
        assertEquals("static_username", statusResponseActive.getUserId());

        final ActivationLayer1Response layer1Response = fetchLayer1Response(stepLogger);

        // Verify custom attributes, there should be no change
        assertEquals("value", layer1Response.getCustomAttributes().get("key"));

        // Now update activation OTP for the pending activation
        powerAuthClient.updateActivationOtp(activationId, null, validOtpValue);

        // Try commit activation with wrong OTP, but the very last attempt is valid.
        final int maxIterations = CustomActivationProviderForTests.MAX_FAILED_ATTEMPTS;
        for (int iteration = 1; iteration <= maxIterations; iteration++) {
            boolean lastIteration = iteration == maxIterations;
            boolean isActivated;
            try {
                final CommitActivationRequest commitRequest = new CommitActivationRequest();
                commitRequest.setActivationId(activationId);
                commitRequest.setActivationOtp(lastIteration ? validOtpValue : invalidOtpValue);
                final CommitActivationResponse commitResponse = powerAuthClient.commitActivation(commitRequest);
                isActivated = commitResponse.isActivated();
            } catch (PowerAuthClientException ex) {
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
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());

        // Validate failed attempts counter.
        final Map<String, Object> statusResponseMap = (Map<String, Object>) stepLoggerStatus.getFirstItem("activation-status-obtained").object();
        ActivationStatusBlobInfo statusBlobInfo = (ActivationStatusBlobInfo) statusResponseMap.get("statusBlob");
        assertEquals(0L, statusBlobInfo.getFailedAttempts());

        // Remove activation
        powerAuthClient.removeActivation(activationId, "test");
    }

    public static void customActivationOtpInvalidTest(PowerAuthClient powerAuthClient, CreateActivationStepModel createModel,
                                        ObjectStepLogger stepLogger, String validOtpValue, String invalidOtpValue) throws Exception {

        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_2_STATIC_NOCOMMIT_NOPROCESS");

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("key", "value");

        createModel.setIdentityAttributes(identityAttributes);
        createModel.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, createModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final ActivationLayer2Response layer2Response = fetchLayer2Response(stepLogger);

        final String activationId = layer2Response.getActivationId();
        assertNotNull(activationId);
        assertNotNull(layer2Response.getCtrData());
        assertNotNull(layer2Response.getServerPublicKey());

        // Verify activation status - activation was not automatically committed
        final GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.PENDING_COMMIT, statusResponseActive.getActivationStatus());
        assertEquals("static_username", statusResponseActive.getUserId());

        final ActivationLayer1Response layer1Response = fetchLayer1Response(stepLogger);

        // Verify custom attributes, there should be no change
        assertEquals("value", layer1Response.getCustomAttributes().get("key"));

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
            } catch (PowerAuthClientException ex) {
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

    private static ActivationLayer1Response fetchLayer1Response(final ObjectStepLogger stepLogger) {
        return stepLogger.getItems().stream()
                .filter(item -> "Decrypted Layer 1 Response".equals(item.name()))
                .map(item -> (ActivationLayer1Response) item.object())
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure().message("Response was not successfully decrypted").build());
    }

    private static ActivationLayer2Response fetchLayer2Response(final ObjectStepLogger stepLogger) {
        return stepLogger.getItems().stream()
                .filter(item -> "Decrypted Layer 2 Response".equals(item.name()))
                .map(item -> (ActivationLayer2Response) item.object())
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure().message("Response was not successfully decrypted").build());
    }
}
