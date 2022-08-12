/*
 * PowerAuth test and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.app.enrollmentserver.api.model.onboarding.request.OnboardingCleanupRequest;
import com.wultra.app.enrollmentserver.api.model.onboarding.request.OnboardingOtpResendRequest;
import com.wultra.app.enrollmentserver.api.model.onboarding.request.OnboardingStartRequest;
import com.wultra.app.enrollmentserver.api.model.onboarding.request.OnboardingStatusRequest;
import com.wultra.app.enrollmentserver.api.model.onboarding.response.OnboardingStartResponse;
import com.wultra.app.enrollmentserver.api.model.onboarding.response.OnboardingStatusResponse;
import com.wultra.app.enrollmentserver.model.enumeration.OnboardingStatus;
import com.wultra.app.enrollmentserver.model.enumeration.OtpType;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.v3.ActivationStatus;
import com.wultra.security.powerauth.client.v3.GetActivationStatusResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.model.request.OtpDetailRequest;
import com.wultra.security.powerauth.model.response.OtpDetailResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.CreateActivationStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.EncryptStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.GetStatusStep;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opentest4j.AssertionFailedError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthOnboardingTest {

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private EncryptStepModel encryptModel;
    private CreateActivationStepModel activationModel;
    private GetStatusStepModel statusModel;
    private ObjectStepLogger stepLogger;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @BeforeEach
    void setUp() throws IOException {
        encryptModel = new EncryptStepModel();
        encryptModel.setApplicationKey(config.getApplicationKey());
        encryptModel.setApplicationSecret(config.getApplicationSecret());
        encryptModel.setMasterPublicKey(config.getMasterPublicKey());
        encryptModel.setHeaders(new HashMap<>());
        encryptModel.setResultStatusObject(config.getResultStatusObjectV31());
        encryptModel.setVersion("3.1");
        encryptModel.setScope("application");

        // Create temp status file
        File tempStatusFile = File.createTempFile("pa_status_v31", ".json");
        JSONObject resultStatusObject = new JSONObject();

        // Model shared among tests
        activationModel = new CreateActivationStepModel();
        activationModel.setActivationName("test v3.1 onboarding");
        activationModel.setApplicationKey(config.getApplicationKey());
        activationModel.setApplicationSecret(config.getApplicationSecret());
        activationModel.setMasterPublicKey(config.getMasterPublicKey());
        activationModel.setHeaders(new HashMap<>());
        activationModel.setPassword(config.getPassword());
        activationModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        activationModel.setResultStatusObject(resultStatusObject);
        activationModel.setUriString(config.getEnrollmentServiceUrl());
        activationModel.setVersion("3.1");
        activationModel.setDeviceInfo("backend-tests");

        statusModel = new GetStatusStepModel();
        statusModel.setHeaders(new HashMap<>());
        statusModel.setResultStatusObject(resultStatusObject);
        statusModel.setUriString(config.getEnrollmentServiceUrl());
        statusModel.setVersion("3.1");

        stepLogger = new ObjectStepLogger(System.out);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testSuccessfulOnboarding() throws Exception {
        // Test onboarding start
        String clientId = generateRandomClientId();
        String processId = startOnboarding(clientId);

        // Test onboarding status
        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, getProcessStatus(processId));

        // Obtain activation OTP from testing endpoint
        String otpCode = getOtpCode(processId);

        // Create a new custom activation
        String activationId = createCustomActivation(processId, otpCode, clientId);

        // Test onboarding status
        assertEquals(OnboardingStatus.VERIFICATION_IN_PROGRESS, getProcessStatus(processId));

        // Verify activation flags using custom object in status
        ObjectStepLogger stepLoggerStatus = new ObjectStepLogger(System.out);
        new GetStatusStep().execute(stepLoggerStatus, statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().isSuccess());
        assertEquals(200, stepLoggerStatus.getResponse().getStatusCode());
        ObjectResponse<ActivationStatusResponse> objectResponse = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().getResponseObject();
        Map<String, Object> customObject = objectResponse.getResponseObject().getCustomObject();
        assertNotNull(customObject);
        assertEquals(Collections.singletonList("VERIFICATION_PENDING"), customObject.get("activationFlags"));

        // Remove activation
        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void testInvalidOtp() throws Exception {
        // Test onboarding start
        String clientId = generateRandomClientId();
        String processId = startOnboarding(clientId);

        // Test onboarding status
        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, getProcessStatus(processId));

        assertThrows(AssertionFailedError.class, () ->
                createCustomActivation(processId, "0000000000", clientId),
                "Activation with invalid OTP should fail");

        // Test onboarding cleanup
        onboardingCleanup(processId);
    }

    @Test
    public void testInvalidProcessId() throws Exception {
        assertThrows(AssertionFailedError.class, () ->
                createCustomActivation("8b2928d2-f7e7-489b-8ebc-76d4aad173a6", "0000000000", "12345678"),
                "Activation with invalid OTP should fail");
    }

    @Test
    void testOnboardingCleanup() throws Exception {
        // Test onboarding start
        String processId = startOnboarding();

        // Test onboarding status
        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, getProcessStatus(processId));

        // Test onboarding cleanup
        onboardingCleanup(processId);

        // Test onboarding status
        assertEquals(OnboardingStatus.FAILED, getProcessStatus(processId));
    }

    @Test
    void testResendPeriod() throws Exception {
        // Test onboarding start
        String processId = startOnboarding();

        // Test failed OTP resend
        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/otp/resend");
        OnboardingOtpResendRequest requestResend = new OnboardingOtpResendRequest();
        requestResend.setProcessId(processId);
        ObjectRequest<Object> objectRequest = new ObjectRequest<>();
        objectRequest.setRequestObject(requestResend);
        byte[] data = objectMapper.writeValueAsBytes(objectRequest);
        encryptModel.setData(data);
        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(400, stepLogger.getResponse().getStatusCode());

        // Test onboarding cleanup
        onboardingCleanup(processId);
    }

    @Test
    void testMaxProcesses() throws Exception {
        // Use same mock client ID suffix to make sure user ID is the same across all requests
        String clientId = generateRandomClientId();
        String processId = startOnboarding(clientId);
        onboardingCleanup(processId);
        processId = startOnboarding(clientId);
        onboardingCleanup(processId);
        processId = startOnboarding(clientId);
        onboardingCleanup(processId);
        processId = startOnboarding(clientId);
        onboardingCleanup(processId);
        processId = startOnboarding(clientId);
        onboardingCleanup(processId);
        // Sixth attempt should fail
        processId = null;
        try {
            processId = startOnboarding(clientId);
        } catch (AssertionFailedError e) {
            // Expected failure
        }
        assertNull(processId);
    }

    @Test
    void testMaxAttemptsReached() throws Exception {
        // Test onboarding start
        String clientId = generateRandomClientId();
        String processId = startOnboarding(clientId);

        // Test onboarding status
        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, getProcessStatus(processId));

        // Obtain activation OTP from testing endpoint
        String otpCode = getOtpCode(processId);

        for (int i = 0; i < 5; i++) {
            assertThrows(AssertionFailedError.class, () ->
                    createCustomActivation(processId, "0000000000", clientId),
                    "Activation with invalid OTP should fail");
        }

        assertThrows(AssertionFailedError.class, () ->
                createCustomActivation(processId, otpCode, clientId),
                "Sixth attempt with correct OTP code should fail");
    }

    @Test
    void testMaxAttemptsNotReached() throws Exception {
        // Test onboarding start
        String clientId = generateRandomClientId();
        String processId = startOnboarding(clientId);

        // Test onboarding status
        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, getProcessStatus(processId));

        // Obtain activation OTP from testing endpoint
        String otpCode = getOtpCode(processId);

        for (int i = 0; i < 4; i++) {
            assertThrows(AssertionFailedError.class, () ->
                    createCustomActivation(processId, "0000000000", clientId),
                    "A new custom activation with invalid OTP code should fail");
        }
        String activationId = createCustomActivation(processId, otpCode, clientId);
        assertNotNull(activationId, "Fifth attempt with correct OTP code should succeed");
    }

    @Test
    void testResumeProcesses() throws Exception {
        final String clientId = generateRandomClientId();
        final String processId1 = startOnboarding(clientId);
        final String processId2 = startOnboarding(clientId);
        assertEquals(processId1, processId2, "Process must resume for the given clientId");
    }

    // Shared test logic
    private String startOnboarding() throws Exception {
        return startOnboarding(null);
    }

    private String startOnboarding(final String clientId) throws Exception {
        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/start");
        Map<String, Object> identification = new LinkedHashMap<>();
        identification.put("clientNumber", clientId != null ? clientId : generateRandomClientId());
        identification.put("birthDate", "1970-03-21");
        OnboardingStartRequest request = new OnboardingStartRequest();
        request.setIdentification(identification);
        executeRequest(request);

        EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger.getResponse().getResponseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

        boolean responseSuccessfullyDecrypted = false;
        String processId = null;
        OnboardingStatus onboardingStatus = null;
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                String responseData = item.getObject().toString();
                ObjectResponse<OnboardingStartResponse> objectResponse = objectMapper.readValue(responseData, new TypeReference<ObjectResponse<OnboardingStartResponse>>() {});
                OnboardingStartResponse response = objectResponse.getResponseObject();
                processId = response.getProcessId();
                onboardingStatus = response.getOnboardingStatus();
                responseSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseSuccessfullyDecrypted);
        assertNotNull(processId);
        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, onboardingStatus);
        return processId;
    }

    private void executeRequest(Object request) throws Exception {
        ObjectRequest<Object> objectRequest = new ObjectRequest<>();
        objectRequest.setRequestObject(request);
        byte[] data = objectMapper.writeValueAsBytes(objectRequest);
        encryptModel.setData(data);
        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
    }

    private void onboardingCleanup(String processId) throws Exception {
        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/cleanup");
        OnboardingCleanupRequest requestCleanup = new OnboardingCleanupRequest();
        requestCleanup.setProcessId(processId);
        executeRequest(requestCleanup);
    }

    private OnboardingStatus getProcessStatus(String processId) throws Exception {
        OnboardingStatus onboardingStatus = null;
        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/status");
        OnboardingStatusRequest requestStatus = new OnboardingStatusRequest();
        requestStatus.setProcessId(processId);
        executeRequest(requestStatus);

        EciesEncryptedResponse responseStatusOK = (EciesEncryptedResponse) stepLogger.getResponse().getResponseObject();
        assertNotNull(responseStatusOK.getEncryptedData());
        assertNotNull(responseStatusOK.getMac());

        boolean responseStatusSuccessfullyDecrypted = false;
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                String responseData = item.getObject().toString();
                ObjectResponse<OnboardingStatusResponse> objectResponse = objectMapper.readValue(responseData, new TypeReference<ObjectResponse<OnboardingStatusResponse>>() {});
                OnboardingStatusResponse response = objectResponse.getResponseObject();
                processId = response.getProcessId();
                onboardingStatus = response.getOnboardingStatus();
                responseStatusSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseStatusSuccessfullyDecrypted);
        assertNotNull(processId);
        return onboardingStatus;
    }

    private String generateRandomClientId() {
        SecureRandom random = new SecureRandom();
        BigInteger bound = BigInteger.TEN.pow(18).subtract(BigInteger.ONE);
        long number = Math.abs(random.nextLong() % bound.longValue());
        return Long.toString(number);
    }

    private String createCustomActivation(String processId, String otpCode, String clientId) throws Exception {
        stepLogger = new ObjectStepLogger(System.out);
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("processId", processId);
        identityAttributes.put("otpCode", otpCode);
        activationModel.setIdentityAttributes(identityAttributes);
        new CreateActivationStep().execute(stepLogger, activationModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        String activationId = null;
        boolean responseOk = false;
        // Verify decrypted responses
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Layer 2 Response")) {
                ActivationLayer2Response layer2Response = (ActivationLayer2Response) item.getObject();
                activationId = layer2Response.getActivationId();
                assertNotNull(activationId);
                assertNotNull(layer2Response.getCtrData());
                assertNotNull(layer2Response.getServerPublicKey());
                // Verify activation status - activation was automatically committed
                GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(activationId);
                assertEquals(ActivationStatus.ACTIVE, statusResponseActive.getActivationStatus());
                assertEquals("mockuser_" + clientId, statusResponseActive.getUserId());
                assertEquals(Collections.singletonList("VERIFICATION_PENDING"), statusResponseActive.getActivationFlags());
                responseOk = true;
            }
        }

        assertTrue(responseOk);
        return activationId;
    }

    private String getOtpCode(String processId) throws Exception {
        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/otp/detail");
        OtpDetailRequest requestOtp = new OtpDetailRequest();
        requestOtp.setProcessId(processId);
        requestOtp.setOtpType(OtpType.ACTIVATION);
        executeRequest(requestOtp);

        EciesEncryptedResponse responseOtpOK = (EciesEncryptedResponse) stepLogger.getResponse().getResponseObject();
        assertNotNull(responseOtpOK.getEncryptedData());
        assertNotNull(responseOtpOK.getMac());

        boolean responseOtpSuccessfullyDecrypted = false;
        String otpCode = null;
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                String responseData = item.getObject().toString();
                ObjectResponse<OtpDetailResponse> objectResponse = objectMapper.readValue(responseData, new TypeReference<ObjectResponse<OtpDetailResponse>>() {});
                OtpDetailResponse response = objectResponse.getResponseObject();
                otpCode = response.getOtpCode();
                responseOtpSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseOtpSuccessfullyDecrypted);
        assertNotNull(otpCode);
        return otpCode;
    }

}
