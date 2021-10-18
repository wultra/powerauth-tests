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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.EncryptStep;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import lombok.Data;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opentest4j.AssertionFailedError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthOnboardingTest {

    private PowerAuthTestConfiguration config;
    private PowerAuthClient powerAuthClient;
    private EncryptStepModel encryptModel;
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
    public void setUp() throws IOException {
        encryptModel = new EncryptStepModel();
        encryptModel.setApplicationKey(config.getApplicationKey());
        encryptModel.setApplicationSecret(config.getApplicationSecret());
        encryptModel.setMasterPublicKey(config.getMasterPublicKey());
        encryptModel.setHeaders(new HashMap<>());
        encryptModel.setResultStatusObject(config.getResultStatusObjectV31());
        encryptModel.setVersion("3.1");
        encryptModel.setScope("application");

        stepLogger = new ObjectStepLogger(System.out);
    }

    @Test
    public void testSuccessfulOnboarding() throws Exception {
        // Test onboarding start
        String processId = startOnboarding();

        // Test onboarding status
        assertEquals(OnboardingStatus.IN_PROGRESS, getProcessStatus(processId));

        // Obtain activation OTP from testing endpoint
        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/onboarding/otp/detail");
        OtpDetailRequest requestOtp = new OtpDetailRequest();
        requestOtp.setProcessId(processId);
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

        // Create a new custom activation
        // TODO

        // Test onboarding cleanup until activation is ready
        onboardingCleanup(processId);
    }

    @Test
    public void testOnboardingCleanup() throws Exception {
        // Test onboarding start
        String processId = startOnboarding();

        // Test onboarding status
        assertEquals(OnboardingStatus.IN_PROGRESS, getProcessStatus(processId));

        // Test onboarding cleanup
        onboardingCleanup(processId);

        // Test onboarding status
        assertEquals(OnboardingStatus.FAILED, getProcessStatus(processId));
    }

    @Test
    public void testResendPeriod() throws Exception {
        // Test onboarding start
        String processId = startOnboarding();

        // Test failed OTP resend
        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/onboarding/otp/resend");
        OtpResendRequest requestResend = new OtpResendRequest();
        requestResend.setProcessId(processId);
        ObjectRequest<Object> objectRequest = new ObjectRequest<>();
        objectRequest.setRequestObject(requestResend);
        byte[] data = objectMapper.writeValueAsBytes(objectRequest);
        encryptModel.setData(data);
        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(400, stepLogger.getResponse().getStatusCode());
    }

    @Test
    public void testMaxProcesses() throws Exception {
        // Use same mock client ID suffix to make sure user ID is the same across all requests
        SecureRandom secureRandom = new SecureRandom();
        int randomInt = secureRandom.nextInt(99999999);
        String clientId = Integer.toString(randomInt);
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

    // TODO - max attempts test

    // Shared test logic
    private String startOnboarding() throws Exception {
        return startOnboarding(null);
    }

    private String startOnboarding(String clientId) throws Exception {
        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/onboarding/start");
        Map<String, Object> identification = new LinkedHashMap<>();
        if (clientId == null) {
            identification.put("clientId", "12345678");
        } else {
            identification.put("clientId", clientId);
        }
        identification.put("birthDate", "1970/03/21");
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
        assertEquals(OnboardingStatus.IN_PROGRESS, onboardingStatus);
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
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/onboarding/cleanup");
        OnboardingCleanupRequest requestCleanup = new OnboardingCleanupRequest();
        requestCleanup.setProcessId(processId);
        executeRequest(requestCleanup);
    }

    private OnboardingStatus getProcessStatus(String processId) throws Exception {
        OnboardingStatus onboardingStatus = null;
        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/onboarding/status");
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

    // Model classes
    @Data
    public static class OnboardingStartRequest {
        private Map<String, Object> identification;
    }

    @Data
    public static class OnboardingStartResponse {
        private String processId;
        private OnboardingStatus onboardingStatus;
    }

    public enum OnboardingStatus {
        IN_PROGRESS,
        FINISHED,
        FAILED
    }

    @Data
    public static class OnboardingStatusRequest {
        private String processId;
    }

    @Data
    public static class OnboardingStatusResponse {
        private String processId;
        private OnboardingStatus onboardingStatus;
    }

    @Data
    public static class OtpResendRequest {
        private String processId;
    }

    @Data
    public static class OtpDetailRequest {
        private String processId;
    }

    @Data
    public static class OtpDetailResponse {
        private String processId;
        private String otpCode;
    }

    @Data
    public static class OnboardingCleanupRequest {
        private String processId;
    }

}
