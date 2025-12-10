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
package com.wultra.security.powerauth.test.shared.v3;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.app.enrollmentserver.api.model.onboarding.request.OnboardingCleanupRequest;
import com.wultra.app.enrollmentserver.api.model.onboarding.request.OnboardingOtpResendRequest;
import com.wultra.app.enrollmentserver.api.model.onboarding.request.OnboardingStartRequest;
import com.wultra.app.enrollmentserver.api.model.onboarding.request.OnboardingStatusRequest;
import com.wultra.app.enrollmentserver.api.model.onboarding.response.ConfigurationResponse;
import com.wultra.app.enrollmentserver.api.model.onboarding.response.OnboardingStartResponse;
import com.wultra.app.enrollmentserver.api.model.onboarding.response.OnboardingStatusResponse;
import com.wultra.app.enrollmentserver.api.model.onboarding.response.error.ActivationOtpErrorResponse;
import com.wultra.app.enrollmentserver.model.enumeration.ActivationType;
import com.wultra.app.enrollmentserver.model.enumeration.OnboardingStatus;
import com.wultra.app.enrollmentserver.model.enumeration.OtpType;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.response.v3.GetActivationStatusResponse;
import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.CreateActivationStep;
import com.wultra.security.powerauth.lib.cmd.steps.EncryptStep;
import com.wultra.security.powerauth.lib.cmd.steps.GetStatusStep;
import com.wultra.security.powerauth.lib.cmd.steps.PrepareActivationStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import com.wultra.security.powerauth.model.request.OtpDetailRequest;
import com.wultra.security.powerauth.model.response.OtpDetailResponse;
import com.wultra.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response;
import com.wultra.security.powerauth.rest.api.model.response.v3.ActivationStatusResponse;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.AssertionFailureBuilder;
import org.opentest4j.AssertionFailedError;

import java.io.File;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth onboarding test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthOnboardingShared {

    public static final SharedSecretAlgorithm SHARED_SECRET_ALGORITHM_DEFAULT = SharedSecretAlgorithm.EC_P384_ML_L3;

    /**
     * Test of {@code POST /api/configuration}.
     *
     * @param ctx test context
     * @implNote requires data from {@code /src/test/resources/data/enrollment-onboarding/extra-data.sql}; maven test runner is configured to insert the data
     */
    public static void testConfiguration(final TestContext ctx) throws Exception {
        final ObjectStepLogger stepLogger = new ObjectStepLogger();
        ctx.encryptModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/configuration");
        final Map<String, Object> request = Map.of("processType", "reactivation");
        executeRequest(ctx, request, stepLogger);

        final EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

        final ConfigurationResponse response = stepLogger.getItems().stream()
                .filter(item -> "Decrypted Response".equals(item.name()))
                .map(item -> item.object().toString())
                .map(item -> read(ctx.objectMapper, item, new TypeReference<ObjectResponse<ConfigurationResponse>>() {}))
                .map(ObjectResponse::getResponseObject)
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure().message("Response was not successfully decrypted").build());

        assertTrue(response.enabled());
        assertTrue(response.otpForIdentification());
        assertTrue(response.otpForIdentityVerification());

        final var documents = response.documents();
        assertEquals(2, documents.requiredDocumentsCount());
        assertEquals(2, documents.items().size());

        final var item1 = documents.items().get(0);
        assertEquals(ConfigurationResponse.DocumentType.ID_CARD, item1.type());
        assertEquals(2, item1.sideCount());
        assertTrue(item1.mandatory());

        final var item2 = documents.items().get(1);
        assertEquals(ConfigurationResponse.DocumentType.DRIVING_LICENCE, item2.type());
        assertEquals(1, item2.sideCount());
        assertFalse(item2.mandatory());
    }

    @SuppressWarnings("unchecked")
    public static void testSuccessfulOnboardingWithCustomActivation(final TestContext ctx) throws Exception {
        // Test onboarding start
        String clientId = generateRandomClientId();
        final OnboardingStartResponse onboardingStartResponse = startOnboarding(ctx, clientId);
        assertNull(onboardingStartResponse.activationCode());
        assertEquals(ActivationType.IDENTITY, onboardingStartResponse.activationType());
        final String processId = onboardingStartResponse.processId();

        // Test onboarding status
        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, getProcessStatus(ctx, processId));

        // Obtain activation OTP from testing endpoint
        String otpCode = getOtpCode(ctx, processId);

        // Create a new custom activation
        String activationId = createCustomActivation(ctx, processId, otpCode, clientId);

        // Test onboarding status
        assertEquals(OnboardingStatus.VERIFICATION_IN_PROGRESS, getProcessStatus(ctx, processId));

        // Verify activation flags using custom object in status
        ObjectStepLogger stepLoggerStatus = new ObjectStepLogger();
        new GetStatusStep().execute(stepLoggerStatus, ctx.statusModel.toMap());
        assertTrue(stepLoggerStatus.getResult().success());
        assertEquals(200, stepLoggerStatus.getResponse().statusCode());
        final ObjectResponse<ActivationStatusResponse> objectResponse = (ObjectResponse<ActivationStatusResponse>) stepLoggerStatus.getResponse().responseObject();
        Map<String, Object> customObject = objectResponse.getResponseObject().getCustomObject();
        assertNotNull(customObject);
        assertEquals(Collections.singletonList("VERIFICATION_PENDING"), customObject.get("activationFlags"));

        onboardingCleanup(ctx, processId);
        final GetActivationStatusResponse activationStatusResponse = ctx.powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.REMOVED, activationStatusResponse.getActivationStatus(), "Cleanup should remove the activation");
    }

    @SuppressWarnings("unchecked")
    public static void testSuccessfulOnboardingWithActivationCode(final TestContext ctx) throws Exception {
        final String clientId = generateRandomClientId();
        final OnboardingStartResponse onboardingStartResponse = startOnboarding(ctx, clientId, false, "onboarding");
        assertNotNull(onboardingStartResponse.activationCode());
        assertEquals(ActivationType.CODE, onboardingStartResponse.activationType());
        final String processId = onboardingStartResponse.processId();

        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, getProcessStatus(ctx, processId));

        final String activationCode = onboardingStartResponse.activationCode();
        assertNotNull(activationCode);

        final String activationId = finishActivation(ctx, activationCode);

        // not yet synchronized, done in /api/identity/init
        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, getProcessStatus(ctx, processId));

        // activation is not yet active
        final ObjectStepLogger stepLoggerStatus = new ObjectStepLogger();
        new GetStatusStep().execute(stepLoggerStatus, ctx.statusModel.toMap());
        assertFalse(stepLoggerStatus.getResult().success());

        onboardingCleanup(ctx, processId);
        final GetActivationStatusResponse activationStatusResponse = ctx.powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.REMOVED, activationStatusResponse.getActivationStatus(), "Cleanup should remove the activation");
    }

    private static String finishActivation(final TestContext ctx, final String activationCode) throws Exception {
        final PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationCode(activationCode);
        model.setActivationName(UUID.randomUUID().toString());
        model.setApplicationKey(ctx.config().getApplicationKey());
        model.setApplicationSecret(ctx.config().getApplicationSecret());

        final PowerAuthVersion version = ctx.activationModel().getVersion();
        if (version.getMajorVersion() == 3) {
            model.setMasterPublicKeyP256(ctx.config().getMasterPublicKeyP256());
        } else {
            model.setMasterPublicKeyP384(ctx.config().getMasterPublicKeyP384());
            model.setMasterPublicKeyMlDsa65(ctx.config().getMasterPublicKeyMlDsa65());
            model.setSharedSecretAlgorithm(SHARED_SECRET_ALGORITHM_DEFAULT);
        }

        model.setHeaders(new HashMap<>());
        model.setPassword(ctx.config().getPassword());
        model.setResultStatusObject(new JSONObject());
        model.setStatusFileName(File.createTempFile("pa_status_onboarding_test_" + version, ".json").getAbsolutePath());
        model.setUriString(ctx.config().getEnrollmentServiceUrl());
        model.setVersion(version);
        model.setDeviceInfo("backend-tests");
        final ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

        return stepLoggerPrepare.getItems().stream()
                .filter(item -> "Decrypted Layer 2 Response".equals(item.name()))
                .map(item -> (ActivationLayer2Response) item.object())
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure().message("Response was not successfully decrypted").build())
                .getActivationId();
    }

    public static void testInvalidOtp(final TestContext ctx) throws Exception {
        // Test onboarding start
        String clientId = generateRandomClientId();
        final String processId = startOnboarding(ctx, clientId).processId();

        // Test onboarding status
        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, getProcessStatus(ctx, processId));

        assertThrows(AssertionFailedError.class, () ->
                createCustomActivation(ctx, processId, "0000000000", clientId),
                "Activation with invalid OTP should fail");

        // Test onboarding cleanup
        onboardingCleanup(ctx, processId);
    }

    public static void testOtpForNonExistingUser(final TestContext ctx) throws Exception {

        final String clientId = generateRandomClientId();
        final String processId = startOnboarding(ctx, clientId, true, null).processId();

        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, getProcessStatus(ctx, processId));

        // assert that otp code has been generated although not sent
        getOtpCode(ctx, processId);

        onboardingCleanup(ctx, processId);
    }

    public static void testInvalidProcessId(final TestContext ctx) {
        assertThrows(AssertionFailedError.class, () ->
                createCustomActivation(ctx, "8b2928d2-f7e7-489b-8ebc-76d4aad173a6", "0000000000", "12345678"),
                "Activation with invalid OTP should fail");
    }

    public static void testOnboardingCleanup(final TestContext ctx) throws Exception {
        // Test onboarding start
        final String processId = startOnboarding(ctx).processId();

        // Test onboarding status
        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, getProcessStatus(ctx, processId));

        // Test onboarding cleanup
        onboardingCleanup(ctx, processId);

        // Test onboarding status
        assertEquals(OnboardingStatus.FAILED, getProcessStatus(ctx, processId));
    }

    public static void testResendPeriod(final TestContext ctx) throws Exception {
        // Test onboarding start
        final String processId = startOnboarding(ctx).processId();

        // Test failed OTP resend
        ObjectStepLogger stepLogger = ctx.stepLogger;
        ctx.encryptModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/otp/resend");
        OnboardingOtpResendRequest requestResend = new OnboardingOtpResendRequest();
        requestResend.setProcessId(processId);
        ObjectRequest<Object> objectRequest = new ObjectRequest<>();
        objectRequest.setRequestObject(requestResend);
        byte[] data = ctx.objectMapper.writeValueAsBytes(objectRequest);
        ctx.encryptModel.setData(data);
        new EncryptStep().execute(stepLogger, ctx.encryptModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());

        // Test onboarding cleanup
        onboardingCleanup(ctx, processId);
    }

    public static void testMaxProcesses(final TestContext ctx) throws Exception {
        // Use same client ID to make sure user ID is the same across all requests
        final String clientId = generateRandomClientId();

        for (int i = 0; i < 5; i++) {
            final String processId = startOnboarding(ctx, clientId).processId();
            onboardingCleanup(ctx, processId);
        }

        // Sixth attempt should fail
        assertThrows(AssertionError.class, () -> startOnboarding(ctx, clientId));
    }

    public static void testOtpMaxFailedAttemptsReached(final TestContext ctx) throws Exception {
        // Test onboarding start
        String clientId = generateRandomClientId();
        final String processId = startOnboarding(ctx, clientId).processId();

        // Test onboarding status
        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, getProcessStatus(ctx, processId));

        // Obtain activation OTP from testing endpoint
        String otpCode = getOtpCode(ctx, processId);

        for (int i = 4; i > 0; i--) {
            assertEquals(i,
                    createCustomActivationAssumeFailure(ctx, processId, "0000000000"),
                    "Activation with invalid OTP should fail and remaining attempt count should be valid");
        }

        assertNull(createCustomActivationAssumeFailure(ctx, processId, "0000000000"),
                "Activation with invalid OTP should fail when all attempts were used");

        assertNull(createCustomActivationAssumeFailure(ctx, processId, otpCode), "Sixth attempt with correct OTP code should fail");

        assertEquals(OnboardingStatus.FAILED, getProcessStatus(ctx, processId));
    }

    public static void testMaxAttemptsNotReached(final TestContext ctx) throws Exception {
        // Test onboarding start
        String clientId = generateRandomClientId();
        final String processId = startOnboarding(ctx, clientId).processId();

        // Test onboarding status
        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, getProcessStatus(ctx, processId));

        // Obtain activation OTP from testing endpoint
        String otpCode = getOtpCode(ctx, processId);

        for (int i = 0; i < 4; i++) {
            assertThrows(AssertionFailedError.class, () ->
                    createCustomActivation(ctx, processId, "0000000000", clientId),
                    "A new custom activation with invalid OTP code should fail");
        }
        String activationId = createCustomActivation(ctx, processId, otpCode, clientId);
        assertNotNull(activationId, "Fifth attempt with correct OTP code should succeed");
    }

    public static void testResumeProcesses(final TestContext ctx) throws Exception {
        final String clientId = generateRandomClientId();
        final String processId1 = startOnboarding(ctx, clientId).processId();
        final String processId2 = startOnboarding(ctx, clientId).processId();
        assertEquals(processId1, processId2, "Process must resume for the given clientId");
    }

    // Shared test logic
    private static OnboardingStartResponse startOnboarding(final TestContext ctx) throws Exception {
        return startOnboarding(ctx, null);
    }

    private static OnboardingStartResponse startOnboarding(final TestContext ctx, final String clientId) throws Exception {
        return startOnboarding(ctx, clientId, false, null);
    }

    private static OnboardingStartResponse startOnboarding(final TestContext ctx, final String clientId, final boolean shouldUserLookupFail, final String processType) throws Exception {
        ObjectStepLogger stepLogger = new ObjectStepLogger();
        ctx.encryptModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/start");
        Map<String, Object> identification = new LinkedHashMap<>();
        identification.put("clientNumber", clientId != null ? clientId : generateRandomClientId());
        identification.put("birthDate", "1970-03-21");
        // instruction for MockOnboardingProvider#lookupUser(LookupUserRequest) whether to fail
        identification.put("shouldFail", shouldUserLookupFail);
        final OnboardingStartRequest request = OnboardingStartRequest.builder()
                .identification(identification)
                .processType(processType)
                .build();
        executeRequest(ctx, request, stepLogger);

        final EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

        final OnboardingStartResponse response = stepLogger.getItems().stream()
                .filter(item -> "Decrypted Response".equals(item.name()))
                .map(item -> item.object().toString())
                .map(item -> read(ctx.objectMapper, item, new TypeReference<ObjectResponse<OnboardingStartResponse>>() {}))
                .map(ObjectResponse::getResponseObject)
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure().message("Response was not successfully decrypted").build());

        final String processId = response.processId();
        final OnboardingStatus onboardingStatus = response.onboardingStatus();

        assertNotNull(processId);
        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, onboardingStatus);
        return response;
    }

    private static void executeRequest(final TestContext ctx, final Object request, final ObjectStepLogger stepLogger) throws Exception {
        ObjectRequest<Object> objectRequest = new ObjectRequest<>();
        objectRequest.setRequestObject(request);
        byte[] data = ctx.objectMapper.writeValueAsBytes(objectRequest);
        ctx.encryptModel.setData(data);
        new EncryptStep().execute(stepLogger, ctx.encryptModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    private static void onboardingCleanup(final TestContext ctx, final String processId) throws Exception {
        ctx.encryptModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/cleanup");
        OnboardingCleanupRequest requestCleanup = new OnboardingCleanupRequest();
        requestCleanup.setProcessId(processId);
        executeRequest(ctx, requestCleanup, new ObjectStepLogger());
    }

    private static OnboardingStatus getProcessStatus(final TestContext ctx, final String processId) throws Exception {
        ObjectStepLogger stepLogger = new ObjectStepLogger();
        ctx.encryptModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/status");
        OnboardingStatusRequest requestStatus = new OnboardingStatusRequest();
        requestStatus.setProcessId(processId);
        executeRequest(ctx, requestStatus, stepLogger);

        final EciesEncryptedResponse responseStatusOK = (EciesEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(responseStatusOK.getEncryptedData());
        assertNotNull(responseStatusOK.getMac());

        final OnboardingStatusResponse response = stepLogger.getItems().stream()
                .filter(item -> "Decrypted Response".equals(item.name()))
                .map(item -> item.object().toString())
                .map(item -> read(ctx.objectMapper, item, new TypeReference<ObjectResponse<OnboardingStatusResponse>>() {}))
                .map(ObjectResponse::getResponseObject)
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure().message("Response was not successfully decrypted").build());

        final String processIdResponse = response.getProcessId();
        final OnboardingStatus onboardingStatus = response.getOnboardingStatus();

        assertNotNull(processIdResponse);
        return onboardingStatus;
    }

    private static String generateRandomClientId() {
        SecureRandom random = new SecureRandom();
        BigInteger bound = BigInteger.TEN.pow(18).subtract(BigInteger.ONE);
        long number = Math.abs(random.nextLong() % bound.longValue());
        return Long.toString(number);
    }

    private static String createCustomActivation(final TestContext ctx, final String processId, final String otpCode, final String clientId) throws Exception {
        ObjectStepLogger stepLogger = new ObjectStepLogger();
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("processId", processId);
        identityAttributes.put("otpCode", otpCode);
        identityAttributes.put("credentialsType", "ONBOARDING");
        ctx.activationModel.setIdentityAttributes(identityAttributes);
        new CreateActivationStep().execute(stepLogger, ctx.activationModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final ActivationLayer2Response layer2Response = stepLogger.getItems().stream()
                .filter(item -> "Decrypted Layer 2 Response".equals(item.name()))
                .map(item -> (ActivationLayer2Response) item.object())
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure().message("Response was not successfully decrypted").build());

        final String activationId = layer2Response.getActivationId();
        assertNotNull(activationId);
        assertNotNull(layer2Response.getCtrData());
        assertNotNull(layer2Response.getServerPublicKey());

        // Verify activation status - activation was automatically committed
        final GetActivationStatusResponse statusResponseActive = ctx.powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.ACTIVE, statusResponseActive.getActivationStatus());
        assertEquals("mockuser_" + clientId, statusResponseActive.getUserId());
        assertEquals(Collections.singletonList("VERIFICATION_PENDING"), statusResponseActive.getActivationFlags());

        return activationId;
    }

    private static Integer createCustomActivationAssumeFailure(final TestContext ctx, final String processId, final String otpCode) throws Exception {
        ObjectStepLogger stepLogger = new ObjectStepLogger();
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("processId", processId);
        identityAttributes.put("otpCode", otpCode);
        identityAttributes.put("credentialsType", "ONBOARDING");
        ctx.activationModel.setIdentityAttributes(identityAttributes);
        new CreateActivationStep().execute(stepLogger, ctx.activationModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());

        final String response = (String) stepLogger.getResponse().responseObject();
        final ActivationOtpErrorResponse errorResponseOtp = ctx.objectMapper.readValue(response, ActivationOtpErrorResponse.class);
        return errorResponseOtp.getRemainingAttempts();
    }

    private static String getOtpCode(final TestContext ctx, final String processId) throws Exception {
        ObjectStepLogger stepLogger = new ObjectStepLogger();
        ctx.encryptModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/otp/detail");
        OtpDetailRequest requestOtp = new OtpDetailRequest();
        requestOtp.setProcessId(processId);
        requestOtp.setOtpType(OtpType.ACTIVATION);
        executeRequest(ctx, requestOtp, stepLogger);

        final EciesEncryptedResponse responseOtpOK = (EciesEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(responseOtpOK.getEncryptedData());
        assertNotNull(responseOtpOK.getMac());

        final String otpCode = stepLogger.getItems().stream()
                .filter(item -> "Decrypted Response".equals(item.name()))
                .map(item -> item.object().toString())
                .map(item -> read(ctx.objectMapper, item, new TypeReference<ObjectResponse<OtpDetailResponse>>() {}))
                .map(ObjectResponse::getResponseObject)
                .map(OtpDetailResponse::getOtpCode)
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure().message("Response was not successfully decrypted").build());

        assertNotNull(otpCode);
        return otpCode;
    }

    private static <T> T read(final ObjectMapper objectMapper, final String source, final TypeReference<T> type) {
        try {
            final T result = objectMapper.readValue(source, type);
            assertNotNull(result);
            return result;
        } catch (JsonProcessingException e) {
            throw AssertionFailureBuilder.assertionFailure()
                    .message("Unable to parse JSON.")
                    .cause(e)
                    .build();
        }
    }

    public record TestContext(
            PowerAuthClient powerAuthClient,
            PowerAuthTestConfiguration config,
            CreateActivationStepModel activationModel,
            GetStatusStepModel statusModel,
            EncryptStepModel encryptModel,
            ObjectMapper objectMapper,
            ObjectStepLogger stepLogger
    ){}

}
