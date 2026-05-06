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

import com.wultra.app.enrollmentserver.api.model.onboarding.request.*;
import com.wultra.app.enrollmentserver.api.model.onboarding.response.*;
import com.wultra.app.enrollmentserver.model.enumeration.*;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.response.ListActivationFlagsResponse;
import com.wultra.security.powerauth.client.model.response.v3.GetActivationStatusResponse;
import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.model.StepItem;
import com.wultra.security.powerauth.lib.cmd.steps.*;
import com.wultra.security.powerauth.lib.cmd.steps.model.*;
import com.wultra.security.powerauth.model.request.OtpDetailRequest;
import com.wultra.security.powerauth.model.response.OtpDetailResponse;
import com.wultra.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.awaitility.core.ThrowingRunnable;
import org.junit.jupiter.api.AssertionFailureBuilder;
import org.opentest4j.AssertionFailedError;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static java.util.stream.Collectors.toList;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth identity verification test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthIdentityVerificationShared {

    public static final SharedSecretAlgorithm SHARED_SECRET_ALGORITHM_DEFAULT = SharedSecretAlgorithm.EC_P384_ML_L3;

    public static void testSuccessfulIdentityVerificationWithCustomActivation(final TestContext ctx) throws Exception {
        final TestProcessContext processCtx = prepareActivation(ctx);
        final String activationId = processCtx.activationId;
        final String processId = processCtx.processId;

        approveConsent(ctx, processId);
        processDocumentsSynchronous(processCtx, ctx);

        initPresenceCheck(ctx, processId);
        submitPresenceCheck(ctx, processId);
        if (!ctx.config.isSkipResultVerification()) {
            verifyStatusBeforeOtp(ctx);
            verifyOtpCheckSuccessful(ctx, processId);
            verifyProcessFinished(ctx, processId, activationId);
        }

        ctx.powerAuthClient.removeActivation(activationId, "test");
    }

    public static void testSuccessfulIdentityVerificationWithActivationCode(final TestContext ctx) throws Exception {
        final String clientId = generateRandomClientId() + "_async_evaluate";
        final OnboardingStartResponse onboardingStartResponse = startOnboarding(ctx, clientId, "onboarding");
        final String processId = onboardingStartResponse.processId();

        final String activationCode = onboardingStartResponse.activationCode();
        final String temporaryActivationId = finishActivation(ctx, activationCode);

        createToken(ctx);

        final TestProcessContext processContext = new TestProcessContext();
        processContext.processId = processId;
        processContext.activationId = temporaryActivationId;

        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, checkProcessStatus(ctx, processId));

        // skip approveConsent on purpose
        processDocumentsAsynchronous(processContext, ctx);
        approveEvaluation(ctx, processId, clientId);
        assertIdentityVerificationStateWithRetries(ctx,
                new IdentityVerificationState(IdentityVerificationPhase.PRESENCE_CHECK, IdentityVerificationStatus.NOT_INITIALIZED));

        initPresenceCheck(ctx, processId);
        assertEquals(OnboardingStatus.VERIFICATION_IN_PROGRESS, checkProcessStatus(ctx, processId));

        submitPresenceCheck(ctx, processId);
        approveClient(ctx, processId, clientId);
        // skip OTP verification on purpose
        final String targetActivationId = createTargetActivation(ctx, processId);
        verifyProcessFinished(ctx, processId, targetActivationId);

        ctx.powerAuthClient.removeActivation(temporaryActivationId, "test");
        ctx.powerAuthClient.removeActivation(targetActivationId, "test");
    }

    private static void approveEvaluation(final TestContext ctx, final String processId, final String clientId) {
        final RestClient restClient = RestClient.builder()
                .defaultHeaders(h ->
                        h.setBasicAuth(
                                ctx.config.getEnrollmentOnboardingPrivateApiUsername(),
                                ctx.config.getEnrollmentOnboardingPrivateApiPassword()))
                .build();

        final List<String> verificationIds = restClient.get()
                .uri(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/private/test/process/{processId}/identityVerifications", processId)
                .retrieve()
                .body(new ParameterizedTypeReference<>() {});

        assertNotNull(verificationIds);
        assertFalse(verificationIds.isEmpty());

        final String userId = "mockuser_" + clientId; // this is logic of MockOnboardingProvider#userLookup

        final AcknowledgeEvaluationClientRequest request = new AcknowledgeEvaluationClientRequest(
                processId,
                userId,
                verificationIds.get(0),
                AcknowledgeEvaluationClientRequest.EvaluationResult.OK,
                null);

        final AcknowledgeEvaluationClientResponse result = restClient.post()
                .uri(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/private/client/evaluate")
                .contentType(MediaType.APPLICATION_JSON)
                .body(request)
                .retrieve()
                .body(AcknowledgeEvaluationClientResponse.class);

        assertNotNull(result);
        assertEquals(AcknowledgeEvaluationClientResponse.Result.OK, result.result(), "Error message: " + result.resultReason());
    }

    private static void approveClient(final TestContext ctx, final String processId, String clientId) {
        assertIdentityVerificationStateWithRetries(ctx,
                new IdentityVerificationState(IdentityVerificationPhase.ONBOARDING_APPROVAL, IdentityVerificationStatus.IN_PROGRESS));

        final RestClient restClient = RestClient.builder()
                .defaultHeaders(h ->
                        h.setBasicAuth(
                                ctx.config.getEnrollmentOnboardingPrivateApiUsername(),
                                ctx.config.getEnrollmentOnboardingPrivateApiPassword()))
                .build();

        final List<String> verificationIds = restClient.get()
                .uri(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/private/test/process/{processId}/identityVerifications", processId)
                .retrieve()
                .body(new ParameterizedTypeReference<>() {});

        assertNotNull(verificationIds);
        assertFalse(verificationIds.isEmpty());

        final String userId = "mockuser_" + clientId; // this is logic of MockOnboardingProvider#userLookup

        final AcknowledgeApproveClientRequest request = new AcknowledgeApproveClientRequest(
                processId,
                userId,
                verificationIds.get(0),
                AcknowledgeApproveClientRequest.ApprovalResult.OK,
                null);

        final AcknowledgeApproveClientResponse result = restClient.post()
                .uri(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/private/client/approve")
                .contentType(MediaType.APPLICATION_JSON)
                .body(request)
                .retrieve()
                .body(AcknowledgeApproveClientResponse.class);

        assertNotNull(result);
        assertEquals(AcknowledgeApproveClientResponse.Result.OK, result.result(), "Error message: " + result.resultReason());
    }

    private static String createTargetActivation(final TestContext ctx, final String processId) throws Exception {
        assertIdentityVerificationStateWithRetries(ctx,
                new IdentityVerificationState(IdentityVerificationPhase.ACTIVATION_FINISH, IdentityVerificationStatus.IN_PROGRESS));

        final CreateTargetActivationRequest request = CreateTargetActivationRequest.builder()
                .processId(processId)
                .build();

        final ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        ctx.tokenAndEncryptModel.setData(ctx.objectMapper.writeValueAsBytes(new ObjectRequest<>(request)));
        ctx.tokenAndEncryptModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/identity/activation");

        new TokenAndEncryptStep().execute(stepLogger, ctx.tokenAndEncryptModel.toMap());
        assertTrue(stepLogger.getResult().success());

        final String activationCode = stepLogger.getItems().stream()
                .filter(isStepItemDecryptedResponse())
                .map(item -> item.object().toString())
                .map(item -> read(ctx.objectMapper, item, new TypeReference<ObjectResponse<CreateTargetActivationResponse>>() {}))
                .map(ObjectResponse::getResponseObject)
                .map(CreateTargetActivationResponse::activationCode)
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure().message("Response was not successfully decrypted").build());

        assertNotNull(activationCode);
        return finishActivation(ctx, activationCode);
    }

    public static void testSuccessfulIdentityVerificationWithDocumentSubmitV2(final TestContext ctx) throws Exception {
        final String clientId = generateRandomClientId();
        final OnboardingStartResponse onboardingStartResponse = startOnboarding(ctx, clientId, "onboardingSimple");
        final String processId = onboardingStartResponse.processId();

        final String activationCode = onboardingStartResponse.activationCode();
        final String activationId = finishActivation(ctx, activationCode);

        createToken(ctx);

        final TestProcessContext processContext = new TestProcessContext();
        processContext.processId = processId;
        processContext.activationId = activationId;

        assertEquals(OnboardingStatus.ACTIVATION_IN_PROGRESS, checkProcessStatus(ctx, processId));

        processDocumentsV2(processContext, ctx);

        initPresenceCheck(ctx, processId);
        assertEquals(OnboardingStatus.VERIFICATION_IN_PROGRESS, checkProcessStatus(ctx, processId));

        submitPresenceCheck(ctx, processId);

        verifyProcessFinished(ctx, processId, activationId);

        ctx.powerAuthClient.removeActivation(activationId, "test");
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
        model.setResultStatusObject(ctx.activationModel().getResultStatusObject());
        model.setStatusFileName(ctx.config().getStatusFile(version).getAbsolutePath());
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

    private static void processDocumentsSynchronous(final TestProcessContext processCtx, final TestContext ctx) throws Exception {
        processDocuments(processCtx, ctx);
        assertIdentityVerificationStateWithRetries(ctx,
                new IdentityVerificationState(IdentityVerificationPhase.PRESENCE_CHECK, IdentityVerificationStatus.NOT_INITIALIZED));
    }

    private static void processDocumentsAsynchronous(final TestProcessContext processCtx, final TestContext ctx) throws Exception {
        processDocuments(processCtx, ctx);
        assertIdentityVerificationStateWithRetries(ctx,
                new IdentityVerificationState(IdentityVerificationPhase.CLIENT_EVALUATION, IdentityVerificationStatus.IN_PROGRESS));
    }

    private static void processDocuments(final TestProcessContext processCtx, final TestContext ctx) throws Exception {
        final String activationId = processCtx.activationId;
        final String processId = processCtx.processId;

        initIdentityVerification(ctx, activationId, processId);

        final List<FileSubmit> idCardSubmits = List.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.FRONT),
                FileSubmit.createFrom("images/id_card_mock_back.png", DocumentType.ID_CARD, CardSide.BACK)
        );

        final DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, idCardSubmits);

        submitDocuments(ctx, idCardSubmitRequest);

        assertStatusOfSubmittedDocsWithRetries(ctx, processId, idCardSubmits.size(), DocumentStatus.ACCEPTED);

        assertIdentityVerificationStateWithRetries(ctx,
                new IdentityVerificationState(IdentityVerificationPhase.DOCUMENT_UPLOAD, IdentityVerificationStatus.IN_PROGRESS));

        final List<FileSubmit> drivingLicenseSubmits = List.of(
                FileSubmit.createFrom("images/driving_license_mock_front.png", DocumentType.DRIVING_LICENSE, CardSide.FRONT)
        );
        final DocumentSubmitRequest driveLicenseSubmitRequest = createDocumentSubmitRequest(processId, drivingLicenseSubmits);
        submitDocuments(ctx, driveLicenseSubmitRequest);

        assertStatusOfSubmittedDocsWithRetries(ctx, processId, idCardSubmits.size() + drivingLicenseSubmits.size(), DocumentStatus.ACCEPTED);
    }

    private static void processDocumentsV2(final TestProcessContext processCtx, final TestContext ctx) throws Exception {
        final String activationId = processCtx.activationId;
        final String processId = processCtx.processId;

        initIdentityVerification(ctx, activationId, processId);

        final var idCardSubmitRequest = DocumentSubmitV2Request.builder()
                .processId(processId)
                .documents(List.of(
                        DocumentSubmitV2Request.Document.builder()
                                .type(DocumentType.ID_CARD)
                                .side(CardSide.FRONT)
                                .filename("images/id_card_mock_front.png")
                                .data(readFileContentAsBase64("images/id_card_mock_front.png"))
                                .build(),
                        DocumentSubmitV2Request.Document.builder()
                                .type(DocumentType.ID_CARD)
                                .side(CardSide.BACK)
                                .filename("images/id_card_mock_back.png")
                                .data(readFileContentAsBase64("images/id_card_mock_back.png"))
                                .build()
                ))
                .build();

        submitDocumentsV2(ctx, idCardSubmitRequest);

        final var expectedDocumentCount = new AtomicInteger(idCardSubmitRequest.documents().size());
        assertStatusOfSubmittedDocsWithRetries(ctx, processId, expectedDocumentCount.get(), DocumentStatus.ACCEPTED);

        assertIdentityVerificationStateWithRetries(ctx,
                new IdentityVerificationState(IdentityVerificationPhase.DOCUMENT_UPLOAD, IdentityVerificationStatus.IN_PROGRESS));

        final var driveLicenseSubmitRequest = DocumentSubmitV2Request.builder()
                .processId(processId)
                .documents(List.of(
                        DocumentSubmitV2Request.Document.builder()
                                .type(DocumentType.DRIVING_LICENSE)
                                .side(CardSide.FRONT)
                                .filename("images/driving_license_mock_front.png")
                                .data(readFileContentAsBase64("images/driving_license_mock_front.png"))
                                .build()
                ))
                .build();

        submitDocumentsV2(ctx, driveLicenseSubmitRequest);

        expectedDocumentCount.getAndAdd(driveLicenseSubmitRequest.documents().size());
        assertStatusOfSubmittedDocsWithRetries(ctx, processId, expectedDocumentCount.get(), DocumentStatus.ACCEPTED);

        assertIdentityVerificationStateWithRetries(ctx,
                new IdentityVerificationState(IdentityVerificationPhase.PRESENCE_CHECK, IdentityVerificationStatus.NOT_INITIALIZED));
    }

    private static String readFileContentAsBase64(final String fileName) throws IOException {
        final var file = new ClassPathResource(fileName).getFile();
        final var fileBytes = Files.readAllBytes(file.toPath());
        return Base64.getEncoder().encodeToString(fileBytes);
    }

    public static void testScaFailedPresenceCheck(final TestContext ctx) throws Exception {
        // instruction for WultraMockPresenceCheckProvider#getResult(OwnerId, SessionInfo) to fail
        final TestProcessContext processCtx = prepareActivation(ctx, "_PRESENCE_CHECK_REJECTED");
        final String activationId = processCtx.activationId;
        final String processId = processCtx.processId;

        approveConsent(ctx, processId);
        processDocumentsSynchronous(processCtx, ctx);

        initPresenceCheck(ctx, processId);
        submitPresenceCheck(ctx, processId);
        if (!ctx.config.isSkipResultVerification()) {
            verifyStatusBeforeOtp(ctx);
            verifyOtpCheckFailed(ctx, processId, IdentityVerificationPhase.PRESENCE_CHECK);
            assertIdentityVerificationStateWithRetries(ctx,
                    new IdentityVerificationState(IdentityVerificationPhase.PRESENCE_CHECK, IdentityVerificationStatus.NOT_INITIALIZED));
            verifyProcessNotFinished(ctx, processId);
        }

        ctx.powerAuthClient.removeActivation(activationId, "test");
    }

    public static void testScaFailedOtpCheck(final TestContext ctx) throws Exception {
        final TestProcessContext processCtx = prepareActivation(ctx);
        final String activationId = processCtx.activationId;
        final String processId = processCtx.processId;

        approveConsent(ctx, processId);
        processDocumentsSynchronous(processCtx, ctx);

        initPresenceCheck(ctx, processId);
        submitPresenceCheck(ctx, processId);
        if (!ctx.config.isSkipResultVerification()) {
            verifyStatusBeforeOtp(ctx);
            verifyOtpCheckFailedInvalidCode(ctx, processId, IdentityVerificationPhase.OTP_VERIFICATION);
            assertIdentityVerificationStateWithRetries(ctx,
                    new IdentityVerificationState(IdentityVerificationPhase.OTP_VERIFICATION, IdentityVerificationStatus.VERIFICATION_PENDING));
            verifyProcessNotFinished(ctx, processId);
        }

        ctx.powerAuthClient.removeActivation(activationId, "test");
    }

    public static void testSuccessfulIdentityVerificationWithRestarts(final TestContext ctx) throws Exception {
        final TestProcessContext context = prepareActivation(ctx);
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(ctx, processId);

        for (int i = 0; i < 3; i++) {
            initIdentityVerification(ctx, activationId, processId);

            final List<FileSubmit> idCardSubmits = List.of(
                    FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.FRONT),
                    FileSubmit.createFrom("images/id_card_mock_back.png", DocumentType.ID_CARD, CardSide.BACK)
            );

            DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, idCardSubmits);

            submitDocuments(ctx, idCardSubmitRequest);

            assertStatusOfSubmittedDocsWithRetries(ctx, processId, idCardSubmits.size(), DocumentStatus.ACCEPTED);

            assertIdentityVerificationStateWithRetries(ctx,
                    new IdentityVerificationState(IdentityVerificationPhase.DOCUMENT_UPLOAD, IdentityVerificationStatus.IN_PROGRESS));

            final List<FileSubmit> drivingLicenseSubmits = List.of(
                    FileSubmit.createFrom("images/driving_license_mock_front.png", DocumentType.DRIVING_LICENSE, CardSide.FRONT)
            );
            final DocumentSubmitRequest driveLicenseSubmitRequest = createDocumentSubmitRequest(processId, drivingLicenseSubmits);
            submitDocuments(ctx, driveLicenseSubmitRequest);

            assertStatusOfSubmittedDocsWithRetries(ctx, processId, idCardSubmits.size() + drivingLicenseSubmits.size(), DocumentStatus.ACCEPTED);

            IdentityVerificationState idState =
                    new IdentityVerificationState(IdentityVerificationPhase.PRESENCE_CHECK, IdentityVerificationStatus.NOT_INITIALIZED);
            assertIdentityVerificationStateWithRetries(ctx, idState);

            if (i < 2) {
                // Restart the identity verification in first two walkthroughs, the third walkthrough continues
                cleanupIdentityVerification(ctx, processId);
            }
        }

        initPresenceCheck(ctx, processId);
        submitPresenceCheck(ctx, processId);
        if (!ctx.config.isSkipResultVerification()) {
            verifyStatusBeforeOtp(ctx);
            verifyOtpCheckSuccessful(ctx, processId);
            verifyProcessFinished(ctx, processId, activationId);
        }

        ctx.powerAuthClient.removeActivation(activationId, "test");
    }

    public static void testSuccessfulIdentityVerificationMultipleDocSubmits(final TestContext ctx) throws Exception {
        final TestProcessContext context = prepareActivation(ctx);
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(ctx, processId);
        initIdentityVerification(ctx, activationId, processId);

        final List<FileSubmit> idCardSubmits = List.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.FRONT),
                FileSubmit.createFrom("images/id_card_mock_back.png", DocumentType.ID_CARD, CardSide.BACK)
        );
        DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, idCardSubmits);
        submitDocuments(ctx, idCardSubmitRequest);
        assertStatusOfSubmittedDocsWithRetries(ctx, processId, idCardSubmits.size(), DocumentStatus.ACCEPTED);

        final List<FileSubmit> drivingLicenseSubmits = List.of(
                FileSubmit.createFrom("images/driving_license_mock_front.png", DocumentType.DRIVING_LICENSE, CardSide.FRONT)
        );
        DocumentSubmitRequest driveLicenseSubmitRequest = createDocumentSubmitRequest(processId, drivingLicenseSubmits);
        submitDocuments(ctx, driveLicenseSubmitRequest);

        assertStatusOfSubmittedDocsWithRetries(ctx, processId, idCardSubmits.size() + drivingLicenseSubmits.size(), DocumentStatus.ACCEPTED);

        IdentityVerificationState idState =
                new IdentityVerificationState(IdentityVerificationPhase.PRESENCE_CHECK, IdentityVerificationStatus.NOT_INITIALIZED);
        assertIdentityVerificationStateWithRetries(ctx, idState);

        initPresenceCheck(ctx, processId);
        submitPresenceCheck(ctx, processId);
        if (!ctx.config.isSkipResultVerification()) {
            verifyStatusBeforeOtp(ctx);
            verifyOtpCheckSuccessful(ctx, processId);
            verifyProcessFinished(ctx, processId, activationId);
        }

        ctx.powerAuthClient.removeActivation(activationId, "test");
    }

    public static void testDocSubmitDifferentDocumentType(final TestContext ctx) throws Exception {
        if (!ctx.config.isAdditionalDocSubmitValidationsEnabled()) {
            return;
        }
        final TestProcessContext context = prepareActivation(ctx);
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(ctx, processId);
        initIdentityVerification(ctx, activationId, processId);

        final List<FileSubmit> docSubmits = List.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.DRIVING_LICENSE, CardSide.FRONT)
        );
        DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, docSubmits);
        submitDocuments(ctx, idCardSubmitRequest);

        assertStatusOfSubmittedDocsWithRetries(ctx, processId, docSubmits.size(), DocumentStatus.REJECTED);

        ctx.powerAuthClient.removeActivation(activationId, "test");
    }

    public static void testDocSubmitDifferentCardSide(final TestContext ctx) throws Exception {
        if (!ctx.config.isAdditionalDocSubmitValidationsEnabled()) {
            return;
        }
        final TestProcessContext context = prepareActivation(ctx);
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(ctx, processId);
        initIdentityVerification(ctx, activationId, processId);

        final List<FileSubmit> docSubmits = List.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.BACK)
        );
        DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, docSubmits);
        submitDocuments(ctx, idCardSubmitRequest);

        assertStatusOfSubmittedDocsWithRetries(ctx, processId, docSubmits.size(), DocumentStatus.REJECTED);

        ctx.powerAuthClient.removeActivation(activationId, "test");
    }

    public static void testDocSubmitMaxAttemptsLimit(final TestContext ctx) throws Exception {
        if (!ctx.config.isAdditionalDocSubmitValidationsEnabled()) {
            return;
        }
        final TestProcessContext context = prepareActivation(ctx);
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(ctx, processId);
        initIdentityVerification(ctx, activationId, processId);

        final List<FileSubmit> docSubmits = List.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.DRIVING_LICENSE, CardSide.FRONT)
        );

        final DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, docSubmits);

        for (int i = 0; i < 6; i++) {
            submitDocuments(ctx, idCardSubmitRequest);
            assertStatusOfSubmittedDocsWithRetries(ctx, processId, i + 1, DocumentStatus.REJECTED);
            assertIdentityVerificationStateWithRetries(ctx,
                    new IdentityVerificationState(IdentityVerificationPhase.DOCUMENT_UPLOAD, IdentityVerificationStatus.IN_PROGRESS));
        }

        assertThrows(AssertionError.class, () -> submitDocuments(ctx, idCardSubmitRequest));
        assertIdentityVerificationStateWithRetries(ctx,
                new IdentityVerificationState(null, IdentityVerificationStatus.NOT_INITIALIZED));

        ctx.powerAuthClient.removeActivation(activationId, "test");
    }

    public static void testIdentityVerificationNotDocumentPhotos(final TestContext ctx) throws Exception {
        final TestProcessContext context = prepareActivation(ctx);
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(ctx, processId);
        initIdentityVerification(ctx, activationId, processId);

        final List<FileSubmit> invalidDocSubmits = List.of(
                FileSubmit.createFrom("images/random_photo_1.png", DocumentType.ID_CARD, CardSide.FRONT),
                FileSubmit.createFrom("images/random_photo_2.png", DocumentType.ID_CARD, CardSide.BACK)
        );
        DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, invalidDocSubmits);
        submitDocuments(ctx, idCardSubmitRequest);

        assertStatusOfSubmittedDocsWithRetries(ctx, processId, invalidDocSubmits.size(), DocumentStatus.REJECTED);

        ctx.powerAuthClient.removeActivation(activationId, "test");
    }

    public static void testIdentityVerificationCleanup(final TestContext ctx) throws Exception {
        final TestProcessContext context = prepareActivation(ctx);
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(ctx, processId);
        initIdentityVerification(ctx, activationId, processId);

        final List<FileSubmit> idDocSubmits = List.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.FRONT),
                FileSubmit.createFrom("images/id_card_mock_back.png", DocumentType.ID_CARD, CardSide.BACK)
        );
        DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, idDocSubmits);
        submitDocuments(ctx, idCardSubmitRequest);

        cleanupIdentityVerification(ctx, processId);

        ctx.powerAuthClient.removeActivation(activationId, "test");
    }

    public static void testIdentityVerificationMaxAttemptLimit(final TestContext ctx) throws Exception {
        final TestProcessContext context = prepareActivation(ctx);
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(ctx, processId);
        for (int i = 0; i < 5; i++) {
            initIdentityVerification(ctx, activationId, processId);

            final List<FileSubmit> idDocSubmits = List.of(
                    FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.FRONT),
                    FileSubmit.createFrom("images/id_card_mock_back.png", DocumentType.ID_CARD, CardSide.BACK)
            );
            DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, idDocSubmits);
            submitDocuments(ctx, idCardSubmitRequest);

            if (i < 4) {
                cleanupIdentityVerification(ctx, processId);
            } else {
                // Check that cleanupIdentityVerification method fails due to non-200 response
                assertThrows(AssertionError.class, () -> cleanupIdentityVerification(ctx, processId));
            }
        }

        ctx.powerAuthClient.removeActivation(activationId, "test");
    }

    public static void initDocumentVerificationSdkTest(final TestContext ctx) throws Exception {
        final TestProcessContext context = prepareActivation(ctx);
        final String processId = context.processId;

        approveConsent(ctx, processId);
        initIdentityVerification(ctx, context.activationId, processId);

        Map<String, String> attributes = new HashMap<>();
        attributes.put("sdk-init-token", "value");

        DocumentVerificationSdkInitRequest initRequest = new DocumentVerificationSdkInitRequest();
        initRequest.setProcessId(processId);
        initRequest.setAttributes(attributes);
        ObjectStepLogger stepLogger = new ObjectStepLogger();
        ctx.signatureModel.setData(ctx.objectMapper.writeValueAsBytes(new ObjectRequest<>(initRequest)));
        ctx.signatureModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/identity/document/init-sdk");
        ctx.signatureModel.setResourceId("/api/identity/document/init-sdk");

        new AuthAndEncryptStep().execute(stepLogger, ctx.signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
        final EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());
    }

    public static void testFailedScaOtpMaxFailedAttemptsIdentityRestart(final TestContext ctx) throws Exception {
        final TestProcessContext processCtx = prepareActivation(ctx);
        final String activationId = processCtx.activationId;
        final String processId = processCtx.processId;

        approveConsent(ctx, processId);
        processDocumentsSynchronous(processCtx, ctx);

        initPresenceCheck(ctx, processId);
        submitPresenceCheck(ctx, processId);
        if (!ctx.config.isSkipResultVerification()) {
            for (int i = 0; i < 4; i++) {
                verifyStatusBeforeOtp(ctx);
                verifyOtpCheckFailedInvalidCode(ctx, processId, IdentityVerificationPhase.OTP_VERIFICATION);
            }
            // Verify restart of identity verification
            verifyStatusBeforeOtp(ctx);
            verifyOtpCheckFailedInvalidCode(ctx, processId, null);
        }

        ctx.powerAuthClient.removeActivation(activationId, "test");
    }

    public static void testErrorScoreLimit(final TestContext ctx) throws Exception {
        // 4 * invalid OTP (2) + reset(3) + 3 * invalid OTP (2)  = 17 > score limit(15)
        final TestProcessContext processCtx = prepareActivation(ctx);
        final String activationId = processCtx.activationId;
        final String processId = processCtx.processId;

        approveConsent(ctx, processId);

        // 1st identity verification
        processDocumentsSynchronous(processCtx, ctx);

        initPresenceCheck(ctx, processId);
        submitPresenceCheck(ctx, processId);
        if (!ctx.config.isSkipResultVerification()) {
            for (int i = 0; i < 4; i++) {
                verifyStatusBeforeOtp(ctx);
                verifyOtpCheckFailedInvalidCode(ctx, processId, IdentityVerificationPhase.OTP_VERIFICATION);
            }
            // Verify restart of identity verification
            verifyStatusBeforeOtp(ctx);
            verifyOtpCheckFailedInvalidCode(ctx, processId, null);
        }

        // 2nd identity verification
        processDocumentsSynchronous(processCtx, ctx);

        initPresenceCheck(ctx, processId);
        submitPresenceCheck(ctx, processId);
        if (!ctx.config.isSkipResultVerification()) {
            for (int i = 0; i < 3; i++) {
                verifyStatusBeforeOtp(ctx);
                verifyOtpCheckFailedInvalidCode(ctx, processId, IdentityVerificationPhase.OTP_VERIFICATION);
            }
        }

        // Verify failed because of error score
        final OnboardingStatus status = checkProcessStatus(ctx, processId);
        assertEquals(OnboardingStatus.FAILED, status);

        ctx.powerAuthClient.removeActivation(activationId, "test");
    }

    private static TestProcessContext prepareActivation(final TestContext ctx) throws Exception {
        return prepareActivation(ctx, "");
    }

    private static TestProcessContext prepareActivation(final TestContext ctx, final String clientIdPostfix) throws Exception {
        final String clientId = generateRandomClientId() + clientIdPostfix;
        final String processId = startOnboarding(ctx, clientId, null).processId();
        final String activationId = createCustomActivation(ctx, processId, getOtpCode(ctx, processId, OtpType.ACTIVATION), clientId);
        createToken(ctx);

        final TestProcessContext testContext = new TestProcessContext();
        testContext.activationId = activationId;
        testContext.processId = processId;
        return testContext;
    }

    private static OnboardingStartResponse startOnboarding(final TestContext ctx, final String clientId, final String processType) throws Exception {
        ObjectStepLogger stepLogger = ctx.stepLogger;
        ctx.encryptModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/start");
        ctx.encryptModel.setScope("application");
        Map<String, Object> identification = new LinkedHashMap<>();
        identification.put("clientNumber", clientId != null ? clientId : generateRandomClientId());
        identification.put("birthDate", "1970-03-21");
        final OnboardingStartRequest request = OnboardingStartRequest.builder()
                .identification(identification)
                .processType(processType)
                .build();
        executeRequest(request, ctx.encryptModel, stepLogger, ctx.objectMapper);

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

    private static void executeRequest(final Object request, final EncryptStepModel encryptModel, final ObjectStepLogger stepLogger, final ObjectMapper objectMapper) throws Exception {
        ObjectRequest<Object> objectRequest = new ObjectRequest<>();
        objectRequest.setRequestObject(request);
        byte[] data = objectMapper.writeValueAsBytes(objectRequest);
        encryptModel.setData(data);
        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
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

    private static void createToken(final TestContext ctx) throws Exception {
        ObjectStepLogger stepLogger1 = new ObjectStepLogger();
        new CreateTokenStep().execute(stepLogger1, ctx.createTokenModel.toMap());
        assertTrue(stepLogger1.getResult().success());
        assertEquals(200, stepLogger1.getResponse().statusCode());

        String tokenId = null;
        String tokenSecret = null;
        for (StepItem item: stepLogger1.getItems()) {
            if (item.name().equals("Token successfully obtained")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                tokenId = (String) responseMap.get("tokenId");
                tokenSecret = (String) responseMap.get("tokenSecret");
                break;
            }
        }

        assertNotNull(tokenId);
        assertNotNull(tokenSecret);

        ctx.tokenAndEncryptModel.setTokenId(tokenId);
        ctx.tokenAndEncryptModel.setTokenSecret(tokenSecret);

        ctx.tokenModel.setTokenId(tokenId);
        ctx.tokenModel.setTokenSecret(tokenSecret);
    }

    private static String getOtpCode(final TestContext ctx, final String processId, final OtpType otpType) throws Exception {
        ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        ctx.encryptModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/otp/detail");
        ctx.encryptModel.setScope("application");
        OtpDetailRequest requestOtp = new OtpDetailRequest();
        requestOtp.setProcessId(processId);
        requestOtp.setOtpType(otpType);
        executeRequest(requestOtp, ctx.encryptModel, stepLogger, ctx.objectMapper);

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

    private static void initIdentityVerification(final TestContext ctx, final String activationId, final String processId) throws Exception {
        // Check activation flags
        final ListActivationFlagsResponse flagResponse = ctx.powerAuthClient.listActivationFlags(activationId);
        assertEquals(Collections.singletonList("VERIFICATION_PENDING"), flagResponse.getActivationFlags());

        // Initialize identity verification request
        IdentityVerificationInitRequest initRequest = new IdentityVerificationInitRequest();
        initRequest.setProcessId(processId);
        ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        ctx.signatureModel.setData(ctx.objectMapper.writeValueAsBytes(new ObjectRequest<>(initRequest)));
        ctx.signatureModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/identity/init");
        ctx.signatureModel.setResourceId("/api/identity/init");

        new VerifyAuthenticationStep().execute(stepLogger, ctx.signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        // Check activation flags
        ListActivationFlagsResponse flagResponse2 = ctx.powerAuthClient.listActivationFlags(activationId);
        assertEquals(Collections.singletonList("VERIFICATION_IN_PROGRESS"), flagResponse2.getActivationFlags());
    }

    private static void approveConsent(final TestContext ctx, final String processId) throws Exception {
        final OnboardingConsentTextRequest textRequest = new OnboardingConsentTextRequest();
        textRequest.setProcessId(processId);
        textRequest.setConsentType("GDPR");

        ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        ctx.tokenModel.setData(ctx.objectMapper.writeValueAsBytes(new ObjectRequest<>(textRequest)));
        ctx.tokenModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/identity/consent/text");

        new VerifyTokenStep().execute(stepLogger, ctx.tokenModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final String consentText = convertValue(ctx.objectMapper, stepLogger, new TypeReference<ObjectResponse<OnboardingConsentTextResponse>>() { })
                .getConsentText();
        assertThat(consentText, startsWith("<html>"));

        final OnboardingConsentApprovalRequest approvalRequest = new OnboardingConsentApprovalRequest();
        approvalRequest.setProcessId(processId);
        approvalRequest.setConsentType("GDPR");
        approvalRequest.setApproved(true);

        stepLogger = new ObjectStepLogger(System.out);
        ctx.signatureModel.setData(ctx.objectMapper.writeValueAsBytes(new ObjectRequest<>(approvalRequest)));
        ctx.signatureModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/identity/consent/approve");
        ctx.signatureModel.setResourceId("/api/identity/consent/approve");

        new VerifyAuthenticationStep().execute(stepLogger, ctx.signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    private static Predicate<StepItem> isStepItemDecryptedResponse() {
        return stepItem -> "Decrypted Response".equals(stepItem.name());
    }

    private static <T> T safeReadValue(final ObjectMapper objectMapper, final String value, final TypeReference<T> typeReference) {
        try {
            return objectMapper.readValue(value, typeReference);
        } catch (JacksonException e) {
            fail("Unable to read json", e);
            return null;
        }
    }

    private static <T> T convertValue(final ObjectMapper objectMapper, final ObjectStepLogger stepLogger, final TypeReference<ObjectResponse<T>> typeReference) {
        final Object value = stepLogger.getResponse().responseObject();
        return objectMapper.convertValue(value, typeReference).getResponseObject();
    }

    private static DocumentSubmitRequest createDocumentSubmitRequest(String processId, List<FileSubmit> fileSubmits)
            throws IOException {
        DocumentSubmitRequest submitRequest = new DocumentSubmitRequest();
        submitRequest.setProcessId(processId);
        List<DocumentSubmitRequest.DocumentMetadata> allMetadata = new ArrayList<>();
        fileSubmits.forEach(fileSubmit -> {
            DocumentSubmitRequest.DocumentMetadata metadata = new DocumentSubmitRequest.DocumentMetadata();
            metadata.setFilename(fileSubmit.file.getName());
            metadata.setSide(fileSubmit.getCardSide());
            metadata.setType(fileSubmit.getDocumentType());
            allMetadata.add(metadata);
        });
        submitRequest.setDocuments(allMetadata);
        submitRequest.setResubmit(false);

        // Add zipped request data
        final List<File> files = fileSubmits.stream()
                .map(FileSubmit::getFile)
                .collect(toList());
        byte[] zippedFiles = toZipBytes(files);
        submitRequest.setData(zippedFiles);

        return submitRequest;
    }

    private static void submitDocuments(final TestContext ctx, final DocumentSubmitRequest submitRequest) throws Exception {
        ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        ctx.tokenAndEncryptModel.setData(ctx.objectMapper.writeValueAsBytes(new ObjectRequest<>(submitRequest)));
        ctx.tokenAndEncryptModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/identity/document/submit");

        new TokenAndEncryptStep().execute(stepLogger, ctx.tokenAndEncryptModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final EciesEncryptedResponse response = (EciesEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(response.getEncryptedData());
        assertNotNull(response.getMac());
    }

    private static void submitDocumentsV2(final TestContext ctx, final DocumentSubmitV2Request submitRequest) throws Exception {
        final var stepLogger = new ObjectStepLogger(System.out);
        ctx.tokenAndEncryptModel.setData(ctx.objectMapper.writeValueAsBytes(new ObjectRequest<>(submitRequest)));
        ctx.tokenAndEncryptModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/v2/identity/document/submit");

        new TokenAndEncryptStep().execute(stepLogger, ctx.tokenAndEncryptModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final var response = (EciesEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(response.getEncryptedData());
        assertNotNull(response.getMac());
    }

    private static void assertStatusOfSubmittedDocsWithRetries(final TestContext ctx, final String processId, final int expectedDocumentsCount, final DocumentStatus expectedStatus) throws Exception {
        int assertCounter = 1;
        int assertMaxRetries = ctx.config.getAssertMaxRetries();

        while(assertCounter <= assertMaxRetries) {
            try {
                assertStatusOfSubmittedDocs(ctx, processId, expectedDocumentsCount, expectedStatus);
                break;
            } catch (AssertionFailedError e) {
                if (assertCounter >= assertMaxRetries) {
                    throw e;
                }
            }
            ctx.stepLogger.writeItem("assert-submitted-doc-retry", "Assert failed this time", "Retrying document status assert " + assertCounter, "INFO", null);
            assertCounter++;
            Thread.sleep(ctx.config.getAssertRetryWaitPeriod().toMillis());
        }
    }

    private static void assertIdentityVerificationStateWithRetries(final TestContext ctx, final IdentityVerificationState state) {
        final AtomicInteger attemptCounter = new AtomicInteger(1);

        final ThrowingRunnable assertion = () -> {
            final IdentityVerificationState current = checkIdentityVerificationState(ctx);
            if (!current.equals(state)) {
                ctx.stepLogger.writeItem("assert-identity-verification-status-retry", "Assert failed this time", "Retrying identity verification status assert " + attemptCounter.getAndIncrement(), "INFO", null);
            }
            assertEquals(state, current);
        };

        await()
                .alias("Identity verification status")
                .atMost(ctx.config.getAssertRetryWaitPeriod().multipliedBy(ctx.config.getAssertMaxRetries()))
                .pollInterval(ctx.config.getAssertRetryWaitPeriod())
                .untilAsserted(assertion);
    }

    private static void assertStatusOfSubmittedDocs(final TestContext ctx, final String processId, final int expectedDocumentsCount, final DocumentStatus expectedStatus) throws Exception {
        // Check status of submitted document
        DocumentStatusRequest docStatusRequest = new DocumentStatusRequest();
        docStatusRequest.setProcessId(processId);
        ObjectStepLogger stepLogger = new ObjectStepLogger();
        ctx.tokenModel.setData(ctx.objectMapper.writeValueAsBytes(new ObjectRequest<>(docStatusRequest)));
        ctx.tokenModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/identity/document/status");

        new VerifyTokenStep().execute(stepLogger, ctx.tokenModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final DocumentStatusResponse response = convertValue(ctx.objectMapper, stepLogger, new TypeReference<>() { });
        assertEquals(expectedDocumentsCount, response.getDocuments().size());
        for (int i = 0; i < expectedDocumentsCount; i++) {
            assertEquals(expectedStatus, response.getDocuments().get(i).getStatus());
        }
    }

    private static void initPresenceCheck(final TestContext ctx, final String processId) throws Exception {
        if (ctx.config.isSkipPresenceCheck()) {
            return;
        }
        PresenceCheckInitRequest presenceCheckRequest = new PresenceCheckInitRequest();
        presenceCheckRequest.setProcessId(processId);
        ObjectStepLogger stepLogger = new ObjectStepLogger();
        ctx.signatureModel.setData(ctx.objectMapper.writeValueAsBytes(new ObjectRequest<>(presenceCheckRequest)));
        ctx.signatureModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/identity/presence-check/init");
        ctx.signatureModel.setResourceId("/api/identity/presence-check/init");

        new AuthAndEncryptStep().execute(stepLogger, ctx.signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    private static void submitPresenceCheck(final TestContext ctx, final String processId) throws Exception {
        if (ctx.config.isSkipPresenceCheck()) {
            return;
        }
        final PresenceCheckSubmitRequest presenceCheckRequest = new PresenceCheckSubmitRequest();
        presenceCheckRequest.setProcessId(processId);
        ObjectStepLogger stepLogger = new ObjectStepLogger();
        ctx.signatureModel.setData(ctx.objectMapper.writeValueAsBytes(new ObjectRequest<>(presenceCheckRequest)));
        ctx.signatureModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/identity/presence-check/submit");
        ctx.signatureModel.setResourceId("/api/identity/presence-check/submit");

        new VerifyAuthenticationStep().execute(stepLogger, ctx.signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    private static void verifyStatusBeforeOtp(final TestContext ctx) throws Exception {
        // Presence check should succeed immediately in mock implementation, but in general this can take some time
        boolean verificationComplete = false;
        for (int i = 0; i < 10; i++) {
            IdentityVerificationState idState = checkIdentityVerificationState(ctx);
            if (ctx.config.isSkipOtpVerification() && idState.getStatus() == IdentityVerificationStatus.ACCEPTED) {
                verificationComplete = true;
                break;
            }
            if (!ctx.config.isSkipOtpVerification() && idState.phase == IdentityVerificationPhase.OTP_VERIFICATION && idState.getStatus() == IdentityVerificationStatus.VERIFICATION_PENDING) {
                verificationComplete = true;
                break;
            } else {
                Thread.sleep(1000);
            }
        }
        assertTrue(verificationComplete);
    }

    private static IdentityVerificationState checkIdentityVerificationState(final TestContext ctx) throws Exception {
        IdentityVerificationStatusRequest statusRequest = new IdentityVerificationStatusRequest();
        ObjectStepLogger stepLogger = new ObjectStepLogger();
        ctx.tokenModel.setData(ctx.objectMapper.writeValueAsBytes(new ObjectRequest<>(statusRequest)));
        ctx.tokenModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/identity/status");

        new VerifyTokenStep().execute(stepLogger, ctx.tokenModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
        final IdentityVerificationStatusResponse response = convertValue(ctx.objectMapper, stepLogger, new TypeReference<>() {});
        final IdentityVerificationState idState = new IdentityVerificationState(
                response.getIdentityVerificationPhase(),
                response.getIdentityVerificationStatus());

        assertNotNull(idState);
        assertNotNull(idState.getStatus());
        return idState;
    }

    private static OnboardingStatus checkProcessStatus(final TestContext ctx, final String processId) throws Exception {
        OnboardingStatusRequest statusRequest = new OnboardingStatusRequest();
        statusRequest.setProcessId(processId);
        ObjectStepLogger stepLogger = new ObjectStepLogger();
        ctx.encryptModel.setData(ctx.objectMapper.writeValueAsBytes(new ObjectRequest<>(statusRequest)));
        ctx.encryptModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/status");
        ctx.encryptModel.setScope("application");

        new EncryptStep().execute(stepLogger, ctx.encryptModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final OnboardingStatus status = stepLogger.getItems().stream()
                .filter(item -> "Decrypted Response".equals(item.name()))
                .map(item -> item.object().toString())
                .map(item -> read(ctx.objectMapper, item, new TypeReference<ObjectResponse<OnboardingStatusResponse>>() {}))
                .map(ObjectResponse::getResponseObject)
                .map(OnboardingStatusResponse::getOnboardingStatus)
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure().message("Response was not successfully decrypted").build());

        assertNotNull(status);
        return status;
    }

    private static void verifyOtpCheckFailed(final TestContext ctx, final String processId, final IdentityVerificationPhase allowedPhase) throws Exception {
        final String otpCode = getOtpCode(ctx, processId, OtpType.USER_VERIFICATION);
        verifyOtpCheck(ctx, processId, false, otpCode, allowedPhase);
    }

    private static void verifyOtpCheckFailedInvalidCode(final TestContext ctx, final String processId, final IdentityVerificationPhase allowedPhase) throws Exception {
        final String otpCode = "invalid";
        verifyOtpCheck(ctx, processId, false, otpCode, allowedPhase);
    }

    private static void verifyOtpCheckSuccessful(final TestContext ctx, String processId) throws Exception {
        final String otpCode = getOtpCode(ctx, processId, OtpType.USER_VERIFICATION);
        verifyOtpCheck(ctx, processId, true, otpCode, IdentityVerificationPhase.COMPLETED);
    }

    private static void verifyOtpCheck(final TestContext ctx, final String processId, final boolean expectedResult, final String otpCode, final IdentityVerificationPhase allowedPhase) throws Exception {
        if (ctx.config.isSkipOtpVerification()) {
            return;
        }
        boolean otpVerified = false;
        boolean verificationComplete = false;
        IdentityVerificationState idState = checkIdentityVerificationState(ctx);
        if (idState.getStatus() == IdentityVerificationStatus.VERIFICATION_PENDING) {
            IdentityVerificationOtpVerifyRequest otpVerifyRequest = new IdentityVerificationOtpVerifyRequest();
            otpVerifyRequest.setProcessId(processId);
            otpVerifyRequest.setOtpCode(otpCode);
            ObjectStepLogger stepLogger = new ObjectStepLogger();
            ctx.encryptModel.setData(ctx.objectMapper.writeValueAsBytes(new ObjectRequest<>(otpVerifyRequest)));
            ctx.encryptModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/identity/otp/verify");
            ctx.encryptModel.setScope("activation");
            new EncryptStep().execute(stepLogger, ctx.encryptModel.toMap());
            assertTrue(stepLogger.getResult().success());
            assertEquals(200, stepLogger.getResponse().statusCode());

            otpVerified = stepLogger.getItems().stream()
                    .filter(isStepItemDecryptedResponse())
                    .map(StepItem::object)
                    .map(Object::toString)
                    .map(it -> safeReadValue(ctx.objectMapper, it, new TypeReference<ObjectResponse<OtpVerifyResponse>>() {}))
                    .filter(Objects::nonNull)
                    .map(ObjectResponse::getResponseObject)
                    .map(OtpVerifyResponse::isVerified)
                    .findFirst()
                    .orElse(false);

            // Force status refresh
            idState = checkIdentityVerificationState(ctx);
        }
        if (idState.getStatus() == IdentityVerificationStatus.ACCEPTED) {
            verificationComplete = true;
        } else if (idState.getPhase() == allowedPhase) {
            verificationComplete = true;
        }
        assertTrue(verificationComplete, "Verification should complete, either valid OTP or phase set to " + allowedPhase);
        assertEquals(expectedResult, otpVerified);
    }

    private static void cleanupIdentityVerification(final TestContext ctx, final String processId) throws Exception {
        IdentityVerificationCleanupRequest cleanupRequest = new IdentityVerificationCleanupRequest();
        cleanupRequest.setProcessId(processId);
        ObjectStepLogger stepLogger = new ObjectStepLogger();
        ctx.signatureModel.setData(ctx.objectMapper.writeValueAsBytes(new ObjectRequest<>(cleanupRequest)));
        ctx.signatureModel.setUriString(ctx.config.getEnrollmentOnboardingServiceUrl() + "/api/identity/cleanup");
        ctx.signatureModel.setResourceId("/api/identity/cleanup");

        new VerifyAuthenticationStep().execute(stepLogger, ctx.signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    private static void verifyProcessFinished(final TestContext ctx, final String processId, final String activationId) throws Exception {
        final AtomicInteger attemptCounter = new AtomicInteger(1);

        final Callable<Boolean> processStatusEvaluator = () -> {
            final OnboardingStatus status = checkProcessStatus(ctx, processId);
            if (status == OnboardingStatus.FINISHED) {
                return true;
            }
            ctx.stepLogger.writeItem("assert-process-status-retry", "Assert failed this time", "Retrying process status assert " + attemptCounter.getAndIncrement(), "INFO", null);
            return false;
        };

        await()
                .alias("Process did not finish within the expected timeout")
                .atMost(ctx.config.getAssertRetryWaitPeriod().multipliedBy(ctx.config.getAssertMaxRetries()))
                .pollInterval(ctx.config.getAssertRetryWaitPeriod())
                .until(processStatusEvaluator);

        // Check activation flags
        ListActivationFlagsResponse flagResponse3 = ctx.powerAuthClient.listActivationFlags(activationId);
        assertTrue(flagResponse3.getActivationFlags().isEmpty());
    }

    private static void verifyProcessNotFinished(final TestContext ctx, final String processId) throws Exception {
        final OnboardingStatus status = checkProcessStatus(ctx, processId);
        assertNotEquals(OnboardingStatus.FINISHED, status, "Process must NOT be finished");
    }

    /**
     * @return Bytes of zipped files
     */
    private static byte[] toZipBytes(List<File> files) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(baos);
        for (File file : files) {
            ZipEntry entry = new ZipEntry(file.getName());
            byte[] data = Files.readAllBytes(file.toPath());
            zos.putNextEntry(entry);
            zos.write(data, 0, data.length);
            zos.closeEntry();
        }
        baos.close();
        return baos.toByteArray();
    }

    @Getter
    private static class FileSubmit {

        private final File file;

        private final DocumentType documentType;

        private final CardSide cardSide;

        private FileSubmit(File file, DocumentType documentType, CardSide cardSide) {
            this.file = file;
            this.documentType = documentType;
            this.cardSide = cardSide;
        }

        static FileSubmit createFrom(String filePath, DocumentType documentType, CardSide cardSide)
            throws IOException {
            File file = new ClassPathResource(filePath).getFile();
            return new FileSubmit(file, documentType, cardSide);
        }

    }

    public record TestContext(
        PowerAuthClient powerAuthClient,
        PowerAuthTestConfiguration config,
        CreateActivationStepModel activationModel,
        EncryptStepModel encryptModel,
        VerifyAuthenticationStepModel signatureModel,
        CreateTokenStepModel createTokenModel,
        TokenAndEncryptStepModel tokenAndEncryptModel,
        VerifyTokenStepModel tokenModel,
        ObjectMapper objectMapper,
        ObjectStepLogger stepLogger
    ){}

    @AllArgsConstructor
    @EqualsAndHashCode
    @Getter
    @ToString
    private static class IdentityVerificationState {

        private IdentityVerificationPhase phase;

        private IdentityVerificationStatus status;

    }

    private static class TestProcessContext {
        private String activationId;
        private String processId;
    }

    private static <T> T read(final ObjectMapper objectMapper, final String source, final TypeReference<T> type) {
        try {
            final T result = objectMapper.readValue(source, type);
            assertNotNull(result);
            return result;
        } catch (JacksonException e) {
            throw AssertionFailureBuilder.assertionFailure()
                    .message("Unable to parse JSON.")
                    .cause(e)
                    .build();
        }
    }

}
