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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.common.collect.ImmutableList;
import com.wultra.app.enrollmentserver.api.model.onboarding.request.*;
import com.wultra.app.enrollmentserver.api.model.onboarding.response.*;
import com.wultra.app.enrollmentserver.api.model.onboarding.response.data.DocumentMetadataResponseDto;
import com.wultra.app.enrollmentserver.model.enumeration.*;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.v3.ActivationStatus;
import com.wultra.security.powerauth.client.v3.GetActivationStatusResponse;
import com.wultra.security.powerauth.client.v3.ListActivationFlagsResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.model.request.OtpDetailRequest;
import com.wultra.security.powerauth.model.response.OtpDetailResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.*;
import io.getlime.security.powerauth.lib.cmd.steps.v3.*;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opentest4j.AssertionFailedError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.*;
import java.util.function.Predicate;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static java.util.stream.Collectors.toList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthIdentityVerificationTest {

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private EncryptStepModel encryptModel;
    private VerifySignatureStepModel signatureModel;
    private TokenAndEncryptStepModel tokenAndEncryptModel;
    private CreateActivationStepModel activationModel;
    private CreateTokenStepModel createTokenModel;
    private ObjectStepLogger stepLogger;

    private final ObjectMapper objectMapper = new ObjectMapper().disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

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
        // Create temp status file
        File tempStatusFile = File.createTempFile("pa_status_v31", ".json");

        // Create result status object
        JSONObject resultStatusObject = new JSONObject();

        encryptModel = new EncryptStepModel();
        encryptModel.setApplicationKey(config.getApplicationKey());
        encryptModel.setApplicationSecret(config.getApplicationSecret());
        encryptModel.setMasterPublicKey(config.getMasterPublicKey());
        encryptModel.setHeaders(new HashMap<>());
        encryptModel.setResultStatusObject(resultStatusObject);
        encryptModel.setVersion("3.1");

        signatureModel = new VerifySignatureStepModel();
        signatureModel.setApplicationKey(config.getApplicationKey());
        signatureModel.setApplicationSecret(config.getApplicationSecret());
        signatureModel.setHeaders(new HashMap<>());
        signatureModel.setHttpMethod("POST");
        signatureModel.setPassword(config.getPassword());
        signatureModel.setResultStatusObject(resultStatusObject);
        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION);
        signatureModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        signatureModel.setVersion("3.1");

        tokenAndEncryptModel = new TokenAndEncryptStepModel();
        tokenAndEncryptModel.setApplicationKey(config.getApplicationKey());
        tokenAndEncryptModel.setApplicationSecret(config.getApplicationSecret());
        tokenAndEncryptModel.setHeaders(new HashMap<>());
        tokenAndEncryptModel.setHttpMethod("POST");
        tokenAndEncryptModel.setResultStatusObject(resultStatusObject);
        tokenAndEncryptModel.setVersion("3.1");

        // Model shared among tests
        activationModel = new CreateActivationStepModel();
        activationModel.setActivationName("test v3.1 document verification");
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

        createTokenModel = new CreateTokenStepModel();
        createTokenModel.setApplicationKey(config.getApplicationKey());
        createTokenModel.setApplicationSecret(config.getApplicationSecret());
        createTokenModel.setHeaders(new HashMap<>());
        createTokenModel.setMasterPublicKey(config.getMasterPublicKey());
        createTokenModel.setPassword(config.getPassword());
        createTokenModel.setResultStatusObject(resultStatusObject);
        createTokenModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        createTokenModel.setUriString(config.getEnrollmentServiceUrl());
        createTokenModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION);
        createTokenModel.setVersion("3.1");

        stepLogger = new ObjectStepLogger(System.out);
    }

    @Test
    void testSuccessfulIdentityVerification() throws Exception {
        final TestContext context = prepareActivation();
        final String activationId = context.activationId;
        final String processId = context.processId;

        processDocuments(context);

        initPresenceCheck(processId);
        submitPresenceCheck(processId);
        if (!config.isSkipResultVerification()) {
            verifyStatusBeforeOtp();
            verifyOtpCheckSuccessful(processId);
            verifyProcessFinished(processId, activationId);
        }

        powerAuthClient.removeActivation(activationId, "test");
    }

    private void processDocuments(final TestContext context) throws Exception {
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(processId);
        initIdentityVerification(activationId, processId);

        final List<FileSubmit> idCardSubmits = ImmutableList.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.FRONT),
                FileSubmit.createFrom("images/id_card_mock_back.png", DocumentType.ID_CARD, CardSide.BACK)
        );

        final DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, idCardSubmits);

        submitDocuments(idCardSubmitRequest, idCardSubmits);

        assertStatusOfSubmittedDocsWithRetries(processId, idCardSubmits.size(), DocumentStatus.ACCEPTED);

        assertIdentityVerificationStateWithRetries(
                new IdentityVerificationState(IdentityVerificationPhase.DOCUMENT_UPLOAD, IdentityVerificationStatus.IN_PROGRESS));

        final List<FileSubmit> drivingLicenseSubmits = ImmutableList.of(
                FileSubmit.createFrom("images/driving_license_mock_front.png", DocumentType.DRIVING_LICENSE, CardSide.FRONT)
        );
        final DocumentSubmitRequest driveLicenseSubmitRequest = createDocumentSubmitRequest(processId, drivingLicenseSubmits);
        submitDocuments(driveLicenseSubmitRequest, drivingLicenseSubmits);

        assertStatusOfSubmittedDocsWithRetries(processId, idCardSubmits.size() + drivingLicenseSubmits.size(), DocumentStatus.ACCEPTED);

        assertIdentityVerificationStateWithRetries(
                new IdentityVerificationState(IdentityVerificationPhase.PRESENCE_CHECK, IdentityVerificationStatus.NOT_INITIALIZED));
    }

    @Test
    void testScaFailedPresenceCheck() throws Exception {
        // instruction for WultraMockPresenceCheckProvider#getResult(OwnerId, SessionInfo) to fail
        final TestContext context = prepareActivation("_PRESENCE_CHECK_REJECTED");
        final String activationId = context.activationId;
        final String processId = context.processId;

        processDocuments(context);

        initPresenceCheck(processId);
        submitPresenceCheck(processId);
        if (!config.isSkipResultVerification()) {
            verifyStatusBeforeOtp();
            verifyOtpCheckFailed(processId, IdentityVerificationPhase.PRESENCE_CHECK);
            assertIdentityVerificationStateWithRetries(
                    new IdentityVerificationState(IdentityVerificationPhase.PRESENCE_CHECK, IdentityVerificationStatus.NOT_INITIALIZED));
            verifyProcessNotFinished(processId);
        }

        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void testScaFailedOtpCheck() throws Exception {
        final TestContext context = prepareActivation();
        final String activationId = context.activationId;
        final String processId = context.processId;

        processDocuments(context);

        initPresenceCheck(processId);
        submitPresenceCheck(processId);
        if (!config.isSkipResultVerification()) {
            verifyStatusBeforeOtp();
            verifyOtpCheckFailedInvalidCode(processId, IdentityVerificationPhase.OTP_VERIFICATION);
            assertIdentityVerificationStateWithRetries(
                    new IdentityVerificationState(IdentityVerificationPhase.OTP_VERIFICATION, IdentityVerificationStatus.VERIFICATION_PENDING));
            verifyProcessNotFinished(processId);
        }

        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void testSuccessfulIdentityVerificationWithRestarts() throws Exception {
        final TestContext context = prepareActivation();
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(processId);

        for (int i = 0; i < 3; i++) {
            initIdentityVerification(activationId, processId);

            List<FileSubmit> idCardSubmits = ImmutableList.of(
                    FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.FRONT),
                    FileSubmit.createFrom("images/id_card_mock_back.png", DocumentType.ID_CARD, CardSide.BACK)
            );

            DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, idCardSubmits);

            submitDocuments(idCardSubmitRequest, idCardSubmits);

            assertStatusOfSubmittedDocsWithRetries(processId, idCardSubmits.size(), DocumentStatus.ACCEPTED);

            assertIdentityVerificationStateWithRetries(
                    new IdentityVerificationState(IdentityVerificationPhase.DOCUMENT_UPLOAD, IdentityVerificationStatus.IN_PROGRESS));

            final List<FileSubmit> drivingLicenseSubmits = ImmutableList.of(
                    FileSubmit.createFrom("images/driving_license_mock_front.png", DocumentType.DRIVING_LICENSE, CardSide.FRONT)
            );
            final DocumentSubmitRequest driveLicenseSubmitRequest = createDocumentSubmitRequest(processId, drivingLicenseSubmits);
            submitDocuments(driveLicenseSubmitRequest, drivingLicenseSubmits);

            assertStatusOfSubmittedDocsWithRetries(processId, idCardSubmits.size() + drivingLicenseSubmits.size(), DocumentStatus.ACCEPTED);

            IdentityVerificationState idState =
                    new IdentityVerificationState(IdentityVerificationPhase.PRESENCE_CHECK, IdentityVerificationStatus.NOT_INITIALIZED);
            assertIdentityVerificationStateWithRetries(idState);

            if (i < 2) {
                // Restart the identity verification in first two walkthroughs, the third walkthrough continues
                cleanupIdentityVerification(processId);
            }
        }

        initPresenceCheck(processId);
        submitPresenceCheck(processId);
        if (!config.isSkipResultVerification()) {
            verifyStatusBeforeOtp();
            verifyOtpCheckSuccessful(processId);
            verifyProcessFinished(processId, activationId);
        }

        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void testSuccessfulIdentityVerificationMultipleDocSubmits() throws Exception {
        final TestContext context = prepareActivation();
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(processId);
        initIdentityVerification(activationId, processId);

        List<FileSubmit> idCardSubmits = ImmutableList.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.FRONT),
                FileSubmit.createFrom("images/id_card_mock_back.png", DocumentType.ID_CARD, CardSide.BACK)
        );
        DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, idCardSubmits);
        submitDocuments(idCardSubmitRequest, idCardSubmits);

        List<FileSubmit> drivingLicenseSubmits = ImmutableList.of(
                FileSubmit.createFrom("images/driving_license_mock_front.png", DocumentType.DRIVING_LICENSE, CardSide.FRONT)
        );
        DocumentSubmitRequest driveLicenseSubmitRequest = createDocumentSubmitRequest(processId, drivingLicenseSubmits);
        submitDocuments(driveLicenseSubmitRequest, drivingLicenseSubmits);

        assertStatusOfSubmittedDocsWithRetries(processId, idCardSubmits.size() + drivingLicenseSubmits.size(), DocumentStatus.ACCEPTED);

        IdentityVerificationState idState =
                new IdentityVerificationState(IdentityVerificationPhase.PRESENCE_CHECK, IdentityVerificationStatus.NOT_INITIALIZED);
        assertIdentityVerificationStateWithRetries(idState);

        initPresenceCheck(processId);
        submitPresenceCheck(processId);
        if (!config.isSkipResultVerification()) {
            verifyStatusBeforeOtp();
            verifyOtpCheckSuccessful(processId);
            verifyProcessFinished(processId, activationId);
        }

        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void testDocSubmitDifferentDocumentType() throws Exception {
        if (!config.isAdditionalDocSubmitValidationsEnabled()) {
            return;
        }
        final TestContext context = prepareActivation();
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(processId);
        initIdentityVerification(activationId, processId);

        final List<FileSubmit> docSubmits = ImmutableList.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.DRIVING_LICENSE, CardSide.FRONT)
        );
        DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, docSubmits);
        submitDocuments(idCardSubmitRequest, docSubmits);

        assertStatusOfSubmittedDocsWithRetries(processId, docSubmits.size(), DocumentStatus.REJECTED);

        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void testDocSubmitDifferentCardSide() throws Exception {
        if (!config.isAdditionalDocSubmitValidationsEnabled()) {
            return;
        }
        final TestContext context = prepareActivation();
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(processId);
        initIdentityVerification(activationId, processId);

        List<FileSubmit> docSubmits = ImmutableList.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.BACK)
        );
        DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, docSubmits);
        submitDocuments(idCardSubmitRequest, docSubmits);

        assertStatusOfSubmittedDocsWithRetries(processId, docSubmits.size(), DocumentStatus.REJECTED);

        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void testDocSubmitMaxAttemptsLimit() throws Exception {
        if (!config.isAdditionalDocSubmitValidationsEnabled()) {
            return;
        }
        final TestContext context = prepareActivation();
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(processId);
        initIdentityVerification(activationId, processId);

        final List<FileSubmit> docSubmits = ImmutableList.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.DRIVING_LICENSE, CardSide.FRONT)
        );

        final DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, docSubmits);

        for (int i = 0; i < 6; i++) {
            submitDocuments(idCardSubmitRequest, docSubmits);
            assertStatusOfSubmittedDocsWithRetries(processId, i + 1, DocumentStatus.REJECTED);
            assertIdentityVerificationStateWithRetries(
                    new IdentityVerificationState(IdentityVerificationPhase.DOCUMENT_UPLOAD, IdentityVerificationStatus.IN_PROGRESS));
        }

        assertThrows(AssertionError.class, () -> submitDocuments(idCardSubmitRequest, docSubmits));
        assertIdentityVerificationStateWithRetries(
                new IdentityVerificationState(null, IdentityVerificationStatus.NOT_INITIALIZED));

        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void testIdentityVerificationNotDocumentPhotos() throws Exception {
        final TestContext context = prepareActivation();
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(processId);
        initIdentityVerification(activationId, processId);

        List<FileSubmit> invalidDocSubmits = ImmutableList.of(
                FileSubmit.createFrom("images/random_photo_1.png", DocumentType.ID_CARD, CardSide.FRONT),
                FileSubmit.createFrom("images/random_photo_2.png", DocumentType.ID_CARD, CardSide.BACK)
        );
        DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, invalidDocSubmits);
        submitDocuments(idCardSubmitRequest, invalidDocSubmits);

        assertStatusOfSubmittedDocsWithRetries(processId, invalidDocSubmits.size(), DocumentStatus.ACCEPTED);

        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void testIdentityVerificationCleanup() throws Exception {
        final TestContext context = prepareActivation();
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(processId);
        initIdentityVerification(activationId, processId);

        List<FileSubmit> idDocSubmits = ImmutableList.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.FRONT),
                FileSubmit.createFrom("images/id_card_mock_back.png", DocumentType.ID_CARD, CardSide.BACK)
        );
        DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, idDocSubmits);
        submitDocuments(idCardSubmitRequest, idDocSubmits);

        cleanupIdentityVerification(processId);

        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void testIdentityVerificationMaxAttemptLimit() throws Exception {
        final TestContext context = prepareActivation();
        final String activationId = context.activationId;
        final String processId = context.processId;

        approveConsent(processId);
        for (int i = 0; i < 5; i++) {
            initIdentityVerification(activationId, processId);

            List<FileSubmit> idDocSubmits = ImmutableList.of(
                    FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.FRONT),
                    FileSubmit.createFrom("images/id_card_mock_back.png", DocumentType.ID_CARD, CardSide.BACK)
            );
            DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, idDocSubmits);
            submitDocuments(idCardSubmitRequest, idDocSubmits);

            if (i < 4) {
                cleanupIdentityVerification(processId);
            } else {
                // Check that cleanupIdentityVerification method fails due to non-200 response
                assertThrows(AssertionError.class, () -> cleanupIdentityVerification(processId));
            }
        }

        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void largeUploadTest() throws Exception {
        final TestContext context = prepareActivation();
        final String activationId = context.activationId;
        final String processId = context.processId;

        createToken();

        // Initialize identity verification request
        IdentityVerificationInitRequest initRequest = new IdentityVerificationInitRequest();
        initRequest.setProcessId(processId);
        stepLogger = new ObjectStepLogger(System.out);
        signatureModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(initRequest)));
        signatureModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/identity/init");
        signatureModel.setResourceId("/api/identity/init");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        File imageFront = new ClassPathResource("images/id_card_mock_front_large.png").getFile();

        // ZIP request data for front side
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(baos);
        ZipEntry entry = new ZipEntry(imageFront.getName());
        byte[] data = Files.readAllBytes(imageFront.toPath());
        zos.putNextEntry(entry);
        zos.write(data, 0, data.length);
        zos.closeEntry();
        baos.close();
        byte[] imageZipped = baos.toByteArray();

        // Submit large image for front side
        stepLogger = new ObjectStepLogger(System.out);
        tokenAndEncryptModel.setData(imageZipped);
        tokenAndEncryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/identity/document/upload");

        new TokenAndEncryptStep().execute(stepLogger, tokenAndEncryptModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        String uploadIdFront = null;
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                String responseData = item.getObject().toString();
                ObjectResponse<DocumentUploadResponse> objectResponse = objectMapper.readValue(responseData, new TypeReference<ObjectResponse<DocumentUploadResponse>>() {});
                DocumentUploadResponse response = objectResponse.getResponseObject();
                uploadIdFront = response.getId();
                break;
            }
        }

        assertNotNull(uploadIdFront);

        File imageBack = new ClassPathResource("images/id_card_mock_back_large.png").getFile();

        // ZIP request data for front side
        baos = new ByteArrayOutputStream();
        zos = new ZipOutputStream(baos);
        entry = new ZipEntry(imageBack.getName());
        data = Files.readAllBytes(imageBack.toPath());
        zos.putNextEntry(entry);
        zos.write(data, 0, data.length);
        zos.closeEntry();
        baos.close();
        imageZipped = baos.toByteArray();

        // Submit large image for back side
        stepLogger = new ObjectStepLogger(System.out);
        tokenAndEncryptModel.setData(imageZipped);
        tokenAndEncryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/identity/document/upload");

        new TokenAndEncryptStep().execute(stepLogger, tokenAndEncryptModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        String uploadIdBack = null;
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                String responseData = item.getObject().toString();
                ObjectResponse<DocumentUploadResponse> objectResponse = objectMapper.readValue(responseData, new TypeReference<ObjectResponse<DocumentUploadResponse>>() {});
                DocumentUploadResponse response = objectResponse.getResponseObject();
                uploadIdBack = response.getId();
                break;
            }
        }

        assertNotNull(uploadIdBack);

        List<DocumentSubmitRequest.DocumentMetadata> metadataList = new ArrayList<>();
        DocumentSubmitRequest submitRequest = new DocumentSubmitRequest();
        submitRequest.setProcessId(processId);
        DocumentSubmitRequest.DocumentMetadata metadata = new DocumentSubmitRequest.DocumentMetadata();
        metadata.setSide(CardSide.FRONT);
        metadata.setType(DocumentType.ID_CARD);
        metadata.setFilename("id_card_mock_front_large.png");
        metadata.setUploadId(uploadIdFront);
        metadataList.add(metadata);
        metadata = new DocumentSubmitRequest.DocumentMetadata();
        metadata.setSide(CardSide.BACK);
        metadata.setType(DocumentType.ID_CARD);
        metadata.setFilename("id_card_mock_back_large.png");
        metadata.setUploadId(uploadIdBack);
        metadataList.add(metadata);
        submitRequest.setDocuments(metadataList);
        submitRequest.setResubmit(false);

        // Submit ID card
        stepLogger = new ObjectStepLogger(System.out);
        tokenAndEncryptModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(submitRequest)));
        tokenAndEncryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/identity/document/submit");

        new TokenAndEncryptStep().execute(stepLogger, tokenAndEncryptModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        String documentId = null;
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                String responseData = item.getObject().toString();
                ObjectResponse<DocumentSubmitResponse> objectResponse = objectMapper.readValue(responseData, new TypeReference<ObjectResponse<DocumentSubmitResponse>>() {});
                DocumentSubmitResponse response = objectResponse.getResponseObject();
                assertEquals(2, response.getDocuments().size());
                DocumentMetadataResponseDto doc1 = response.getDocuments().get(0);
                documentId = doc1.getId();
                assertNotNull(documentId);
                // TODO - check that this state is correct, I would expect that submitted document is in VERIFICATION_PENDING
                // state for synchronous processing, which is not sent at the moment
                assertEquals(DocumentStatus.UPLOAD_IN_PROGRESS, doc1.getStatus());
                break;
            }
        }
        assertNotNull(documentId);

        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void initDocumentVerificationSdkTest() throws Exception {
        final TestContext context = prepareActivation();
        final String processId = context.processId;

        initIdentityVerification(context.activationId, processId);

        Map<String, String> attributes = new HashMap<>();
        attributes.put("sdk-init-token", "value");

        DocumentVerificationSdkInitRequest initRequest = new DocumentVerificationSdkInitRequest();
        initRequest.setProcessId(processId);
        initRequest.setAttributes(attributes);
        stepLogger = new ObjectStepLogger(System.out);
        signatureModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(initRequest)));
        signatureModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/identity/document/init-sdk");
        signatureModel.setResourceId("/api/identity/document/init-sdk");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
        EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger.getResponse().getResponseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());
    }

    @Test
    void testFailedScaOtpMaxFailedAttemptsIdentityRestart() throws Exception {
        final TestContext context = prepareActivation();
        final String activationId = context.activationId;
        final String processId = context.processId;

        processDocuments(context);

        initPresenceCheck(processId);
        submitPresenceCheck(processId);
        if (!config.isSkipResultVerification()) {
            for (int i = 0; i < 4; i++) {
                verifyStatusBeforeOtp();
                verifyOtpCheckFailedInvalidCode(processId, IdentityVerificationPhase.OTP_VERIFICATION);
            }
            // Verify restart of identity verification
            verifyStatusBeforeOtp();
            verifyOtpCheckFailedInvalidCode(processId, null);
        }

        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void testErrorScoreLimit() throws Exception {
        // 4 * invalid OTP (2) + reset(3) + 3 * invalid OTP (2)  = 17 > score limit(15)
        final TestContext context = prepareActivation();
        final String activationId = context.activationId;
        final String processId = context.processId;

        // 1st identity verification
        processDocuments(context);

        initPresenceCheck(processId);
        submitPresenceCheck(processId);
        if (!config.isSkipResultVerification()) {
            for (int i = 0; i < 4; i++) {
                verifyStatusBeforeOtp();
                verifyOtpCheckFailedInvalidCode(processId, IdentityVerificationPhase.OTP_VERIFICATION);
            }
            // Verify restart of identity verification
            verifyStatusBeforeOtp();
            verifyOtpCheckFailedInvalidCode(processId, null);
        }

        // 2nd identity verification
        processDocuments(context);

        initPresenceCheck(processId);
        submitPresenceCheck(processId);
        if (!config.isSkipResultVerification()) {
            for (int i = 0; i < 3; i++) {
                verifyStatusBeforeOtp();
                verifyOtpCheckFailedInvalidCode(processId, IdentityVerificationPhase.OTP_VERIFICATION);
            }
        }

        // Verify failed because of error score
        final OnboardingStatus status = checkProcessStatus(processId);
        assertEquals(OnboardingStatus.FAILED, status);

        powerAuthClient.removeActivation(activationId, "test");
    }

    private TestContext prepareActivation() throws Exception {
        return prepareActivation("");
    }

    private TestContext prepareActivation(final String clientIdPostfix) throws Exception {
        String clientId = generateRandomClientId() + clientIdPostfix;
        String processId = startOnboarding(clientId);
        String activationId = createCustomActivation(processId, getOtpCode(processId, OtpType.ACTIVATION), clientId);
        createToken();

        final TestContext testContext = new TestContext();
        testContext.activationId = activationId;
        testContext.processId = processId;
        return testContext;
    }

    private String startOnboarding(final String clientId) throws Exception {
        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/start");
        encryptModel.setScope("application");
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
        identityAttributes.put("credentialsType", "ONBOARDING");
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

    private void createToken() throws Exception {
        stepLogger = new ObjectStepLogger(System.out);
        ObjectStepLogger stepLogger1 = new ObjectStepLogger();
        new CreateTokenStep().execute(stepLogger1, createTokenModel.toMap());
        assertTrue(stepLogger1.getResult().isSuccess());
        assertEquals(200, stepLogger1.getResponse().getStatusCode());

        String tokenId = null;
        String tokenSecret = null;
        for (StepItem item: stepLogger1.getItems()) {
            if (item.getName().equals("Token successfully obtained")) {
                Map<String, Object> responseMap = (Map<String, Object>) item.getObject();
                tokenId = (String) responseMap.get("tokenId");
                tokenSecret = (String) responseMap.get("tokenSecret");
                break;
            }
        }

        assertNotNull(tokenId);
        assertNotNull(tokenSecret);
        tokenAndEncryptModel.setTokenId(tokenId);
        tokenAndEncryptModel.setTokenSecret(tokenSecret);
    }

    private String getOtpCode(String processId, OtpType otpType) throws Exception {
        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/otp/detail");
        encryptModel.setScope("application");
        OtpDetailRequest requestOtp = new OtpDetailRequest();
        requestOtp.setProcessId(processId);
        requestOtp.setOtpType(otpType);
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

    private void initIdentityVerification(String activationId, String processId) throws Exception {
        // Check activation flags
        ListActivationFlagsResponse flagResponse = powerAuthClient.listActivationFlags(activationId);
        assertEquals(Collections.singletonList("VERIFICATION_PENDING"), flagResponse.getActivationFlags());

        // Initialize identity verification request
        IdentityVerificationInitRequest initRequest = new IdentityVerificationInitRequest();
        initRequest.setProcessId(processId);
        stepLogger = new ObjectStepLogger(System.out);
        signatureModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(initRequest)));
        signatureModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/identity/init");
        signatureModel.setResourceId("/api/identity/init");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        // Check activation flags
        ListActivationFlagsResponse flagResponse2 = powerAuthClient.listActivationFlags(activationId);
        assertEquals(Collections.singletonList("VERIFICATION_IN_PROGRESS"), flagResponse2.getActivationFlags());
    }

    private void approveConsent(final String processId) throws Exception {
        final OnboardingConsentTextRequest textRequest = new OnboardingConsentTextRequest();
        textRequest.setProcessId(processId);
        textRequest.setConsentType("GDPR");

        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(textRequest)));
        encryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/identity/consent/text");
        encryptModel.setScope("activation");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        final String consentText = stepLogger.getItems().stream()
                .filter(isStepItemDecryptedResponse())
                .map(StepItem::getObject)
                .map(Object::toString)
                .map(it -> safeReadValue(it, new TypeReference<ObjectResponse<OnboardingConsentTextResponse>>() { }))
                .filter(Objects::nonNull)
                .map(ObjectResponse::getResponseObject)
                .map(OnboardingConsentTextResponse::getConsentText)
                .findFirst()
                .orElse("error - no consent found");

        assertThat(consentText, startsWith("<html>"));

        final OnboardingConsentApprovalRequest approvalRequest = new OnboardingConsentApprovalRequest();
        approvalRequest.setProcessId(processId);
        approvalRequest.setConsentType("GDPR");
        approvalRequest.setApproved(true);

        stepLogger = new ObjectStepLogger(System.out);
        signatureModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(approvalRequest)));
        signatureModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/identity/consent/approve");
        signatureModel.setResourceId("/api/identity/consent/approve");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
    }

    private Predicate<StepItem> isStepItemDecryptedResponse() {
        return stepItem -> "Decrypted Response".equals(stepItem.getName());
    }

    private <T> T safeReadValue(final String value, final TypeReference<T> typeReference) {
        try {
            return objectMapper.readValue(value, typeReference);
        } catch (JsonProcessingException e) {
            fail("Unable to read json", e);
            return null;
        }
    }

    private DocumentSubmitRequest createDocumentSubmitRequest(String processId, List<FileSubmit> fileSubmits)
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

    private void submitDocuments(DocumentSubmitRequest submitRequest, List<FileSubmit> fileSubmits) throws Exception {
        // Submit ID card
        stepLogger = new ObjectStepLogger(System.out);
        tokenAndEncryptModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(submitRequest)));
        tokenAndEncryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/identity/document/submit");

        new TokenAndEncryptStep().execute(stepLogger, tokenAndEncryptModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        EciesEncryptedResponse responseOtpOK = (EciesEncryptedResponse) stepLogger.getResponse().getResponseObject();
        assertNotNull(responseOtpOK.getEncryptedData());
        assertNotNull(responseOtpOK.getMac());

        // TODO - check that this state is correct, I would expect that submitted document is in VERIFICATION_PENDING
        // state for synchronous processing, which is not sent at the moment
        List<DocumentStatus> expectedStatuses = ImmutableList.of(DocumentStatus.UPLOAD_IN_PROGRESS);
        for (StepItem item : stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                String responseData = item.getObject().toString();
                ObjectResponse<DocumentSubmitResponse> objectResponse =
                        objectMapper.readValue(responseData, new TypeReference<ObjectResponse<DocumentSubmitResponse>>() { });
                DocumentSubmitResponse response = objectResponse.getResponseObject();
                assertEquals(fileSubmits.size(), response.getDocuments().size());
                for (int i = 0; i < fileSubmits.size(); i++) {
                    DocumentMetadataResponseDto doc = response.getDocuments().get(i);
                    assertNotNull(doc.getId());
                    assertTrue(expectedStatuses.contains(doc.getStatus()));
                }
            }
        }
    }

    private void assertStatusOfSubmittedDocsWithRetries(String processId, int expectedDocumentsCount, DocumentStatus expectedStatus) throws Exception {
        int assertCounter = 1;
        int assertMaxRetries = config.getAssertMaxRetries();

        while(assertCounter <= assertMaxRetries) {
            try {
                assertStatusOfSubmittedDocs(processId, expectedDocumentsCount, expectedStatus);
                break;
            } catch (AssertionFailedError e) {
                if (assertCounter >= assertMaxRetries) {
                    throw e;
                }
            }
            stepLogger.writeItem("assert-submitted-doc-retry", "Assert failed this time", "Retrying document status assert " + assertCounter, "INFO", null);
            assertCounter++;
            Thread.sleep(config.getAssertRetryWaitPeriod().toMillis());
        }
    }

    private void assertIdentityVerificationStateWithRetries(IdentityVerificationState state) throws Exception {
        int assertCounter = 1;
        int assertMaxRetries = config.getAssertMaxRetries();

        while(assertCounter <= assertMaxRetries) {
            try {
                IdentityVerificationState idState = checkIdentityVerificationState();
                assertEquals(state, idState);
                break;
            } catch (AssertionFailedError e) {
                if (assertCounter >= assertMaxRetries) {
                    throw e;
                }
            }
            stepLogger.writeItem("assert-identity-verification-status-retry", "Assert failed this time", "Retrying identity verification status assert " + assertCounter, "INFO", null);
            assertCounter++;
            Thread.sleep(config.getAssertRetryWaitPeriod().toMillis());
        }
    }

    private void assertStatusOfSubmittedDocs(String processId, int expectedDocumentsCount, DocumentStatus expectedStatus) throws Exception {
        // Check status of submitted document
        DocumentStatusRequest docStatusRequest = new DocumentStatusRequest();
        docStatusRequest.setProcessId(processId);
        stepLogger = new ObjectStepLogger(System.out);
        tokenAndEncryptModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(docStatusRequest)));
        tokenAndEncryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/identity/document/status");

        new TokenAndEncryptStep().execute(stepLogger, tokenAndEncryptModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                String responseData = item.getObject().toString();
                ObjectResponse<DocumentStatusResponse> objectResponse = objectMapper.readValue(responseData, new TypeReference<ObjectResponse<DocumentStatusResponse>>() {});
                DocumentStatusResponse response = objectResponse.getResponseObject();
                assertEquals(expectedDocumentsCount, response.getDocuments().size());
                for (int i = 0; i < expectedDocumentsCount; i++) {
                    assertEquals(expectedStatus, response.getDocuments().get(i).getStatus());
                }
            }
        }
    }

    private void initPresenceCheck(String processId) throws Exception {
        if (config.isSkipPresenceCheck()) {
            return;
        }
        PresenceCheckInitRequest presenceCheckRequest = new PresenceCheckInitRequest();
        presenceCheckRequest.setProcessId(processId);
        stepLogger = new ObjectStepLogger(System.out);
        signatureModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(presenceCheckRequest)));
        signatureModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/identity/presence-check/init");
        signatureModel.setResourceId("/api/identity/presence-check/init");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
    }

    private void submitPresenceCheck(final String processId) throws Exception {
        if (config.isSkipPresenceCheck()) {
            return;
        }
        final PresenceCheckSubmitRequest presenceCheckRequest = new PresenceCheckSubmitRequest();
        presenceCheckRequest.setProcessId(processId);
        stepLogger = new ObjectStepLogger(System.out);
        signatureModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(presenceCheckRequest)));
        signatureModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/identity/presence-check/submit");
        signatureModel.setResourceId("/api/identity/presence-check/submit");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
    }

    private void verifyStatusBeforeOtp() throws Exception {
        // Presence check should succeed immediately in mock implementation, but in general this can take some time
        boolean verificationComplete = false;
        for (int i = 0; i < 10; i++) {
            IdentityVerificationState idState = checkIdentityVerificationState();
            if (config.isSkipOtpVerification() && idState.getStatus() == IdentityVerificationStatus.ACCEPTED) {
                verificationComplete = true;
                break;
            }
            if (!config.isSkipOtpVerification() && idState.phase == IdentityVerificationPhase.OTP_VERIFICATION && idState.getStatus() == IdentityVerificationStatus.VERIFICATION_PENDING) {
                verificationComplete = true;
                break;
            } else {
                Thread.sleep(1000);
            }
        }
        assertTrue(verificationComplete);
    }

    private IdentityVerificationState checkIdentityVerificationState() throws Exception {
        IdentityVerificationStatusRequest statusRequest = new IdentityVerificationStatusRequest();
        stepLogger = new ObjectStepLogger(System.out);
        tokenAndEncryptModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(statusRequest)));
        tokenAndEncryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/identity/status");

        new TokenAndEncryptStep().execute(stepLogger, tokenAndEncryptModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
        IdentityVerificationState idState = null;
        for (StepItem item : stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                String responseData = item.getObject().toString();
                ObjectResponse<IdentityVerificationStatusResponse> objectResponse = objectMapper.readValue(responseData, new TypeReference<ObjectResponse<IdentityVerificationStatusResponse>>() {});
                IdentityVerificationStatusResponse response = objectResponse.getResponseObject();
                idState = new IdentityVerificationState(
                        response.getIdentityVerificationPhase(),
                        response.getIdentityVerificationStatus()
                );
            }
        }
        assertNotNull(idState);
        assertNotNull(idState.getStatus());
        return idState;
    }

    private OnboardingStatus checkProcessStatus(String processId) throws Exception {
        OnboardingStatusRequest statusRequest = new OnboardingStatusRequest();
        statusRequest.setProcessId(processId);
        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(statusRequest)));
        encryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/onboarding/status");
        encryptModel.setScope("application");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
        OnboardingStatus status = null;
        for (StepItem item : stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                String responseData = item.getObject().toString();
                ObjectResponse<OnboardingStatusResponse> objectResponse = objectMapper.readValue(responseData, new TypeReference<ObjectResponse<OnboardingStatusResponse>>() {});
                OnboardingStatusResponse response = objectResponse.getResponseObject();
                status = response.getOnboardingStatus();
            }
        }
        assertNotNull(status);
        return status;
    }

    private void verifyOtpCheckFailed(String processId, IdentityVerificationPhase allowedPhase) throws Exception {
        final String otpCode = getOtpCode(processId, OtpType.USER_VERIFICATION);
        verifyOtpCheck(processId, false, otpCode, allowedPhase);
    }

    private void verifyOtpCheckFailedInvalidCode(String processId, IdentityVerificationPhase allowedPhase) throws Exception {
        final String otpCode = "invalid";
        verifyOtpCheck(processId, false, otpCode, allowedPhase);
    }

    private void verifyOtpCheckSuccessful(String processId) throws Exception {
        final String otpCode = getOtpCode(processId, OtpType.USER_VERIFICATION);
        verifyOtpCheck(processId, true, otpCode, IdentityVerificationPhase.COMPLETED);
    }

    private void verifyOtpCheck(final String processId, final boolean expectedResult, final String otpCode, IdentityVerificationPhase allowedPhase) throws Exception {
        if (config.isSkipOtpVerification()) {
            return;
        }
        boolean otpVerified = false;
        boolean verificationComplete = false;
        IdentityVerificationState idState = checkIdentityVerificationState();
        if (idState.getStatus() == IdentityVerificationStatus.VERIFICATION_PENDING) {
            IdentityVerificationOtpVerifyRequest otpVerifyRequest = new IdentityVerificationOtpVerifyRequest();
            otpVerifyRequest.setProcessId(processId);
            otpVerifyRequest.setOtpCode(otpCode);
            stepLogger = new ObjectStepLogger(System.out);
            encryptModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(otpVerifyRequest)));
            encryptModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/identity/otp/verify");
            encryptModel.setScope("activation");
            new EncryptStep().execute(stepLogger, encryptModel.toMap());
            assertTrue(stepLogger.getResult().isSuccess());
            assertEquals(200, stepLogger.getResponse().getStatusCode());

            otpVerified = stepLogger.getItems().stream()
                    .filter(isStepItemDecryptedResponse())
                    .map(StepItem::getObject)
                    .map(Object::toString)
                    .map(it -> safeReadValue(it, new TypeReference<ObjectResponse<OtpVerifyResponse>>() {}))
                    .filter(Objects::nonNull)
                    .map(ObjectResponse::getResponseObject)
                    .map(OtpVerifyResponse::isVerified)
                    .findFirst()
                    .orElse(false);

            // Force status refresh
            idState = checkIdentityVerificationState();
        }
        if (idState.getStatus() == IdentityVerificationStatus.ACCEPTED) {
            verificationComplete = true;
        } else if (idState.getPhase() == allowedPhase) {
            verificationComplete = true;
        }
        assertTrue(verificationComplete, "Verification should complete, either valid OTP or phase set to " + allowedPhase);
        assertEquals(expectedResult, otpVerified);
    }

    private void cleanupIdentityVerification(String processId) throws Exception {
        IdentityVerificationCleanupRequest cleanupRequest = new IdentityVerificationCleanupRequest();
        cleanupRequest.setProcessId(processId);
        stepLogger = new ObjectStepLogger(System.out);
        signatureModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(cleanupRequest)));
        signatureModel.setUriString(config.getEnrollmentOnboardingServiceUrl() + "/api/identity/cleanup");
        signatureModel.setResourceId("/api/identity/cleanup");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
    }

    private void verifyProcessFinished(String processId, String activationId) throws Exception {
        // Check onboarding process status
        OnboardingStatus status = checkProcessStatus(processId);
        assertEquals(OnboardingStatus.FINISHED, status);

        // Check activation flags
        ListActivationFlagsResponse flagResponse3 = powerAuthClient.listActivationFlags(activationId);
        assertTrue(flagResponse3.getActivationFlags().isEmpty());
    }

    private void verifyProcessNotFinished(final String processId) throws Exception {
        final OnboardingStatus status = checkProcessStatus(processId);
        assertNotEquals(OnboardingStatus.FINISHED, status, "Process must NOT be finished");
    }

    /**
     * @return Bytes of zipped files
     */
    private byte[] toZipBytes(List<File> files) throws IOException {
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
    static class FileSubmit {

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

    @AllArgsConstructor
    @EqualsAndHashCode
    @Getter
    @ToString
    static class IdentityVerificationState {

        private IdentityVerificationPhase phase;

        private IdentityVerificationStatus status;

    }

    private static class TestContext {
        private String activationId;
        private String processId;
    }

}
