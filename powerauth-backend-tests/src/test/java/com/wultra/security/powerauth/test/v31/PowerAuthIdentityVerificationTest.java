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
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.common.collect.ImmutableList;
import com.wultra.app.enrollmentserver.api.model.request.*;
import com.wultra.app.enrollmentserver.api.model.response.*;
import com.wultra.app.enrollmentserver.api.model.response.data.DocumentMetadataResponseDto;
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
import lombok.Getter;
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
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthIdentityVerificationTest {

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
    public void setUp() throws IOException {
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
    public void testSuccessfulIdentityVerification() throws Exception {
        String[] context = prepareActivation();
        String activationId = context[0];
        String processId = context[1];

        initIdentityVerification(activationId, processId);

        List<FileSubmit> idCardSubmits = ImmutableList.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.FRONT),
                FileSubmit.createFrom("images/id_card_mock_back.png", DocumentType.ID_CARD, CardSide.BACK)
        );

        DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, idCardSubmits);

        submitDocuments(idCardSubmitRequest, idCardSubmits);

        if (config.isVerificationOnSubmitEnabled()) {
            assertStatusOfSubmittedDocsWithRetries(processId, idCardSubmits.size(), DocumentStatus.VERIFICATION_PENDING);
        } else {
            assertStatusOfSubmittedDocs(processId, idCardSubmits.size(), DocumentStatus.VERIFICATION_PENDING);
        }

        initPresenceCheck(processId);
        if (!config.isSkipResultVerification()) {
            verifyStatusBeforeOtp();
            verifyOtpCheck(processId);
            verifyProcessFinished(processId, activationId);
        }

        // Remove activation
        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    public void testSuccessfulIdentityVerificationWithRestarts() throws Exception {
        String[] context = prepareActivation();
        String activationId = context[0];
        String processId = context[1];

        for (int i = 0; i < 3; i++) {
            initIdentityVerification(activationId, processId);

            List<FileSubmit> idCardSubmits = ImmutableList.of(
                    FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.FRONT),
                    FileSubmit.createFrom("images/id_card_mock_back.png", DocumentType.ID_CARD, CardSide.BACK)
            );

            DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, idCardSubmits);

            submitDocuments(idCardSubmitRequest, idCardSubmits);

            if (config.isVerificationOnSubmitEnabled()) {
                assertStatusOfSubmittedDocsWithRetries(processId, idCardSubmits.size(), DocumentStatus.VERIFICATION_PENDING);
            } else {
                assertStatusOfSubmittedDocs(processId, idCardSubmits.size(), DocumentStatus.VERIFICATION_PENDING);
            }

            IdentityVerificationStatus status = checkIdentityVerificationStatus();
            assertEquals(IdentityVerificationStatus.VERIFICATION_PENDING, status);

            if (i < 2) {
                // Restart the identity verification in first two walkthroughs, the third walkthrough continues
                cleanupIdentityVerification(processId);
            }
        }

        initPresenceCheck(processId);
        if (!config.isSkipResultVerification()) {
            verifyStatusBeforeOtp();
            verifyOtpCheck(processId);
            verifyProcessFinished(processId, activationId);
        }

        // Remove activation
        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    public void testSuccessfulIdentityVerificationMultipleDocSubmits() throws Exception {
        String[] context = prepareActivation();
        String activationId = context[0];
        String processId = context[1];

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

        if (config.isVerificationOnSubmitEnabled()) {
            assertStatusOfSubmittedDocsWithRetries(processId, idCardSubmits.size() + drivingLicenseSubmits.size(), DocumentStatus.VERIFICATION_PENDING);
        } else {
            assertStatusOfSubmittedDocs(processId, idCardSubmits.size() + drivingLicenseSubmits.size(), DocumentStatus.VERIFICATION_PENDING);
        }

        initPresenceCheck(processId);
        if (!config.isSkipResultVerification()) {
            verifyStatusBeforeOtp();
            verifyOtpCheck(processId);
            verifyProcessFinished(processId, activationId);
        }

        // Remove activation
        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    public void testDocSubmitDifferentDocumentType() throws Exception {
        if (!config.isAdditionalDocSubmitValidationsEnabled()) {
            return;
        }
        String[] context = prepareActivation();
        String activationId = context[0];
        String processId = context[1];

        initIdentityVerification(activationId, processId);

        List<FileSubmit> docSubmits = ImmutableList.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.DRIVING_LICENSE, CardSide.FRONT)
        );
        DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, docSubmits);
        submitDocuments(idCardSubmitRequest, docSubmits);

        if (config.isVerificationOnSubmitEnabled()) {
            assertStatusOfSubmittedDocsWithRetries(processId, docSubmits.size(), DocumentStatus.REJECTED);
        } else {
            assertStatusOfSubmittedDocs(processId, docSubmits.size(), DocumentStatus.REJECTED);
        }

        // Remove activation
        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    public void testDocSubmitDifferentCardSide() throws Exception {
        if (!config.isAdditionalDocSubmitValidationsEnabled()) {
            return;
        }
        String[] context = prepareActivation();
        String activationId = context[0];
        String processId = context[1];

        initIdentityVerification(activationId, processId);

        List<FileSubmit> docSubmits = ImmutableList.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.BACK)
        );
        DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, docSubmits);
        submitDocuments(idCardSubmitRequest, docSubmits);

        if (config.isVerificationOnSubmitEnabled()) {
            assertStatusOfSubmittedDocsWithRetries(processId, docSubmits.size(), DocumentStatus.REJECTED);
        } else {
            assertStatusOfSubmittedDocs(processId, docSubmits.size(), DocumentStatus.REJECTED);
        }

        // Remove activation
        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    public void testIdentityVerificationNotDocumentPhotos() throws Exception {
        String[] context = prepareActivation();
        String activationId = context[0];
        String processId = context[1];

        initIdentityVerification(activationId, processId);

        List<FileSubmit> invalidDocSubmits = ImmutableList.of(
                FileSubmit.createFrom("images/random_photo_1.png", DocumentType.ID_CARD, CardSide.FRONT),
                FileSubmit.createFrom("images/random_photo_2.png", DocumentType.ID_CARD, CardSide.BACK)
        );
        DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, invalidDocSubmits);
        submitDocuments(idCardSubmitRequest, invalidDocSubmits);

        if (config.isVerificationOnSubmitEnabled()) {
            assertStatusOfSubmittedDocsWithRetries(processId, invalidDocSubmits.size(), DocumentStatus.VERIFICATION_PENDING);
        } else {
            assertStatusOfSubmittedDocs(processId, invalidDocSubmits.size(), DocumentStatus.VERIFICATION_PENDING);
        }

        // Remove activation
        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    public void testIdentityVerificationCleanup() throws Exception {
        String[] context = prepareActivation();
        String activationId = context[0];
        String processId = context[1];

        initIdentityVerification(activationId, processId);

        List<FileSubmit> idDocSubmits = ImmutableList.of(
                FileSubmit.createFrom("images/id_card_mock_front.png", DocumentType.ID_CARD, CardSide.FRONT),
                FileSubmit.createFrom("images/id_card_mock_back.png", DocumentType.ID_CARD, CardSide.BACK)
        );
        DocumentSubmitRequest idCardSubmitRequest = createDocumentSubmitRequest(processId, idDocSubmits);
        submitDocuments(idCardSubmitRequest, idDocSubmits);

        cleanupIdentityVerification(processId);

        // Remove activation
        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    public void largeUploadTest() throws Exception {
        String[] context = prepareActivation();
        String activationId = context[0];
        String processId = context[1];

        createToken();

        // Initialize identity verification request
        IdentityVerificationInitRequest initRequest = new IdentityVerificationInitRequest();
        initRequest.setProcessId(processId);
        stepLogger = new ObjectStepLogger(System.out);
        signatureModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(initRequest)));
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/api/identity/init");
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
        tokenAndEncryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/identity/document/upload");

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
        tokenAndEncryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/identity/document/upload");

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
        tokenAndEncryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/identity/document/submit");

        new TokenAndEncryptStep().execute(stepLogger, tokenAndEncryptModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        boolean documentVerificationPending = false;
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
                if (config.isVerificationOnSubmitEnabled()) {
                    assertEquals(DocumentStatus.UPLOAD_IN_PROGRESS, doc1.getStatus());
                } else {
                    assertEquals(DocumentStatus.VERIFICATION_PENDING, doc1.getStatus());
                    documentVerificationPending = true;
                }
                break;
            }
        }
        if (!config.isVerificationOnSubmitEnabled()) {
            assertTrue(documentVerificationPending);
        }
        assertNotNull(documentId);

        // Remove activation
        powerAuthClient.removeActivation(activationId, "test");
    }

    private String[] prepareActivation() throws Exception {
        String clientId = generateRandomClientId();
        String processId = startOnboarding(clientId);
        String activationId = createCustomActivation(processId, getOtpCode(processId, OtpType.ACTIVATION), clientId);
        createToken();
        return new String[]{activationId, processId};
    }

    private String startOnboarding(String clientId) throws Exception {
        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/onboarding/start");
        encryptModel.setScope("application");
        Map<String, Object> identification = new LinkedHashMap<>();
        if (clientId == null) {
            clientId = generateRandomClientId();
            identification.put("clientId", clientId);
        }
        identification.put("clientId", clientId);
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
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/onboarding/otp/detail");
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
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/api/identity/init");
        signatureModel.setResourceId("/api/identity/init");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        // Check activation flags
        ListActivationFlagsResponse flagResponse2 = powerAuthClient.listActivationFlags(activationId);
        assertEquals(Collections.singletonList("VERIFICATION_IN_PROGRESS"), flagResponse2.getActivationFlags());
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
        List<File> files = fileSubmits.stream().map(FileSubmit::getFile).collect(Collectors.toList());
        byte[] zippedFiles = toZipBytes(files);
        submitRequest.setData(zippedFiles);

        return submitRequest;
    }

    private void submitDocuments(DocumentSubmitRequest submitRequest, List<FileSubmit> fileSubmits) throws Exception {
        // Submit ID card
        stepLogger = new ObjectStepLogger(System.out);
        tokenAndEncryptModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(submitRequest)));
        tokenAndEncryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/identity/document/submit");

        new TokenAndEncryptStep().execute(stepLogger, tokenAndEncryptModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        EciesEncryptedResponse responseOtpOK = (EciesEncryptedResponse) stepLogger.getResponse().getResponseObject();
        assertNotNull(responseOtpOK.getEncryptedData());
        assertNotNull(responseOtpOK.getMac());

        List<DocumentStatus> expectedStatuses = config.isVerificationOnSubmitEnabled() ?
                ImmutableList.of(DocumentStatus.REJECTED, DocumentStatus.UPLOAD_IN_PROGRESS) : ImmutableList.of(DocumentStatus.VERIFICATION_PENDING);
        boolean documentVerificationPending = false;
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
                if (!config.isVerificationOnSubmitEnabled()) {
                    documentVerificationPending = response.getDocuments().stream()
                            .filter(doc -> DocumentStatus.VERIFICATION_PENDING == doc.getStatus())
                            .count() == fileSubmits.size();
                }
                break;
            }
        }
        if (!config.isVerificationOnSubmitEnabled()) {
            assertTrue(documentVerificationPending);
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

    private void assertStatusOfSubmittedDocs(String processId, int expectedDocumentsCount, DocumentStatus expectedStatus) throws Exception {
        // Check status of submitted document
        DocumentStatusRequest docStatusRequest = new DocumentStatusRequest();
        docStatusRequest.setProcessId(processId);
        stepLogger = new ObjectStepLogger(System.out);
        tokenAndEncryptModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(docStatusRequest)));
        tokenAndEncryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/identity/document/status");

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
        // Init presence check
        PresenceCheckInitRequest presenceCheckRequest = new PresenceCheckInitRequest();
        presenceCheckRequest.setProcessId(processId);
        stepLogger = new ObjectStepLogger(System.out);
        signatureModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(presenceCheckRequest)));
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/api/identity/presence-check/init");
        signatureModel.setResourceId("/api/identity/presence-check/init");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
    }

    private void verifyStatusBeforeOtp() throws Exception {
        // Presence check should succeed immediately in mock implementation, but in general this can take some time
        boolean verificationComplete = false;
        for (int i = 0; i < 10; i++) {
            IdentityVerificationStatus status = checkIdentityVerificationStatus();
            if (config.isSkipOtpVerification() && status == IdentityVerificationStatus.ACCEPTED) {
                verificationComplete = true;
                break;
            }
            if (!config.isSkipOtpVerification() && status == IdentityVerificationStatus.OTP_VERIFICATION_PENDING) {
                verificationComplete = true;
                break;
            } else {
                Thread.sleep(1000);
            }
        }
        assertTrue(verificationComplete);
    }

    private IdentityVerificationStatus checkIdentityVerificationStatus() throws Exception {
        IdentityVerificationStatusRequest statusRequest = new IdentityVerificationStatusRequest();
        stepLogger = new ObjectStepLogger(System.out);
        tokenAndEncryptModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(statusRequest)));
        tokenAndEncryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/identity/status");

        new TokenAndEncryptStep().execute(stepLogger, tokenAndEncryptModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
        IdentityVerificationStatus status = null;
        for (StepItem item : stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                String responseData = item.getObject().toString();
                ObjectResponse<IdentityVerificationStatusResponse> objectResponse = objectMapper.readValue(responseData, new TypeReference<ObjectResponse<IdentityVerificationStatusResponse>>() {});
                IdentityVerificationStatusResponse response = objectResponse.getResponseObject();
                status = response.getIdentityVerificationStatus();
            }
        }
        assertNotNull(status);
        return status;
    }

    private OnboardingStatus checkProcessStatus(String processId) throws Exception {
        OnboardingStatusRequest statusRequest = new OnboardingStatusRequest();
        statusRequest.setProcessId(processId);
        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(statusRequest)));
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/onboarding/status");
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

    private void verifyOtpCheck(String processId) throws Exception {
        if (config.isSkipOtpVerification()) {
            return;
        }
        boolean otpVerified = false;
        boolean verificationComplete = false;
        for (int i = 0; i < 10; i++) {
            IdentityVerificationStatus status = checkIdentityVerificationStatus();
            if (status == IdentityVerificationStatus.OTP_VERIFICATION_PENDING) {
                String otpCode = getOtpCode(processId, OtpType.USER_VERIFICATION);

                IdentityVerificationOtpVerifyRequest otpVerifyRequest = new IdentityVerificationOtpVerifyRequest();
                otpVerifyRequest.setProcessId(processId);
                otpVerifyRequest.setOtpCode(otpCode);
                stepLogger = new ObjectStepLogger(System.out);
                encryptModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(otpVerifyRequest)));
                encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/identity/otp/verify");
                encryptModel.setScope("activation");
                new EncryptStep().execute(stepLogger, encryptModel.toMap());
                assertTrue(stepLogger.getResult().isSuccess());
                assertEquals(200, stepLogger.getResponse().getStatusCode());

                for (StepItem item : stepLogger.getItems()) {
                    if (item.getName().equals("Decrypted Response")) {
                        String responseData = item.getObject().toString();
                        ObjectResponse<OtpVerifyResponse> objectResponse = objectMapper.readValue(responseData, new TypeReference<ObjectResponse<OtpVerifyResponse>>() {});
                        OtpVerifyResponse response = objectResponse.getResponseObject();
                        otpVerified = response.isVerified();
                    }
                }
                if (otpVerified) {
                    // Force status refresh
                    continue;
                }
            }
            if (status == IdentityVerificationStatus.ACCEPTED) {
                verificationComplete = true;
                break;
            } else {
                Thread.sleep(1000);
            }
        }
        assertTrue(verificationComplete);
    }

    private void cleanupIdentityVerification(String processId) throws Exception {
        IdentityVerificationCleanupRequest cleanupRequest = new IdentityVerificationCleanupRequest();
        cleanupRequest.setProcessId(processId);
        stepLogger = new ObjectStepLogger(System.out);
        signatureModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(cleanupRequest)));
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/api/identity/cleanup");
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

        private File file;

        private DocumentType documentType;

        private CardSide cardSide;

        private FileSubmit(File file, DocumentType documentType, CardSide cardSide) {
            this.file = file;
            this.documentType = documentType;
            this.cardSide = cardSide;
        }

        public static FileSubmit createFrom(String filePath, DocumentType documentType, CardSide cardSide)
            throws IOException {
            File file = new ClassPathResource(filePath).getFile();
            return new FileSubmit(file, documentType, cardSide);
        }

    }

}
