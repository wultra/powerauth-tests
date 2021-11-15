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
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.v3.ActivationStatus;
import com.wultra.security.powerauth.client.v3.GetActivationStatusResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.model.enumeration.*;
import com.wultra.security.powerauth.model.request.*;
import com.wultra.security.powerauth.model.response.DocumentSubmitResponse;
import com.wultra.security.powerauth.model.response.IdentityVerificationStatusResponse;
import com.wultra.security.powerauth.model.response.OnboardingStartResponse;
import com.wultra.security.powerauth.model.response.OtpDetailResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.CreateActivationStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.EncryptStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.SignAndEncryptStep;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
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
    private CreateActivationStepModel activationModel;
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

        // Create result status object
        JSONObject resultStatusObject = new JSONObject();

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

        stepLogger = new ObjectStepLogger(System.out);
    }

    @Test
    public void testSuccessfulIdentityVerification() throws Exception {
        String activationId = prepareActivation();

        File image = new ClassPathResource("images/id_card_mock.png").getFile();

        DocumentSubmitRequest submitRequest = new DocumentSubmitRequest();
        DocumentSubmitRequest.DocumentMetadata metadata = new DocumentSubmitRequest.DocumentMetadata();
        metadata.setFilename("id_card_mock.png");
        metadata.setSide(CardSide.FRONT);
        metadata.setType(DocumentType.ID_CARD);
        submitRequest.setDocuments(Collections.singletonList(metadata));
        submitRequest.setResubmit(false);

        // ZIP request data
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(baos);
        ZipEntry entry = new ZipEntry(image.getName());
        byte[] data = Files.readAllBytes(image.toPath());
        zos.putNextEntry(entry);
        zos.write(data, 0, data.length);
        zos.closeEntry();
        baos.close();
        submitRequest.setData(baos.toByteArray());

        // Submit ID card
        stepLogger = new ObjectStepLogger(System.out);
        signatureModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(submitRequest)));
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/api/identity/document/submit");
        signatureModel.setResourceId("/api/identity/document/submit");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        EciesEncryptedResponse responseOtpOK = (EciesEncryptedResponse) stepLogger.getResponse().getResponseObject();
        assertNotNull(responseOtpOK.getEncryptedData());
        assertNotNull(responseOtpOK.getMac());

        boolean documentVerificationPending = false;
        String documentId = null;
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                String responseData = item.getObject().toString();
                ObjectResponse<DocumentSubmitResponse> objectResponse = objectMapper.readValue(responseData, new TypeReference<ObjectResponse<DocumentSubmitResponse>>() {});
                DocumentSubmitResponse response = objectResponse.getResponseObject();
                assertEquals(1, response.getDocuments().size());
                documentId = response.getDocuments().get(0).getId();
                assertNotNull(documentId);
                assertEquals(DocumentStatus.VERIFICATION_PENDING, response.getDocuments().get(0).getStatus());
                documentVerificationPending = true;
                break;
            }
        }
        assertTrue(documentVerificationPending);

        // Check status of submitted document
        DocumentStatusRequest docStatusRequest = new DocumentStatusRequest();
        DocumentStatusRequest.DocumentFilter filter = new DocumentStatusRequest.DocumentFilter();
        filter.setDocumentId(documentId);
        docStatusRequest.setFilter(Collections.singletonList(filter));
        stepLogger = new ObjectStepLogger(System.out);
        signatureModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(docStatusRequest)));
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/api/identity/document/status");
        signatureModel.setResourceId("/api/identity/document/status");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        // Init presence check
        InitPresenceCheckRequest presenceCheckRequest = new InitPresenceCheckRequest();
        stepLogger = new ObjectStepLogger(System.out);
        signatureModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(presenceCheckRequest)));
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/api/identity/presence-check/init");
        signatureModel.setResourceId("/api/identity/presence-check/init");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        // Presence check should succeed immediately in mock implementation, but in general this can take some time
        boolean verificationComplete = false;
        for (int i = 0; i < 10; i++) {
            IdentityVerificationStatusRequest statusRequest = new IdentityVerificationStatusRequest();
            stepLogger = new ObjectStepLogger(System.out);
            signatureModel.setData(objectMapper.writeValueAsBytes(new ObjectRequest<>(statusRequest)));
            signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/api/identity/status");
            signatureModel.setResourceId("/api/identity/status");

            new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
            assertTrue(stepLogger.getResult().isSuccess());
            assertEquals(200, stepLogger.getResponse().getStatusCode());
            IdentityVerificationStatus status = null;
            for (StepItem item: stepLogger.getItems()) {
                if (item.getName().equals("Decrypted Response")) {
                    String responseData = item.getObject().toString();
                    ObjectResponse<IdentityVerificationStatusResponse> objectResponse = objectMapper.readValue(responseData, new TypeReference<ObjectResponse<IdentityVerificationStatusResponse>>() {});
                    IdentityVerificationStatusResponse response = objectResponse.getResponseObject();
                    status = response.getIdentityVerificationStatus();
                    break;
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

        // Remove activation
        powerAuthClient.removeActivation(activationId, "test");
    }

    private String prepareActivation() throws Exception {
        String clientId = generateRandomClientId();
        String processId = startOnboarding(clientId);
        return createCustomActivation(processId, getOtpCode(processId), clientId);
    }

    private String startOnboarding(String clientId) throws Exception {
        stepLogger = new ObjectStepLogger(System.out);
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/onboarding/start");
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
        return otpCode;
    }

}
