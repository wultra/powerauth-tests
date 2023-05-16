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
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.SignAndEncryptStep;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthActivationCodeTest {

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private PrepareActivationStepModel activationModel;
    private VerifySignatureStepModel signatureModel;
    private File tempStatusFile;
    private ObjectStepLogger stepLogger;

    private final PowerAuthClientActivation clientActivation = new PowerAuthClientActivation();

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @BeforeEach
    void setUp() throws IOException {
        // Create temp status file
        tempStatusFile = File.createTempFile("pa_status_v31", ".json");

        // Model shared among tests
        activationModel = new PrepareActivationStepModel();
        activationModel.setActivationName("test v31");
        activationModel.setApplicationKey(config.getApplicationKey());
        activationModel.setApplicationSecret(config.getApplicationSecret());
        activationModel.setMasterPublicKey(config.getMasterPublicKey());
        activationModel.setHeaders(new HashMap<>());
        activationModel.setPassword(config.getPassword());
        activationModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        activationModel.setResultStatusObject(new JSONObject());
        activationModel.setUriString(config.getPowerAuthIntegrationUrl());
        activationModel.setVersion("3.1");
        activationModel.setDeviceInfo("backend-tests");

        signatureModel = new VerifySignatureStepModel();
        signatureModel.setApplicationKey(config.getApplicationKey());
        signatureModel.setApplicationSecret(config.getApplicationSecret());
        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION_BIOMETRY);
        signatureModel.setPassword(config.getPassword());
        signatureModel.setHttpMethod("POST");
        signatureModel.setHeaders(new HashMap<>());
        signatureModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        signatureModel.setResultStatusObject(config.getResultStatusObjectV31());
        signatureModel.setVersion("3.1");
        signatureModel.setDryRun(false);

        stepLogger = new ObjectStepLogger(System.out);
    }

    @AfterEach
    void tearDown() {
        assertTrue(tempStatusFile.delete());
    }

    @Test
    void activationUsingActivationCodeTest() throws Exception {
        // Run this test only in case Enrollment server is available
        assumeFalse(config.getEnrollmentServiceUrl().isEmpty());

        // Obtain activation code from enrollment server
        signatureModel.setResourceId("/api/activation/code");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/api/activation/code");

        File dataFile = File.createTempFile("data_activation_code", ".dat");
        dataFile.deleteOnExit();
        BufferedWriter out = Files.newBufferedWriter(dataFile.toPath(), StandardCharsets.UTF_8);

        String additionalActivationOtp = UUID.randomUUID().toString();

        String requestData = "{\n" +
                "  \"requestObject\": {\n" +
                "    \"applicationId\": \"" + config.getApplicationName() + "\",\n" +
                "    \"otp\": \"" + additionalActivationOtp + "\"\n" +
                "  }\n" +
                "}";
        out.write(requestData);
        out.close();

        signatureModel.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        boolean responseSuccessfullyDecrypted = false;
        String activationId = null;
        String activationCode = null;
        String activationSignature = null;
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                ObjectMapper objectMapper = config.getObjectMapper();
                final TypeReference<ObjectResponse<LinkedHashMap<String, String>>> responseType = new TypeReference<>(){};
                ObjectResponse<LinkedHashMap<String, String>> responseData = objectMapper.readValue(item.getObject().toString(), responseType);
                activationId = responseData.getResponseObject().get("activationId");
                activationCode = responseData.getResponseObject().get("activationCode");
                activationSignature = responseData.getResponseObject().get("activationSignature");
                responseSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseSuccessfullyDecrypted);
        assertNotNull(activationId);
        assertNotNull(activationCode);
        assertNotNull(activationSignature);

        byte[] activationSignatureBytes = Base64.getDecoder().decode(activationSignature);

        // Verify activation signature
        try {
            boolean activationSignatureOK = clientActivation.verifyActivationCodeSignature(activationCode, activationSignatureBytes, config.getMasterPublicKey());
            assertTrue(activationSignatureOK);
        } catch (Throwable t) {
            t.printStackTrace();
        }

        // Create a new activation using received activation code and generated OTP
        activationModel.setActivationCode(activationCode);
        activationModel.setAdditionalActivationOtp(additionalActivationOtp);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, activationModel.toMap());
        assertTrue(stepLoggerPrepare.getResult().isSuccess());
        assertEquals(200, stepLoggerPrepare.getResponse().getStatusCode());

        // Activations with OTP on key exchange are committed automatically
    }
}
