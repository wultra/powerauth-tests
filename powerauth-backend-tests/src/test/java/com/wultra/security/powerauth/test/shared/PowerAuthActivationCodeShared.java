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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.SignAndEncryptStep;

import java.io.BufferedWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

/**
 * PowerAuth activation spawn test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthActivationCodeShared {

    private static final PowerAuthClientActivation CLIENT_ACTIVATION = new PowerAuthClientActivation();

    public static void activationUsingActivationCodeTest(PowerAuthTestConfiguration config, PrepareActivationStepModel activationModel,
                                                         VerifySignatureStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
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
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        boolean responseSuccessfullyDecrypted = false;
        String activationId = null;
        String activationCode = null;
        String activationSignature = null;
        for (StepItem item: stepLogger.getItems()) {
            if (item.name().equals("Decrypted Response")) {
                ObjectMapper objectMapper = config.getObjectMapper();
                final TypeReference<ObjectResponse<LinkedHashMap<String, String>>> responseType = new TypeReference<>(){};
                final ObjectResponse<LinkedHashMap<String, String>> responseData = objectMapper.readValue(item.object().toString(), responseType);
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
            boolean activationSignatureOK = CLIENT_ACTIVATION.verifyActivationCodeSignature(activationCode, activationSignatureBytes, config.getMasterPublicKey());
            assertTrue(activationSignatureOK);
        } catch (Throwable t) {
            t.printStackTrace();
        }

        // Create a new activation using received activation code and generated OTP
        activationModel.setActivationCode(activationCode);
        activationModel.setAdditionalActivationOtp(additionalActivationOtp);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, activationModel.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

        // Activations with OTP on key exchange are committed automatically
    }
}
