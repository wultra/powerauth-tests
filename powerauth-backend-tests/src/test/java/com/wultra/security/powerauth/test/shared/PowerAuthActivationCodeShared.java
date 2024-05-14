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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.SignAndEncryptStep;
import org.junit.jupiter.api.AssertionFailureBuilder;

import java.io.BufferedWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Map;
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

        final Map<String, String> response = stepLogger.getItems().stream()
                .filter(item -> "Decrypted Response".equals(item.name()))
                .map(item -> item.object().toString())
                .map(item -> PowerAuthActivationCodeShared.<Map<String, Object>>read(config.getObjectMapper(), item))
                .map(item -> (Map<String, String>) item.get("responseObject"))
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure().message("Response was not successfully decrypted").build());

        final String activationId = response.get("activationId");
        final String activationCode = response.get("activationCode");
        final String activationSignature = response.get("activationSignature");

        assertNotNull(activationId);
        assertNotNull(activationCode);
        assertNotNull(activationSignature);

        byte[] activationSignatureBytes = Base64.getDecoder().decode(activationSignature);

        // Verify activation signature
        boolean activationSignatureOK = CLIENT_ACTIVATION.verifyActivationCodeSignature(activationCode, activationSignatureBytes, config.getMasterPublicKey());
        assertTrue(activationSignatureOK);

        // Create a new activation using received activation code and generated OTP
        activationModel.setActivationCode(activationCode);
        activationModel.setAdditionalActivationOtp(additionalActivationOtp);
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, activationModel.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

        // Activations with OTP on key exchange are committed automatically
    }

    private static <T> T read(final ObjectMapper objectMapper, final String source) {
        try {
            final T result = objectMapper.readValue(source, new TypeReference<>() {});
            assertNotNull(result);
            return result;
        } catch (JsonProcessingException e) {
            throw AssertionFailureBuilder.assertionFailure()
                    .message("Unable to parse JSON.")
                    .cause(e)
                    .build();
        }
    }
}
