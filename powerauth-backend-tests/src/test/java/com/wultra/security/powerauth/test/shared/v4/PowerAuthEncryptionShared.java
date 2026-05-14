/*
 * PowerAuth test and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.shared.v4;

import com.wultra.core.rest.model.base.response.ErrorResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.model.StepItem;
import com.wultra.security.powerauth.lib.cmd.steps.EncryptStep;
import com.wultra.security.powerauth.lib.cmd.steps.AuthAndEncryptStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyAuthenticationStepModel;
import com.wultra.security.powerauth.util.TestCounterUtil;
import org.junit.jupiter.api.AssertionFailureBuilder;
import tools.jackson.databind.ObjectMapper;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth encryption test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthEncryptionShared {

    public static void encryptInActivationScopeTest(PowerAuthTestConfiguration config, EncryptStepModel encryptModel, ObjectStepLogger stepLogger) throws Exception {
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/activation");
        encryptModel.setScope("activation");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final AeadEncryptedResponse responseOK = (AeadEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getTimestamp());

        final Object result = fetchDecryptedResponse(stepLogger);

        assertEquals("{\"data\":\"Server successfully decrypted signed data: hello, scope: ACTIVATION_SCOPE\"}", result);
    }

    public static void encryptInApplicationScopeTest(PowerAuthTestConfiguration config, EncryptStepModel encryptModel, ObjectStepLogger stepLogger) throws Exception {
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/application");
        encryptModel.setScope("application");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final AeadEncryptedResponse responseOK = (AeadEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getTimestamp());

        final Object result = fetchDecryptedResponse(stepLogger);

        assertEquals("{\"data\":\"Server successfully decrypted signed data: hello, scope: APPLICATION_SCOPE\"}", result);
    }

    public static void encryptInInvalidScope1Test(PowerAuthTestConfiguration config, EncryptStepModel encryptModel, ObjectStepLogger stepLogger) throws Exception {
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/activation");
        encryptModel.setScope("application");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());
    }

    public static void encryptInInvalidScope2Test(PowerAuthTestConfiguration config, EncryptStepModel encryptModel, ObjectStepLogger stepLogger) throws Exception {
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/application");
        encryptModel.setScope("activation");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());
    }

    public static void encryptEmptyDataTest(PowerAuthTestConfiguration config, EncryptStepModel encryptModel, ObjectStepLogger stepLogger) throws Exception {
        File emptyDataFile = File.createTempFile("data_empty", ".txt");
        emptyDataFile.deleteOnExit();
        FileWriter fw = new FileWriter(emptyDataFile);
        fw.close();

        encryptModel.setData(Files.readAllBytes(Paths.get(emptyDataFile.getAbsolutePath())));
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/raw");
        encryptModel.setScope("activation");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void encryptBlockedActivationTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, EncryptStepModel encryptModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/activation");
        encryptModel.setScope("activation");

        // Block activation and verify that data exchange fails
        powerAuthClient.blockActivation(config.getActivationId(version), "test", "test");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());

        // Unblock activation and verify that data exchange succeeds
        powerAuthClient.unblockActivation(config.getActivationId(version), "test");

        ObjectStepLogger stepLoggerSuccess = new ObjectStepLogger(System.out);

        new EncryptStep().execute(stepLoggerSuccess, encryptModel.toMap());
        assertTrue(stepLoggerSuccess.getResult().success());
        assertEquals(200, stepLoggerSuccess.getResponse().statusCode());

        final AeadEncryptedResponse responseOK = (AeadEncryptedResponse) stepLoggerSuccess.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getTimestamp());

        boolean responseSuccessfullyDecrypted = false;
        for (StepItem item: stepLoggerSuccess.getItems()) {
            if (item.name().equals("Decrypted Response")) {
                assertEquals("{\"data\":\"Server successfully decrypted signed data: hello, scope: ACTIVATION_SCOPE\"}", item.object());
                responseSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseSuccessfullyDecrypted);
    }

    public static void signAndEncryptTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        signatureModel.setResourceId("/exchange/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/signed");

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final AeadEncryptedResponse responseOK = (AeadEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getTimestamp());

        final Object result = fetchDecryptedResponse(stepLogger);

        assertEquals("{\"data\":\"Server successfully decrypted data and verified signature, request data: hello, user ID: " + config.getUser(version) + "\"}", result);
    }

    public static void signAndEncryptWeakSignatureTypeTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId("/exchange/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/signed");

        signatureModel.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION);

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());
    }

    public static void signAndEncryptInvalidPasswordTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId("/exchange/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/signed");
        signatureModel.setPassword("0000");

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());
    }

    public static void signAndEncryptEmptyDataTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, EncryptStepModel encryptModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId("/exchange/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/signed");
        File emptyDataFile = File.createTempFile("data_empty_signed", ".txt");
        emptyDataFile.deleteOnExit();
        FileWriter fw = new FileWriter(emptyDataFile);
        fw.close();

        encryptModel.setData(Files.readAllBytes(Paths.get(emptyDataFile.getAbsolutePath())));

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        // It is allowed to encrypt and sign empty data
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void signAndEncryptLargeDataTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        signatureModel.setResourceId("/exchange/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/signed");

        SecureRandom secureRandom = new SecureRandom();
        File dataFileLarge = File.createTempFile("data_large_" + version, ".dat");
        dataFileLarge.deleteOnExit();
        FileWriter fw = new FileWriter(dataFileLarge);
        fw.write("{\"data\": \"");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int i = 0; i < 5000; i++) {
            baos.write(secureRandom.nextInt());
        }
        fw.write(Base64.getEncoder().encodeToString(baos.toByteArray()));
        fw.write("\"}");
        fw.close();

        signatureModel.setData(Files.readAllBytes(Paths.get(dataFileLarge.getAbsolutePath())));

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void signAndEncryptStringDataTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        signatureModel.setResourceId("/exchange/signed/string");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/signed/string");

        File dataFile = File.createTempFile("data_string" + version, ".dat");
        dataFile.deleteOnExit();
        BufferedWriter out = Files.newBufferedWriter(dataFile.toPath(), StandardCharsets.UTF_8);

        String requestData = Base64.getEncoder().encodeToString(generateRandomString().getBytes(StandardCharsets.UTF_8));
        // JSON Strings need to be enclosed in double quotes
        out.write("\"" + requestData + "\"");
        out.close();

        signatureModel.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Object result = fetchDecryptedResponse(stepLogger);

        assertEquals("\"Server successfully decrypted data and verified signature, request data: " + requestData + ", user ID: " + config.getUser(version) + "\"", result);
    }

    public static void signAndEncryptRawDataTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        signatureModel.setResourceId("/exchange/signed/raw");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/signed/raw");

        File dataFile = File.createTempFile("data_raw_" + version, ".dat");
        dataFile.deleteOnExit();
        BufferedWriter out = Files.newBufferedWriter(dataFile.toPath(), StandardCharsets.UTF_8);

        String requestData = generateRandomString();
        out.write(requestData);
        out.close();

        signatureModel.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Object result = fetchDecryptedResponse(stepLogger);

        assertEquals(requestData, result);
    }

    public static void signAndEncryptGenerifiedDataTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId("/exchange/signed/generics");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/signed/generics");
        File dataFileWithGenerics = File.createTempFile("data-generics", ".json");
        dataFileWithGenerics.deleteOnExit();
        FileWriter fw = new FileWriter(dataFileWithGenerics);
        fw.write("{\"requestObject\":{\"data\":\"test-data\"}}");
        fw.close();
        byte[] data = Files.readAllBytes(Paths.get(dataFileWithGenerics.getAbsolutePath()));
        signatureModel.setData(data);

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Object result = fetchDecryptedResponse(stepLogger);

        assertEquals("{\"status\":\"OK\",\"responseObject\":{\"data\":\"test-data\"}}", result);
    }

    private static Object fetchDecryptedResponse(final ObjectStepLogger stepLogger) {
        return stepLogger.getItems().stream()
                .filter(item -> "Decrypted Response".equals(item.name()))
                .map(StepItem::object)
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure().message("Response was not successfully decrypted").build());
    }

    public static void signAndEncryptInvalidResourceIdTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId("/exchange/invalid");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/signed");

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());
    }

    public static void signAndEncryptBlockedActivationTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        signatureModel.setResourceId("/exchange/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/signed");

        // Block activation and verify that data exchange fails
        powerAuthClient.blockActivation(config.getActivationId(version), "test", "test");

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().success());

        // Unblock activation and verify that data exchange succeeds
        powerAuthClient.unblockActivation(config.getActivationId(version), "test");

        ObjectStepLogger stepLoggerSuccess = new ObjectStepLogger(System.out);
        new AuthAndEncryptStep().execute(stepLoggerSuccess, signatureModel.toMap());
        assertTrue(stepLoggerSuccess.getResult().success());
        assertEquals(200, stepLoggerSuccess.getResponse().statusCode());

        AeadEncryptedResponse responseOK = (AeadEncryptedResponse) stepLoggerSuccess.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getTimestamp());

        boolean responseSuccessfullyDecrypted = false;
        for (StepItem item: stepLoggerSuccess.getItems()) {
            if (item.name().equals("Decrypted Response")) {
                assertEquals("{\"data\":\"Server successfully decrypted data and verified signature, request data: hello, user ID: " + config.getUser(version) + "\"}", item.object());
                responseSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseSuccessfullyDecrypted);
    }

    public static void signAndEncryptUnsupportedApplicationTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, PowerAuthVersion version) throws Exception {
        signatureModel.setResourceId("/exchange/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/signed");

        powerAuthClient.unsupportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new AuthAndEncryptStep().execute(stepLogger1, signatureModel.toMap());
        assertFalse(stepLogger1.getResult().success());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());

        powerAuthClient.supportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        ObjectStepLogger stepLogger2 = new ObjectStepLogger(System.out);
        new AuthAndEncryptStep().execute(stepLogger2, signatureModel.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        final AeadEncryptedResponse responseOK = (AeadEncryptedResponse) stepLogger2.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getTimestamp());

        boolean responseSuccessfullyDecrypted = false;
        for (StepItem item: stepLogger2.getItems()) {
            if (item.name().equals("Decrypted Response")) {
                assertEquals("{\"data\":\"Server successfully decrypted data and verified signature, request data: hello, user ID: " + config.getUser(version) + "\"}", item.object());
                responseSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseSuccessfullyDecrypted);
    }

    public static void signAndEncryptCounterIncrementTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        signatureModel.setResourceId("/exchange/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/signed");

        byte[] ctrData = TestCounterUtil.getCtrData(signatureModel.getResultStatus());
        HashBasedCounter counter = new HashBasedCounter(version.value());
        for (int i = 1; i <= 10; i++) {
            ObjectStepLogger stepLoggerLoop = new ObjectStepLogger();
            new AuthAndEncryptStep().execute(stepLoggerLoop, signatureModel.toMap());
            assertTrue(stepLoggerLoop.getResult().success());
            assertEquals(200, stepLoggerLoop.getResponse().statusCode());

            // Verify hash based counter
            ctrData = counter.next(ctrData);
            assertArrayEquals(ctrData, TestCounterUtil.getCtrData(signatureModel.getResultStatus()));
        }
    }

    public static void signAndEncryptLookAheadTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel) throws Exception {
        signatureModel.setResourceId("/exchange/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/signed");

        // Move counter by 1-4, next signature should succeed thanks to counter lookahead and it is still in max failure limit
        for (int i = 1; i < 4; i++) {
            for (int j=0; j < i; j++) {
                signatureModel.setPassword("1111");
                ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
                new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
                assertFalse(stepLogger.getResult().success());
                assertEquals(401, stepLogger.getResponse().statusCode());
            }

            signatureModel.setPassword(config.getPassword());
            ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
            new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
            assertTrue(stepLogger.getResult().success());
            assertEquals(200, stepLogger.getResponse().statusCode());
        }
    }

    public static void signAndEncryptSingleFactorTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId("/exchange/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/signed");
        signatureModel.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION);

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
    }

    public static void signAndEncryptBiometryTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId("/exchange/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed");
        signatureModel.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_BIOMETRY);

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void encryptedResponseTest(final PowerAuthTestConfiguration config, EncryptStepModel encryptModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v4/activation");
        encryptModel.setScope("activation");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
        AeadEncryptedResponse responseObject = (AeadEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(responseObject.getEncryptedData());
        assertNotNull(responseObject.getTimestamp());
    }

    private static String generateRandomString() {
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder alphabetBuilder = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            alphabetBuilder.append((char) i);
        }
        String alphabet = alphabetBuilder.toString();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            int randomChar = Math.abs(secureRandom.nextInt()) % alphabet.length();
            sb.append(alphabet, randomChar, randomChar+1);
        }
        return sb.toString();
    }

}
