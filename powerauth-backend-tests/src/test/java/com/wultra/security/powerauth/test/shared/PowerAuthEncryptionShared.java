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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.v3.GetEciesDecryptorRequest;
import com.wultra.security.powerauth.client.model.response.v3.GetEciesDecryptorResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.ClientEciesSecrets;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.model.TemporaryKey;
import com.wultra.security.powerauth.test.shared.util.TemporaryKeyFetchUtil;
import com.wultra.core.rest.model.base.response.ErrorResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.model.StepItem;
import com.wultra.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.v3.EncryptStep;
import com.wultra.security.powerauth.lib.cmd.steps.v3.SignAndEncryptStep;
import com.wultra.security.powerauth.lib.cmd.util.CounterUtil;
import org.junit.jupiter.api.AssertionFailureBuilder;

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

    private static final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();

    public static void encryptInActivationScopeTest(PowerAuthTestConfiguration config, EncryptStepModel encryptModel, ObjectStepLogger stepLogger) throws Exception {
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/activation");
        encryptModel.setScope("activation");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

        final Object result = fetchDecryptedResponse(stepLogger);

        assertEquals("{\"data\":\"Server successfully decrypted signed data: hello, scope: ACTIVATION_SCOPE\"}", result);
    }

    public static void encryptInApplicationScopeTest(PowerAuthTestConfiguration config, EncryptStepModel encryptModel, ObjectStepLogger stepLogger) throws Exception {
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/application");
        encryptModel.setScope("application");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

        final Object result = fetchDecryptedResponse(stepLogger);

        assertEquals("{\"data\":\"Server successfully decrypted signed data: hello, scope: APPLICATION_SCOPE\"}", result);
    }

    public static void encryptInInvalidScope1Test(PowerAuthTestConfiguration config, EncryptStepModel encryptModel, ObjectStepLogger stepLogger) throws Exception {
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/activation");
        encryptModel.setScope("application");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());
    }

    public static void encryptInInvalidScope2Test(PowerAuthTestConfiguration config, EncryptStepModel encryptModel, ObjectStepLogger stepLogger) throws Exception {
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/application");
        encryptModel.setScope("activation");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());
    }

    public static void encryptEmptyDataTest(PowerAuthTestConfiguration config, EncryptStepModel encryptModel, ObjectStepLogger stepLogger) throws Exception {
        File emptyDataFile = File.createTempFile("data_empty_signed", ".json");
        emptyDataFile.deleteOnExit();
        FileWriter fw = new FileWriter(emptyDataFile);
        fw.close();

        encryptModel.setData(Files.readAllBytes(Paths.get(emptyDataFile.getAbsolutePath())));
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/activation");
        encryptModel.setScope("activation");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        // It is allowed to encrypt empty data
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void encryptBlockedActivationTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, EncryptStepModel encryptModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/activation");
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

        final EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLoggerSuccess.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

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

    public static void signAndEncryptTest(PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

        final Object result = fetchDecryptedResponse(stepLogger);

        assertEquals("{\"data\":\"Server successfully decrypted data and verified signature, request data: hello, user ID: " + config.getUser(version) + "\"}", result);
    }

    public static void signAndEncryptWeakSignatureTypeTest(PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed");

        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION);

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());
    }

    public static void signAndEncryptInvalidPasswordTest(PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed");
        signatureModel.setPassword("0000");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());
    }

    public static void signAndEncryptEmptyDataTest(PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel, EncryptStepModel encryptModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed");
        File emptyDataFile = File.createTempFile("data_empty_signed", ".json");
        emptyDataFile.deleteOnExit();
        FileWriter fw = new FileWriter(emptyDataFile);
        fw.close();

        encryptModel.setData(Files.readAllBytes(Paths.get(emptyDataFile.getAbsolutePath())));

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        // It is allowed to encrypt and sign empty data
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void signAndEncryptLargeDataTest(PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed");

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

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void signAndEncryptStringDataTest(PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed/string");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed/string");

        File dataFile = File.createTempFile("data_string" + version, ".dat");
        dataFile.deleteOnExit();
        BufferedWriter out = Files.newBufferedWriter(dataFile.toPath(), StandardCharsets.UTF_8);

        String requestData = Base64.getEncoder().encodeToString(generateRandomString().getBytes(StandardCharsets.UTF_8));
        // JSON Strings need to be enclosed in double quotes
        out.write("\"" + requestData + "\"");
        out.close();

        signatureModel.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Object result = fetchDecryptedResponse(stepLogger);

        assertEquals("\"Server successfully decrypted data and verified signature, request data: " + requestData + ", user ID: " + config.getUser(version) + "\"", result);
    }

    public static void signAndEncryptRawDataTest(PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed/raw");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed/raw");

        File dataFile = File.createTempFile("data_raw_" + version, ".dat");
        dataFile.deleteOnExit();
        BufferedWriter out = Files.newBufferedWriter(dataFile.toPath(), StandardCharsets.UTF_8);

        String requestData = generateRandomString();
        out.write(requestData);
        out.close();

        signatureModel.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final Object result = fetchDecryptedResponse(stepLogger);

        assertEquals(requestData, result);
    }

    public static void signAndEncryptGenerifiedDataTest(PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed/generics");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed/generics");
        File dataFileWithGenerics = File.createTempFile("data-generics", ".json");
        dataFileWithGenerics.deleteOnExit();
        FileWriter fw = new FileWriter(dataFileWithGenerics);
        fw.write("{\"requestObject\":{\"data\":\"test-data\"}}");
        fw.close();
        byte[] data = Files.readAllBytes(Paths.get(dataFileWithGenerics.getAbsolutePath()));
        signatureModel.setData(data);

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
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

    public static void signAndEncryptInvalidResourceIdTest(PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId("/exchange/v3/invalid");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());
    }

    public static void signAndEncryptBlockedActivationTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed");

        // Block activation and verify that data exchange fails
        powerAuthClient.blockActivation(config.getActivationId(version), "test", "test");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().success());

        // Unblock activation and verify that data exchange succeeds
        powerAuthClient.unblockActivation(config.getActivationId(version), "test");

        ObjectStepLogger stepLoggerSuccess = new ObjectStepLogger(System.out);
        new SignAndEncryptStep().execute(stepLoggerSuccess, signatureModel.toMap());
        assertTrue(stepLoggerSuccess.getResult().success());
        assertEquals(200, stepLoggerSuccess.getResponse().statusCode());

        EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLoggerSuccess.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

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

    public static void signAndEncryptUnsupportedApplicationTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel, PowerAuthVersion version) throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed");

        powerAuthClient.unsupportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new SignAndEncryptStep().execute(stepLogger1, signatureModel.toMap());
        assertFalse(stepLogger1.getResult().success());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());

        powerAuthClient.supportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        ObjectStepLogger stepLogger2 = new ObjectStepLogger(System.out);
        new SignAndEncryptStep().execute(stepLogger2, signatureModel.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        final EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger2.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

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

    public static void signAndEncryptCounterIncrementTest(PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed");

        byte[] ctrData = CounterUtil.getCtrData(signatureModel, stepLogger);
        HashBasedCounter counter = new HashBasedCounter(version.value());
        for (int i = 1; i <= 10; i++) {
            ObjectStepLogger stepLoggerLoop = new ObjectStepLogger();
            new SignAndEncryptStep().execute(stepLoggerLoop, signatureModel.toMap());
            assertTrue(stepLoggerLoop.getResult().success());
            assertEquals(200, stepLoggerLoop.getResponse().statusCode());

            // Verify hash based counter
            ctrData = counter.next(ctrData);
            assertArrayEquals(ctrData, CounterUtil.getCtrData(signatureModel, stepLoggerLoop));
        }
    }

    public static void signAndEncryptLookAheadTest(PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel) throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed");

        // Move counter by 1-4, next signature should succeed thanks to counter lookahead and it is still in max failure limit
        for (int i = 1; i < 4; i++) {
            for (int j=0; j < i; j++) {
                signatureModel.setPassword("1111");
                ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
                new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
                assertFalse(stepLogger.getResult().success());
                assertEquals(401, stepLogger.getResponse().statusCode());
            }

            signatureModel.setPassword(config.getPassword());
            ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
            new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
            assertTrue(stepLogger.getResult().success());
            assertEquals(200, stepLogger.getResponse().statusCode());
        }
    }

    public static void signAndEncryptSingleFactorTest(PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed");
        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION);

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
    }

    public static void signAndEncryptBiometryTest(PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed");
        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION_BIOMETRY);

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void signAndEncryptThreeFactorTest(PowerAuthTestConfiguration config, VerifySignatureStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/signed");
        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY);

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
    }

    public static void replayAttackEciesDecryptorTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, PowerAuthVersion version) throws Exception {
        final TemporaryKey temporaryKey = TemporaryKeyFetchUtil.fetchTemporaryKey(version, EncryptorScope.APPLICATION_SCOPE, config);
        String requestData = "test_data";
        ClientEncryptor<EciesEncryptedRequest, EciesEncryptedResponse> clientEncryptor = ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.APPLICATION_SCOPE_GENERIC,
                new EncryptorParameters(version.value(), config.getApplicationKey(), null, temporaryKey != null ? temporaryKey.getId() : null),
                new ClientEciesSecrets(config.getMasterPublicKey(), config.getApplicationSecret())
        );
        EciesEncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(requestData.getBytes(StandardCharsets.UTF_8));
        final GetEciesDecryptorRequest eciesDecryptorRequest = new GetEciesDecryptorRequest();
        eciesDecryptorRequest.setProtocolVersion(version.value());
        eciesDecryptorRequest.setActivationId(null);
        eciesDecryptorRequest.setApplicationKey(config.getApplicationKey());
        eciesDecryptorRequest.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        eciesDecryptorRequest.setNonce(encryptedRequest.getNonce());
        eciesDecryptorRequest.setTimestamp(encryptedRequest.getTimestamp());
        eciesDecryptorRequest.setTemporaryKeyId(temporaryKey != null ? temporaryKey.getId() : null);
        GetEciesDecryptorResponse decryptorResponse = powerAuthClient.getEciesDecryptor(eciesDecryptorRequest);
        assertNotNull(decryptorResponse.getSecretKey());
        assertNotNull(decryptorResponse.getSharedInfo2());

        // Replay attack simulation - send the same request twice, expect error ERR0024
        final PowerAuthClientException ex = assertThrows(PowerAuthClientException.class, () ->
                powerAuthClient.getEciesDecryptor(eciesDecryptorRequest));
        assertEquals("ERR0024", ex.getPowerAuthError().get().getCode());
    }

    public static void encryptedResponseTest(final PowerAuthTestConfiguration config, EncryptStepModel encryptModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/exchange/v3/activation");
        encryptModel.setScope("activation");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());
        EciesEncryptedResponse responseObject = (EciesEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(responseObject.getEncryptedData());
        assertNotNull(responseObject.getMac());
        switch (version) {
            case V3_0, V3_1 -> {
                assertNull(responseObject.getNonce());
                assertNull(responseObject.getTimestamp());
            }
            case V3_2, V3_3 -> {
                assertNotNull(responseObject.getNonce());
                assertNotNull(responseObject.getTimestamp());
            }
            default -> fail("Unsupported version");
        }
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
