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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.EncryptStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.SignAndEncryptStep;
import io.getlime.security.powerauth.lib.cmd.util.CounterUtil;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.HashMap;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthEncryptionTest {

    private PowerAuthTestConfiguration config;
    private static File dataFile;
    private EncryptStepModel encryptModel;
    private VerifySignatureStepModel signatureModel;
    private ObjectStepLogger stepLogger;
    private PowerAuthClient powerAuthClient;

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @BeforeClass
    public static void setUpBeforeClass() throws IOException {
        dataFile = File.createTempFile("data", ".json");
        FileWriter fw = new FileWriter(dataFile);
        fw.write("{\"data\": \"hello\"}");
        fw.close();
    }

    @AfterClass
    public static void tearDownAfterClass() {
        assertTrue(dataFile.delete());
    }

    @Before
    public void setUp() throws IOException {
        encryptModel = new EncryptStepModel();
        encryptModel.setApplicationKey(config.getApplicationKey());
        encryptModel.setApplicationSecret(config.getApplicationSecret());
        encryptModel.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));
        encryptModel.setMasterPublicKey(config.getMasterPublicKey());
        encryptModel.setHeaders(new HashMap<>());
        encryptModel.setResultStatusObject(config.getResultStatusObjectV31());
        encryptModel.setVersion("3.1");

        signatureModel = new VerifySignatureStepModel();
        signatureModel.setApplicationKey(config.getApplicationKey());
        signatureModel.setApplicationSecret(config.getApplicationSecret());
        signatureModel.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));
        signatureModel.setHeaders(new HashMap<>());
        signatureModel.setHttpMethod("POST");
        signatureModel.setPassword(config.getPassword());
        signatureModel.setResultStatusObject(config.getResultStatusObjectV31());
        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        signatureModel.setStatusFileName(config.getStatusFileV31().getAbsolutePath());
        signatureModel.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate");
        signatureModel.setVersion("3.1");

        stepLogger = new ObjectStepLogger(System.out);
    }

    @Test
    public void encryptInActivationScopeTest() throws Exception {
        encryptModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/activation");
        encryptModel.setScope("activation");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger.getResponse().getResponseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

        boolean responseSuccessfullyDecrypted = false;
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                assertEquals("{\"data\":\"Server successfully decrypted signed data: hello, scope: ACTIVATION_SCOPE\"}", item.getObject());
                responseSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseSuccessfullyDecrypted);
    }

    @Test
    public void encryptInApplicationScopeTest() throws Exception {
        encryptModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/application");
        encryptModel.setScope("application");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger.getResponse().getResponseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

        boolean responseSuccessfullyDecrypted = false;
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                assertEquals("{\"data\":\"Server successfully decrypted signed data: hello, scope: APPLICATION_SCOPE\"}", item.getObject());
                responseSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseSuccessfullyDecrypted);
    }

    @Test
    public void encryptInInvalidScope1Test() throws Exception {
        encryptModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/activation");
        encryptModel.setScope("application");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(400, stepLogger.getResponse().getStatusCode());
    }

    @Test
    public void encryptInInvalidScope2Test() throws Exception {
        encryptModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/application");
        encryptModel.setScope("activation");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(400, stepLogger.getResponse().getStatusCode());
    }

    @Test
    public void encryptEmptyDataTest() throws Exception {
        File emptyDataFile = File.createTempFile("data_empty_signed", ".json");
        emptyDataFile.deleteOnExit();
        FileWriter fw = new FileWriter(emptyDataFile);
        fw.close();

        encryptModel.setData(Files.readAllBytes(Paths.get(emptyDataFile.getAbsolutePath())));
        encryptModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/activation");
        encryptModel.setScope("activation");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        // It is allowed to encrypt empty data
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
    }

    @Test
    public void encryptBlockedActivationTest() throws Exception {
        encryptModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/activation");
        encryptModel.setScope("activation");

        // Block activation and verify that data exchange fails
        powerAuthClient.blockActivation(config.getActivationIdV31(), "test", "test");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(400, stepLogger.getResponse().getStatusCode());

        // Unblock activation and verify that data exchange succeeds
        powerAuthClient.unblockActivation(config.getActivationIdV31(), "test");

        ObjectStepLogger stepLoggerSuccess = new ObjectStepLogger(System.out);

        new EncryptStep().execute(stepLoggerSuccess, encryptModel.toMap());
        assertTrue(stepLoggerSuccess.getResult().isSuccess());
        assertEquals(200, stepLoggerSuccess.getResponse().getStatusCode());

        EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLoggerSuccess.getResponse().getResponseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

        boolean responseSuccessfullyDecrypted = false;
        for (StepItem item: stepLoggerSuccess.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                assertEquals("{\"data\":\"Server successfully decrypted signed data: hello, scope: ACTIVATION_SCOPE\"}", item.getObject());
                responseSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseSuccessfullyDecrypted);
    }

    @Test
    public void signAndEncryptTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger.getResponse().getResponseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

        boolean responseSuccessfullyDecrypted = false;
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                assertEquals("{\"data\":\"Server successfully decrypted data and verified signature, request data: hello, user ID: " + config.getUserV31() + "\"}", item.getObject());
                responseSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseSuccessfullyDecrypted);
    }

    @Test
    public void signAndEncryptWeakSignatureTypeTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed");

        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION);

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(401, stepLogger.getResponse().getStatusCode());
    }

    @Test
    public void signAndEncryptInvalidPasswordTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed");
        signatureModel.setPassword("0000");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(401, stepLogger.getResponse().getStatusCode());
    }

    @Test
    public void signAndEncryptEmptyDataTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed");
        File emptyDataFile = File.createTempFile("data_empty_signed", ".json");
        emptyDataFile.deleteOnExit();
        FileWriter fw = new FileWriter(emptyDataFile);
        fw.close();

        encryptModel.setData(Files.readAllBytes(Paths.get(emptyDataFile.getAbsolutePath())));

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        // It is allowed to encrypt and sign empty data
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
    }

    @Test
    public void signAndEncryptLargeDataTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed");

        SecureRandom secureRandom = new SecureRandom();
        File dataFileLarge = File.createTempFile("data_large_v3", ".dat");
        dataFileLarge.deleteOnExit();
        FileWriter fw = new FileWriter(dataFileLarge);
        fw.write("{\"data\": \"");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int i = 0; i < 5000; i++) {
            baos.write(secureRandom.nextInt());
        }
        fw.write(BaseEncoding.base64().encode(baos.toByteArray()));
        fw.write("\"}");
        fw.close();

        signatureModel.setData(Files.readAllBytes(Paths.get(dataFileLarge.getAbsolutePath())));

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
    }

    @Test
    public void signAndEncryptStringDataTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed/string");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed/string");

        File dataFileLarge = File.createTempFile("data_string_v3", ".dat");
        dataFileLarge.deleteOnExit();
        BufferedWriter out = Files.newBufferedWriter(dataFileLarge.toPath(), StandardCharsets.UTF_8);

        String requestData = BaseEncoding.base64().encode(generateRandomString().getBytes(StandardCharsets.UTF_8));
        // JSON Strings need to be enclosed in double quotes
        out.write("\"" + requestData + "\"");
        out.close();

        signatureModel.setData(Files.readAllBytes(Paths.get(dataFileLarge.getAbsolutePath())));

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        boolean responseSuccessfullyDecrypted = false;
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                assertEquals("\"Server successfully decrypted data and verified signature, request data: "+requestData+", user ID: " + config.getUserV31() + "\"", item.getObject());
                responseSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseSuccessfullyDecrypted);
    }

    @Test
    public void signAndEncryptRawDataTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed/raw");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed/raw");

        File dataFileLarge = File.createTempFile("data_raw_v3", ".dat");
        dataFileLarge.deleteOnExit();
        BufferedWriter out = Files.newBufferedWriter(dataFileLarge.toPath(), StandardCharsets.UTF_8);

        String requestData = generateRandomString();
        out.write(requestData);
        out.close();

        signatureModel.setData(Files.readAllBytes(Paths.get(dataFileLarge.getAbsolutePath())));

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        boolean responseSuccessfullyDecrypted = false;
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                assertEquals(requestData, item.getObject());
                responseSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseSuccessfullyDecrypted);
    }

    @Test
    public void signAndEncryptInvalidResourceIdTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/invalid");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(401, stepLogger.getResponse().getStatusCode());
    }

    @Test
    public void signAndEncryptBlockedActivationTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed");

        // Block activation and verify that data exchange fails
        powerAuthClient.blockActivation(config.getActivationIdV31(), "test", "test");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().isSuccess());

        // Unblock activation and verify that data exchange succeeds
        powerAuthClient.unblockActivation(config.getActivationIdV31(), "test");

        ObjectStepLogger stepLoggerSuccess = new ObjectStepLogger(System.out);
        new SignAndEncryptStep().execute(stepLoggerSuccess, signatureModel.toMap());
        assertTrue(stepLoggerSuccess.getResult().isSuccess());
        assertEquals(200, stepLoggerSuccess.getResponse().getStatusCode());

        EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLoggerSuccess.getResponse().getResponseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

        boolean responseSuccessfullyDecrypted = false;
        for (StepItem item: stepLoggerSuccess.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                assertEquals("{\"data\":\"Server successfully decrypted data and verified signature, request data: hello, user ID: " + config.getUserV31() + "\"}", item.getObject());
                responseSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseSuccessfullyDecrypted);
    }

    @Test
    public void signAndEncryptUnsupportedApplicationTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed");

        powerAuthClient.unsupportApplicationVersion(config.getApplicationVersionId());

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new SignAndEncryptStep().execute(stepLogger1, signatureModel.toMap());
        assertFalse(stepLogger1.getResult().isSuccess());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());

        powerAuthClient.supportApplicationVersion(config.getApplicationVersionId());

        ObjectStepLogger stepLogger2 = new ObjectStepLogger(System.out);
        new SignAndEncryptStep().execute(stepLogger2, signatureModel.toMap());
        assertTrue(stepLogger2.getResult().isSuccess());
        assertEquals(200, stepLogger2.getResponse().getStatusCode());

        EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger2.getResponse().getResponseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

        boolean responseSuccessfullyDecrypted = false;
        for (StepItem item: stepLogger2.getItems()) {
            if (item.getName().equals("Decrypted Response")) {
                assertEquals("{\"data\":\"Server successfully decrypted data and verified signature, request data: hello, user ID: " + config.getUserV31() + "\"}", item.getObject());
                responseSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseSuccessfullyDecrypted);
    }


    @Test
    public void signAndEncryptCounterIncrementTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed");

        byte[] ctrData = CounterUtil.getCtrData(signatureModel, stepLogger);
        HashBasedCounter counter = new HashBasedCounter();
        for (int i = 1; i <= 10; i++) {
            ObjectStepLogger stepLoggerLoop = new ObjectStepLogger();
            new SignAndEncryptStep().execute(stepLoggerLoop, signatureModel.toMap());
            assertTrue(stepLoggerLoop.getResult().isSuccess());
            assertEquals(200, stepLoggerLoop.getResponse().getStatusCode());

            // Verify hash based counter
            ctrData = counter.next(ctrData);
            assertArrayEquals(ctrData, CounterUtil.getCtrData(signatureModel, stepLoggerLoop));
        }
    }

    @Test
    public void signAndEncryptLookAheadTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed");

        // Move counter by 1-4, next signature should succeed thanks to counter lookahead and it is still in max failure limit
        for (int i = 1; i < 4; i++) {
            for (int j=0; j < i; j++) {
                ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
                signatureModel.setPassword("1111");
                new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
                assertFalse(stepLogger.getResult().isSuccess());
                assertEquals(401, stepLogger.getResponse().getStatusCode());
            }

            ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
            signatureModel.setPassword(config.getPassword());
            new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
            assertTrue(stepLogger.getResult().isSuccess());
            assertEquals(200, stepLogger.getResponse().getStatusCode());
        }
    }

    @Test
    public void signAndEncryptSingleFactorTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed");
        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION);

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(401, stepLogger.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
    }

    @Test
    public void signAndEncryptBiometryTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed");
        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION_BIOMETRY);

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
    }

    @Test
    public void signAndEncryptThreeFactorTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed");
        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY);

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
    }

    private String generateRandomString() {
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
