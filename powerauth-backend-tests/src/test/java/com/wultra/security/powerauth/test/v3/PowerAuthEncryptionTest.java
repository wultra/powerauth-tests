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
package com.wultra.security.powerauth.test.v3;

import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.EncryptStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.SignAndEncryptStep;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashMap;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthEncryptionTest {

    private PowerAuthTestConfiguration config;
    private static File dataFile;
    private EncryptStepModel encryptModel;
    private VerifySignatureStepModel signatureModel;
    private ObjectStepLogger stepLogger;
    private PowerAuthServiceClient powerAuthClient;

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Autowired
    public void setPowerAuthServiceClient(PowerAuthServiceClient powerAuthClient) {
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
    public void setUp() {
        encryptModel = new EncryptStepModel();
        encryptModel.setApplicationKey(config.getApplicationKey());
        encryptModel.setApplicationSecret(config.getApplicationSecret());
        encryptModel.setDataFileName(dataFile.getAbsolutePath());
        encryptModel.setMasterPublicKey(config.getMasterPublicKey());
        encryptModel.setHeaders(new HashMap<>());
        encryptModel.setResultStatusObject(config.getResultStatusObjectV3());
        encryptModel.setVersion("3.0");

        signatureModel = new VerifySignatureStepModel();
        signatureModel.setApplicationKey(config.getApplicationKey());
        signatureModel.setApplicationSecret(config.getApplicationSecret());
        signatureModel.setDataFileName(dataFile.getAbsolutePath());
        signatureModel.setHeaders(new HashMap<>());
        signatureModel.setHttpMethod("POST");
        signatureModel.setPassword(config.getPassword());
        signatureModel.setResultStatusObject(config.getResultStatusObjectV3());
        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        signatureModel.setStatusFileName(config.getStatusFileV3().getAbsolutePath());
        signatureModel.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v3/signature/validate");
        signatureModel.setVersion("3.0");

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

        encryptModel.setDataFileName(emptyDataFile.getAbsolutePath());
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
        powerAuthClient.blockActivation(config.getActivationIdV3(), "test");

        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(400, stepLogger.getResponse().getStatusCode());

        // Unblock activation and verify that data exchange succeeds
        powerAuthClient.unblockActivation(config.getActivationIdV3());

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
                assertEquals("{\"data\":\"Server successfully decrypted data and verified signature, request data: hello, user ID: " + config.getUserV3() + "\"}", item.getObject());
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

        signatureModel.setDataFileName(emptyDataFile.getAbsolutePath());

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

        signatureModel.setDataFileName(dataFileLarge.getAbsolutePath());

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
    }

    @Test
    public void signAndEncryptStringDataTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed/string");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed/string");

        SecureRandom secureRandom = new SecureRandom();
        File dataFileLarge = File.createTempFile("data_string_v3", ".dat");
        dataFileLarge.deleteOnExit();
        FileWriter fw = new FileWriter(dataFileLarge);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int i = 0; i < 5; i++) {
            baos.write(secureRandom.nextInt());
        }
        fw.write("\"" + BaseEncoding.base64().encode(baos.toByteArray()) + "\"");
        fw.close();

        signatureModel.setDataFileName(dataFileLarge.getAbsolutePath());

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
    }

    @Test
    public void signAndEncryptRawDataTest() throws Exception {
        signatureModel.setResourceId("/exchange/v3/signed/raw");
        signatureModel.setUriString(config.getCustomServiceUrl() + "/exchange/v3/signed/raw");

        SecureRandom secureRandom = new SecureRandom();
        File dataFileLarge = File.createTempFile("data_raw_v3", ".dat");
        dataFileLarge.deleteOnExit();
        FileWriter fw = new FileWriter(dataFileLarge);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int i = 0; i < 5; i++) {
            baos.write(secureRandom.nextInt());
        }
        fw.write(baos.toString());
        fw.close();

        signatureModel.setDataFileName(dataFileLarge.getAbsolutePath());

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());
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
        powerAuthClient.blockActivation(config.getActivationIdV3(), "test");

        new SignAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(401, stepLogger.getResponse().getStatusCode());

        // Unblock activation and verify that data exchange succeeds
        powerAuthClient.unblockActivation(config.getActivationIdV3());

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
                assertEquals("{\"data\":\"Server successfully decrypted data and verified signature, request data: hello, user ID: " + config.getUserV3() + "\"}", item.getObject());
                responseSuccessfullyDecrypted = true;
                break;
            }
        }
        assertTrue(responseSuccessfullyDecrypted);
    }

}
