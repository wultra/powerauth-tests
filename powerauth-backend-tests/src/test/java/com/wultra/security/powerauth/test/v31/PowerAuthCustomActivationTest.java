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
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.v3.ActivationStatus;
import com.wultra.security.powerauth.client.v3.GetActivationStatusResponse;
import com.wultra.security.powerauth.client.v3.GetApplicationDetailResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.VerifySignatureStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.CreateActivationStep;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnableConfigurationProperties
@ComponentScan(basePackages = {"com.wultra.security.powerauth", "io.getlime.security.powerauth"})
class PowerAuthCustomActivationTest {

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private CreateActivationStepModel model;
    private static File dataFile;
    private File tempStatusFile;
    private ObjectStepLogger stepLogger;

    @LocalServerPort
    private int port;

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @BeforeAll
    static void setUpBeforeClass() throws IOException {
        dataFile = File.createTempFile("data", ".json");
        FileWriter fw = new FileWriter(dataFile);
        fw.write("All your base are belong to us!");
        fw.close();
    }

    @AfterAll
    static void tearDownAfterClass() {
        assertTrue(dataFile.delete());
    }

    @BeforeEach
    void setUp() throws IOException {
        // Create temp status file
        tempStatusFile = File.createTempFile("pa_status_v31", ".json");

        // Model shared among tests
        model = new CreateActivationStepModel();
        model.setActivationName("test v3.1");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(config.getResultStatusObjectV31());
        model.setUriString("http://localhost:" + port);
        model.setVersion("3.1");
        model.setDeviceInfo("backend-tests");

        // Prepare step logger
        stepLogger = new ObjectStepLogger(System.out);
    }

    @AfterEach
    void tearDown() {
        assertTrue(tempStatusFile.delete());
    }

    @Test
    void customActivationValidTest() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_1_SIMPLE_LOOKUP_COMMIT_PROCESS");
        identityAttributes.put("username", "TestUser1");

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("key", "value");

        model.setIdentityAttributes(identityAttributes);
        model.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        String activationId = null;
        boolean layer2ResponseOk = false;
        boolean layer1ResponseOk = false;
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
                assertEquals("TestUser1", statusResponseActive.getUserId());
                layer2ResponseOk = true;
                continue;
            }
            if (item.getName().equals("Decrypted Layer 1 Response")) {
                ActivationLayer1Response layer1Response = (ActivationLayer1Response) item.getObject();
                // Verify custom attributes after processing
                assertEquals("value_new", layer1Response.getCustomAttributes().get("key_new"));
                layer1ResponseOk = true;
            }
        }

        assertTrue(layer1ResponseOk);
        assertTrue(layer2ResponseOk);

        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void customActivationValid2Test() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_2_STATIC_NOCOMMIT_NOPROCESS");

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("key", "value");

        model.setIdentityAttributes(identityAttributes);
        model.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        String activationId = null;
        boolean layer2ResponseOk = false;
        boolean layer1ResponseOk = false;
        // Verify decrypted responses
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Layer 2 Response")) {
                ActivationLayer2Response layer2Response = (ActivationLayer2Response) item.getObject();
                activationId = layer2Response.getActivationId();
                assertNotNull(activationId);
                assertNotNull(layer2Response.getCtrData());
                assertNotNull(layer2Response.getServerPublicKey());
                // Verify activation status - activation was not automatically committed
                GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(activationId);
                assertEquals(ActivationStatus.PENDING_COMMIT, statusResponseActive.getActivationStatus());
                assertEquals("static_username", statusResponseActive.getUserId());
                layer2ResponseOk = true;
                continue;
            }
            if (item.getName().equals("Decrypted Layer 1 Response")) {
                ActivationLayer1Response layer1Response = (ActivationLayer1Response) item.getObject();
                // Verify custom attributes, there should be no change
                assertEquals("value", layer1Response.getCustomAttributes().get("key"));
                layer1ResponseOk = true;
            }
        }

        assertTrue(layer1ResponseOk);
        assertTrue(layer2ResponseOk);

        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void customActivationValid3Test() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_3_USER_ID_MAP_COMMIT_NOPROCESS");

        Map<String, Object> customAttributes = new HashMap<>();
        identityAttributes.put("username", "TestUser1");
        customAttributes.put("key", "value");

        model.setIdentityAttributes(identityAttributes);
        model.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        String activationId = null;
        boolean layer2ResponseOk = false;
        boolean layer1ResponseOk = false;
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
                assertEquals("12345678", statusResponseActive.getUserId());
                layer2ResponseOk = true;
                continue;
            }
            if (item.getName().equals("Decrypted Layer 1 Response")) {
                ActivationLayer1Response layer1Response = (ActivationLayer1Response) item.getObject();
                // Verify custom attributes, there should be no change
                assertEquals("value", layer1Response.getCustomAttributes().get("key"));
                layer1ResponseOk = true;
            }
        }

        assertTrue(layer1ResponseOk);
        assertTrue(layer2ResponseOk);

        powerAuthClient.removeActivation(activationId, "test");
    }

    @Test
    void customActivationMissingUsernameTest() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_4_MISSING_USERNAME");

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("key", "value");

        model.setIdentityAttributes(identityAttributes);
        model.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(400, stepLogger.getResponse().getStatusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
    }

    @Test
    void customActivationEmptyUsernameTest() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_5_EMPTY_USERNAME");
        identityAttributes.put("username", "");

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("key", "value");

        model.setIdentityAttributes(identityAttributes);
        model.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(400, stepLogger.getResponse().getStatusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
    }

    @Test
    void customActivationUsernameTooLongTest() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_6_USERNAME_TOO_LONG");
        identityAttributes.put("username", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("key", "value");

        model.setIdentityAttributes(identityAttributes);
        model.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(400, stepLogger.getResponse().getStatusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
    }

    @Test
    void customActivationBadMasterPublicKeyTest() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_7_BAD_MASTER_PUBLIC_KEY");
        model.setIdentityAttributes(identityAttributes);

        KeyPair keyPair = new KeyGenerator().generateKeyPair();
        PublicKey originalKey = model.getMasterPublicKey();

        // Set bad master public key
        model.setMasterPublicKey(keyPair.getPublic());

        // Create activation
        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(400, stepLogger.getResponse().getStatusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());

        // Revert master public key change
        model.setMasterPublicKey(originalKey);
    }

    @Test
    void customActivationUnsupportedApplicationTest() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_8_UNSUPPORTED_APP_VERSION");
        model.setIdentityAttributes(identityAttributes);

        // Unsupport application version
        powerAuthClient.unsupportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        // Verify that application version is unsupported
        GetApplicationDetailResponse detailResponse = powerAuthClient.getApplicationDetail(config.getApplicationId());
        for (GetApplicationDetailResponse.Versions version: detailResponse.getVersions()) {
            if (version.getApplicationVersionId().equals(config.getApplicationVersion())) {
                assertFalse(version.isSupported());
            }
        }

        // Create activation
        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(400, stepLogger.getResponse().getStatusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());

        // Support application version
        powerAuthClient.supportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        // Verify that application version is supported
        GetApplicationDetailResponse detailResponse2 = powerAuthClient.getApplicationDetail(config.getApplicationId());
        for (GetApplicationDetailResponse.Versions version: detailResponse2.getVersions()) {
            if (version.getApplicationVersionId().equals(config.getApplicationVersion())) {
                assertTrue(version.isSupported());
            }
        }
    }

    @Test
    void customActivationInvalidApplicationKeyTest() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_8_INVALID_APP_KEY");
        model.setIdentityAttributes(identityAttributes);

        model.setApplicationKey("invalid");

        // Verify that CreateActivation fails
        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(400, stepLogger.getResponse().getStatusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());

        model.setApplicationKey(config.getApplicationKey());
    }

    @Test
    void customActivationInvalidApplicationSecretTest() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_8_INVALID_APP_SECRET");
        model.setIdentityAttributes(identityAttributes);

        model.setApplicationSecret("invalid");

        // Verify that CreateActivation fails
        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(400, stepLogger.getResponse().getStatusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());

        model.setApplicationSecret(config.getApplicationSecret());
    }

    @Test
    void customActivationDoubleCommitTest() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_9_DOUBLE_COMMIT");
        identityAttributes.put("username", "TestUser1");
        model.setIdentityAttributes(identityAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        String activationId = null;
        boolean layer2ResponseOk = false;
        boolean layer1ResponseOk = false;
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
                layer2ResponseOk = true;
                continue;
            }
            if (item.getName().equals("Decrypted Layer 1 Response")) {
                layer1ResponseOk = true;
            }
        }

        assertTrue(layer1ResponseOk);
        assertTrue(layer2ResponseOk);

        // Commit activation
        try {
            powerAuthClient.commitActivation(activationId, "test");
            fail("Double commit should not be allowed");
        } catch (PowerAuthClientException ex) {
            powerAuthClient.removeActivation(activationId, "test");
        }
    }

    @Test
    void customActivationSignatureMaxFailedTest() throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_10_SIGNATURES_MAX_FAILED");
        identityAttributes.put("username", "TestUser1");

        model.setIdentityAttributes(identityAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        String activationId = null;
        boolean layer2ResponseOk = false;
        boolean layer1ResponseOk = false;
        // Verify decrypted responses
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Layer 2 Response")) {
                ActivationLayer2Response layer2Response = (ActivationLayer2Response) item.getObject();
                activationId = layer2Response.getActivationId();
                assertNotNull(activationId);
                layer2ResponseOk = true;
                continue;
            }
            if (item.getName().equals("Decrypted Layer 1 Response")) {
                layer1ResponseOk = true;
            }
        }

        assertTrue(layer1ResponseOk);
        assertTrue(layer2ResponseOk);

        VerifySignatureStepModel signatureModel = new VerifySignatureStepModel();
        signatureModel.setApplicationKey(config.getApplicationKey());
        signatureModel.setApplicationSecret(config.getApplicationSecret());
        signatureModel.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));
        signatureModel.setHeaders(new HashMap<>());
        signatureModel.setHttpMethod("POST");
        signatureModel.setPassword(config.getPassword());
        signatureModel.setResourceId("/pa/signature/validate");
        signatureModel.setResultStatusObject(config.getResultStatusObjectV31());
        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        signatureModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        signatureModel.setUriString("http://localhost:" + port + "/pa/v3/signature/validate");
        signatureModel.setVersion("3.1");

        signatureModel.setPassword("1111");

        // Fail 2 signatures (configured value for maximum failed count is 3)
        for (int i = 0; i < 2; i++) {
            ObjectStepLogger stepLoggerSignature = new ObjectStepLogger();
            new VerifySignatureStep().execute(stepLoggerSignature, signatureModel.toMap());
            assertFalse(stepLoggerSignature.getResult().isSuccess());
            assertEquals(401, stepLoggerSignature.getResponse().getStatusCode());
        }

        // Last signature before max failed attempts should be successful
        signatureModel.setPassword(config.getPassword());
        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifySignatureStep().execute(stepLogger2, signatureModel.toMap());
        assertTrue(stepLogger2.getResult().isSuccess());
        assertEquals(200, stepLogger2.getResponse().getStatusCode());

        // Fail 3 signatures (configured value for maximum failed count is 3)
        signatureModel.setPassword("1111");
        for (int i = 0; i < 3; i++) {
            ObjectStepLogger stepLoggerSignature = new ObjectStepLogger();
            new VerifySignatureStep().execute(stepLoggerSignature, signatureModel.toMap());
            assertFalse(stepLoggerSignature.getResult().isSuccess());
            assertEquals(401, stepLoggerSignature.getResponse().getStatusCode());
        }

        // Activation should be blocked
        GetActivationStatusResponse statusResponseBlocked = powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.BLOCKED, statusResponseBlocked.getActivationStatus());

        powerAuthClient.removeActivation(activationId, "test");
    }
}
