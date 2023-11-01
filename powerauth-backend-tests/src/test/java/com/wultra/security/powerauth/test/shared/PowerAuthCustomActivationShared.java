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
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse;
import com.wultra.security.powerauth.client.model.response.GetApplicationDetailResponse;
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
import io.getlime.security.powerauth.rest.api.model.response.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.ActivationLayer2Response;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class PowerAuthCustomActivationShared {

    public static void customActivationValidTest(PowerAuthClient powerAuthClient, CreateActivationStepModel model, ObjectStepLogger stepLogger) throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_1_SIMPLE_LOOKUP_COMMIT_PROCESS");
        identityAttributes.put("username", "TestUser1");

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("key", "value");

        model.setIdentityAttributes(identityAttributes);
        model.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        String activationId = null;
        boolean layer2ResponseOk = false;
        boolean layer1ResponseOk = false;
        // Verify decrypted responses
        for (StepItem item: stepLogger.getItems()) {
            if (item.name().equals("Decrypted Layer 2 Response")) {
                final ActivationLayer2Response layer2Response = (ActivationLayer2Response) item.object();
                activationId = layer2Response.getActivationId();
                assertNotNull(activationId);
                assertNotNull(layer2Response.getCtrData());
                assertNotNull(layer2Response.getServerPublicKey());
                // Verify activation status - activation was automatically committed
                final GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(activationId);
                assertEquals(ActivationStatus.ACTIVE, statusResponseActive.getActivationStatus());
                assertEquals("TestUser1", statusResponseActive.getUserId());
                layer2ResponseOk = true;
                continue;
            }
            if (item.name().equals("Decrypted Layer 1 Response")) {
                final ActivationLayer1Response layer1Response = (ActivationLayer1Response) item.object();
                // Verify custom attributes after processing
                assertEquals("value_new", layer1Response.getCustomAttributes().get("key_new"));
                layer1ResponseOk = true;
            }
        }

        assertTrue(layer1ResponseOk);
        assertTrue(layer2ResponseOk);

        powerAuthClient.removeActivation(activationId, "test");
    }

    public static void customActivationValid2Test(PowerAuthClient powerAuthClient, CreateActivationStepModel model, ObjectStepLogger stepLogger) throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_2_STATIC_NOCOMMIT_NOPROCESS");

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("key", "value");

        model.setIdentityAttributes(identityAttributes);
        model.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        String activationId = null;
        boolean layer2ResponseOk = false;
        boolean layer1ResponseOk = false;
        // Verify decrypted responses
        for (StepItem item: stepLogger.getItems()) {
            if (item.name().equals("Decrypted Layer 2 Response")) {
                final ActivationLayer2Response layer2Response = (ActivationLayer2Response) item.object();
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
            if (item.name().equals("Decrypted Layer 1 Response")) {
                final ActivationLayer1Response layer1Response = (ActivationLayer1Response) item.object();
                // Verify custom attributes, there should be no change
                assertEquals("value", layer1Response.getCustomAttributes().get("key"));
                layer1ResponseOk = true;
            }
        }

        assertTrue(layer1ResponseOk);
        assertTrue(layer2ResponseOk);

        powerAuthClient.removeActivation(activationId, "test");
    }

    public static void customActivationValid3Test(PowerAuthClient powerAuthClient, CreateActivationStepModel model, ObjectStepLogger stepLogger) throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_3_USER_ID_MAP_COMMIT_NOPROCESS");

        Map<String, Object> customAttributes = new HashMap<>();
        identityAttributes.put("username", "TestUser1");
        customAttributes.put("key", "value");

        model.setIdentityAttributes(identityAttributes);
        model.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        String activationId = null;
        boolean layer2ResponseOk = false;
        boolean layer1ResponseOk = false;
        // Verify decrypted responses
        for (StepItem item: stepLogger.getItems()) {
            if (item.name().equals("Decrypted Layer 2 Response")) {
                final ActivationLayer2Response layer2Response = (ActivationLayer2Response) item.object();
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
            if (item.name().equals("Decrypted Layer 1 Response")) {
                final ActivationLayer1Response layer1Response = (ActivationLayer1Response) item.object();
                // Verify custom attributes, there should be no change
                assertEquals("value", layer1Response.getCustomAttributes().get("key"));
                layer1ResponseOk = true;
            }
        }

        assertTrue(layer1ResponseOk);
        assertTrue(layer2ResponseOk);

        powerAuthClient.removeActivation(activationId, "test");
    }

    public static void customActivationMissingUsernameTest(PowerAuthTestConfiguration config, CreateActivationStepModel model, ObjectStepLogger stepLogger) throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_4_MISSING_USERNAME");

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("key", "value");

        model.setIdentityAttributes(identityAttributes);
        model.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
    }

    public static void customActivationEmptyUsernameTest(PowerAuthTestConfiguration config, CreateActivationStepModel model, ObjectStepLogger stepLogger) throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_5_EMPTY_USERNAME");
        identityAttributes.put("username", "");

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("key", "value");

        model.setIdentityAttributes(identityAttributes);
        model.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
    }

    public static void customActivationUsernameTooLongTest(PowerAuthTestConfiguration config, CreateActivationStepModel model, ObjectStepLogger stepLogger) throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_6_USERNAME_TOO_LONG");
        identityAttributes.put("username", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");

        Map<String, Object> customAttributes = new HashMap<>();
        customAttributes.put("key", "value");

        model.setIdentityAttributes(identityAttributes);
        model.setCustomAttributes(customAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
    }

    public static void customActivationBadMasterPublicKeyTest(PowerAuthTestConfiguration config, CreateActivationStepModel model, ObjectStepLogger stepLogger) throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_7_BAD_MASTER_PUBLIC_KEY");
        model.setIdentityAttributes(identityAttributes);

        KeyPair keyPair = new KeyGenerator().generateKeyPair();
        PublicKey originalKey = model.getMasterPublicKey();

        // Set bad master public key
        model.setMasterPublicKey(keyPair.getPublic());

        // Create activation
        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());

        // Revert master public key change
        model.setMasterPublicKey(originalKey);
    }

    public static void customActivationUnsupportedApplicationTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, CreateActivationStepModel model, ObjectStepLogger stepLogger) throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_8_UNSUPPORTED_APP_VERSION");
        model.setIdentityAttributes(identityAttributes);

        // Unsupport application version
        powerAuthClient.unsupportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        // Verify that application version is unsupported
        final GetApplicationDetailResponse detailResponse = powerAuthClient.getApplicationDetail(config.getApplicationId());
        for (ApplicationVersion version: detailResponse.getVersions()) {
            if (version.getApplicationVersionId().equals(config.getApplicationVersion())) {
                assertFalse(version.isSupported());
            }
        }

        // Create activation
        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());

        // Support application version
        powerAuthClient.supportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        // Verify that application version is supported
        GetApplicationDetailResponse detailResponse2 = powerAuthClient.getApplicationDetail(config.getApplicationId());
        for (ApplicationVersion version: detailResponse2.getVersions()) {
            if (version.getApplicationVersionId().equals(config.getApplicationVersion())) {
                assertTrue(version.isSupported());
            }
        }
    }

    public static void customActivationInvalidApplicationKeyTest(PowerAuthTestConfiguration config, CreateActivationStepModel model, ObjectStepLogger stepLogger) throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_8_INVALID_APP_KEY");
        model.setIdentityAttributes(identityAttributes);

        model.setApplicationKey("invalid");

        // Verify that CreateActivation fails
        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());

        model.setApplicationKey(config.getApplicationKey());
    }

    public static void customActivationInvalidApplicationSecretTest(PowerAuthTestConfiguration config, CreateActivationStepModel model, ObjectStepLogger stepLogger) throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_8_INVALID_APP_SECRET");
        model.setIdentityAttributes(identityAttributes);

        model.setApplicationSecret("invalid");

        // Verify that CreateActivation fails
        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());

        // Verify error response
        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());

        model.setApplicationSecret(config.getApplicationSecret());
    }

    public static void customActivationDoubleCommitTest(PowerAuthClient powerAuthClient, CreateActivationStepModel model, ObjectStepLogger stepLogger) throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_9_DOUBLE_COMMIT");
        identityAttributes.put("username", "TestUser1");
        model.setIdentityAttributes(identityAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        String activationId = null;
        boolean layer2ResponseOk = false;
        boolean layer1ResponseOk = false;
        // Verify decrypted responses
        for (StepItem item: stepLogger.getItems()) {
            if (item.name().equals("Decrypted Layer 2 Response")) {
                final ActivationLayer2Response layer2Response = (ActivationLayer2Response) item.object();
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
            if (item.name().equals("Decrypted Layer 1 Response")) {
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

    public static void customActivationSignatureMaxFailedTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config,
                                                              CreateActivationStepModel model, ObjectStepLogger stepLogger,
                                                              File dataFile, File tempStatusFile, Integer port, String version) throws Exception {
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_10_SIGNATURES_MAX_FAILED");
        identityAttributes.put("username", "TestUser1");

        model.setIdentityAttributes(identityAttributes);

        new CreateActivationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        String activationId = null;
        boolean layer2ResponseOk = false;
        boolean layer1ResponseOk = false;
        // Verify decrypted responses
        for (StepItem item: stepLogger.getItems()) {
            if (item.name().equals("Decrypted Layer 2 Response")) {
                final ActivationLayer2Response layer2Response = (ActivationLayer2Response) item.object();
                activationId = layer2Response.getActivationId();
                assertNotNull(activationId);
                layer2ResponseOk = true;
                continue;
            }
            if (item.name().equals("Decrypted Layer 1 Response")) {
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
        signatureModel.setResultStatusObject(config.getResultStatusObject(version));
        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        signatureModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        signatureModel.setUriString("http://localhost:" + port + "/pa/v3/signature/validate");
        signatureModel.setVersion(version);

        signatureModel.setPassword("1111");

        // Fail 2 signatures (configured value for maximum failed count is 3)
        for (int i = 0; i < 2; i++) {
            ObjectStepLogger stepLoggerSignature = new ObjectStepLogger();
            new VerifySignatureStep().execute(stepLoggerSignature, signatureModel.toMap());
            assertFalse(stepLoggerSignature.getResult().success());
            assertEquals(401, stepLoggerSignature.getResponse().statusCode());
        }

        // Last signature before max failed attempts should be successful
        signatureModel.setPassword(config.getPassword());
        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifySignatureStep().execute(stepLogger2, signatureModel.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        // Fail 3 signatures (configured value for maximum failed count is 3)
        signatureModel.setPassword("1111");
        for (int i = 0; i < 3; i++) {
            ObjectStepLogger stepLoggerSignature = new ObjectStepLogger();
            new VerifySignatureStep().execute(stepLoggerSignature, signatureModel.toMap());
            assertFalse(stepLoggerSignature.getResult().success());
            assertEquals(401, stepLoggerSignature.getResponse().statusCode());
        }

        // Activation should be blocked
        GetActivationStatusResponse statusResponseBlocked = powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.BLOCKED, statusResponseBlocked.getActivationStatus());

        powerAuthClient.removeActivation(activationId, "test");
    }
}
