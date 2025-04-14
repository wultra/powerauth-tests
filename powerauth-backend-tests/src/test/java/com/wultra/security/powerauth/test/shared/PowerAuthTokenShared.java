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
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.core.rest.model.base.response.ErrorResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.model.StepItem;
import com.wultra.security.powerauth.lib.cmd.steps.VerifyTokenStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.CreateTokenStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyTokenStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.CreateTokenStep;
import com.wultra.security.powerauth.lib.cmd.util.CounterUtil;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth token test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthTokenShared {

    public static void tokenCreateAndVerifyTest(final PowerAuthTestConfiguration config, final CreateTokenStepModel model, final File dataFile, final PowerAuthVersion version) throws Exception {
        ObjectStepLogger stepLogger1 = new ObjectStepLogger();
        new CreateTokenStep().execute(stepLogger1, model.toMap());
        assertTrue(stepLogger1.getResult().success());
        assertEquals(200, stepLogger1.getResponse().statusCode());

        String tokenId = null;
        String tokenSecret = null;
        for (StepItem item: stepLogger1.getItems()) {
            if (item.name().equals("Token successfully obtained")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                tokenId = (String) responseMap.get("tokenId");
                tokenSecret = (String) responseMap.get("tokenSecret");
                break;
            }
        }

        assertNotNull(tokenId);
        assertNotNull(tokenSecret);

        VerifyTokenStepModel modelVerify = new VerifyTokenStepModel();
        modelVerify.setTokenId(tokenId);
        modelVerify.setTokenSecret(tokenSecret);
        modelVerify.setHeaders(new HashMap<>());
        modelVerify.setResultStatusObject(config.getResultStatusObject(version));
        modelVerify.setUriString(getTokenUri(config));
        modelVerify.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));
        modelVerify.setHttpMethod("POST");
        modelVerify.setVersion(version);

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifyTokenStep().execute(stepLogger2, modelVerify.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        final Map<String, Object> responseOK = (Map<String, Object>) stepLogger2.getResponse().responseObject();
        assertEquals("OK", responseOK.get("status"));
    }

    public static void tokenCreateInvalidPasswordTest(final PowerAuthTestConfiguration config, final CreateTokenStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        model.setPassword("1235");

        new CreateTokenStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);
    }

    public static void tokenVerifyInvalidTokenTest(final PowerAuthTestConfiguration config, final File dataFile, final PowerAuthVersion version) throws Exception {
        VerifyTokenStepModel modelVerify = new VerifyTokenStepModel();
        modelVerify.setTokenId("test");
        modelVerify.setTokenSecret("test");
        modelVerify.setHeaders(new HashMap<>());
        modelVerify.setResultStatusObject(config.getResultStatusObject(version));
        modelVerify.setUriString(getTokenUri(config));
        modelVerify.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));
        modelVerify.setHttpMethod("POST");
        modelVerify.setVersion(version);

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifyTokenStep().execute(stepLogger2, modelVerify.toMap());
        assertFalse(stepLogger2.getResult().success());
        assertEquals(401, stepLogger2.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger2.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);
    }

    public static void tokenVerifyRemovedTokenTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final CreateTokenStepModel model, final File dataFile, final PowerAuthVersion version) throws Exception {
        ObjectStepLogger stepLogger1 = new ObjectStepLogger();
        new CreateTokenStep().execute(stepLogger1, model.toMap());
        assertTrue(stepLogger1.getResult().success());
        assertEquals(200, stepLogger1.getResponse().statusCode());

        String tokenId = null;
        String tokenSecret = null;
        for (StepItem item: stepLogger1.getItems()) {
            if (item.name().equals("Token successfully obtained")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                tokenId = (String) responseMap.get("tokenId");
                tokenSecret = (String) responseMap.get("tokenSecret");
                break;
            }
        }

        assertNotNull(tokenId);
        assertNotNull(tokenSecret);

        powerAuthClient.removeToken(tokenId, config.getActivationId(version));

        VerifyTokenStepModel modelVerify = new VerifyTokenStepModel();
        modelVerify.setTokenId(tokenId);
        modelVerify.setTokenSecret(tokenSecret);
        modelVerify.setHeaders(new HashMap<>());
        modelVerify.setResultStatusObject(config.getResultStatusObject(version));
        modelVerify.setUriString(getTokenUri(config));
        modelVerify.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));
        modelVerify.setHttpMethod("POST");
        modelVerify.setVersion(version);

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifyTokenStep().execute(stepLogger2, modelVerify.toMap());
        assertFalse(stepLogger2.getResult().success());
        assertEquals(401, stepLogger2.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger2.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);
    }

    public static void tokenCreateBlockedActivationTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final CreateTokenStepModel model, final PowerAuthVersion version) throws Exception {
        powerAuthClient.blockActivation(config.getActivationId(version), "test", "test");

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new CreateTokenStep().execute(stepLogger1, model.toMap());
        assertFalse(stepLogger1.getResult().success());
        assertEquals(401, stepLogger1.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);

        powerAuthClient.unblockActivation(config.getActivationId(version), "test");

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new CreateTokenStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());
    }

    public static void tokenUnsupportedApplicationTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final CreateTokenStepModel model) throws Exception {
        powerAuthClient.unsupportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new CreateTokenStep().execute(stepLogger1, model.toMap());
        assertFalse(stepLogger1.getResult().success());
        if (model.getVersion().useTemporaryKeys()) {
            assertEquals(400, stepLogger1.getResponse().statusCode());
        } else {
            assertEquals(401, stepLogger1.getResponse().statusCode());
        }

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);

        powerAuthClient.supportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());

        ObjectStepLogger stepLogger2 = new ObjectStepLogger(System.out);
        new CreateTokenStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        final EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger2.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());
    }

    public static void tokenCounterIncrementTest(final CreateTokenStepModel model, final ObjectStepLogger stepLogger, final PowerAuthVersion version) throws Exception {
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        new CreateTokenStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        // Verify counter after createToken
        byte[] ctrDataExpected = new HashBasedCounter(version.value()).next(ctrData);
        assertArrayEquals(ctrDataExpected, CounterUtil.getCtrData(model, stepLogger));
    }

    private static void checkSignatureError(final ErrorResponse errorResponse) {
        // Errors differ when Web Flow is used because of its Exception handler, for protocol version 3.3 temporary key error is present
        assertTrue("POWERAUTH_AUTH_FAIL".equals(errorResponse.getResponseObject().getCode()) || "ERR_AUTHENTICATION".equals(errorResponse.getResponseObject().getCode()) || "ERR_TEMPORARY_KEY".equals(errorResponse.getResponseObject().getCode()));
    }

    private static String getTokenUri(final PowerAuthTestConfiguration config) {
        return config.getPowerAuthIntegrationUrl() + "/api/auth/token/app/operation/list";
    }

}
