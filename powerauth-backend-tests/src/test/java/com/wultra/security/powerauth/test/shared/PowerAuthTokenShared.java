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
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.VerifyTokenStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateTokenStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifyTokenStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.CreateTokenStep;
import io.getlime.security.powerauth.lib.cmd.util.CounterUtil;
import io.getlime.security.powerauth.lib.nextstep.client.NextStepClient;
import io.getlime.security.powerauth.lib.nextstep.model.enumeration.AuthMethod;
import io.getlime.security.powerauth.lib.nextstep.model.response.GetAuthMethodsResponse;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;

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

    public static void tokenCreateAndVerifyTest(final PowerAuthTestConfiguration config, final CreateTokenStepModel model, final NextStepClient nextStepClient, final File dataFile, final String version) throws Exception {
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

        if (isWebFlowRunning(config)) {
            Map<String, String> configNS = new HashMap<>();
            configNS.put("activationId", config.getActivationId(version));
            ObjectResponse<GetAuthMethodsResponse> responseNS = nextStepClient.enableAuthMethodForUser(config.getUser(version), AuthMethod.POWERAUTH_TOKEN, configNS);
            assertEquals("OK", responseNS.getStatus());
        }

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

    public static void tokenVerifyInvalidTokenTest(final PowerAuthTestConfiguration config, final File dataFile, final String version) throws Exception {
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

    public static void tokenVerifyRemovedTokenTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final CreateTokenStepModel model, final NextStepClient nextStepClient, final File dataFile, final String version) throws Exception {
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

        if (isWebFlowRunning(config)) {
            Map<String, String> configNS = new HashMap<>();
            configNS.put("activationId", config.getActivationId(version));
            ObjectResponse<GetAuthMethodsResponse> responseNS = nextStepClient.enableAuthMethodForUser(config.getUser(version), AuthMethod.POWERAUTH_TOKEN, configNS);
            assertEquals("OK", responseNS.getStatus());
        }

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

    public static void tokenCreateBlockedActivationTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final CreateTokenStepModel model, final String version) throws Exception {
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
        assertEquals(401, stepLogger1.getResponse().statusCode());

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

    public static void tokenCounterIncrementTest(final CreateTokenStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        new CreateTokenStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        // Verify counter after createToken
        byte[] ctrDataExpected = new HashBasedCounter().next(ctrData);
        assertArrayEquals(ctrDataExpected, CounterUtil.getCtrData(model, stepLogger));
    }

    private static void checkSignatureError(final ErrorResponse errorResponse) {
        // Errors differ when Web Flow is used because of its Exception handler
        assertTrue("POWERAUTH_AUTH_FAIL".equals(errorResponse.getResponseObject().getCode()) || "ERR_AUTHENTICATION".equals(errorResponse.getResponseObject().getCode()));
    }

    private static String getTokenUri(final PowerAuthTestConfiguration config) {
        return config.getPowerAuthIntegrationUrl() + "/api/auth/token/app/operation/list";
    }

    private static boolean isWebFlowRunning(final PowerAuthTestConfiguration config) {
        return config.getPowerAuthIntegrationUrl().contains("powerauth-webflow");
    }
}
