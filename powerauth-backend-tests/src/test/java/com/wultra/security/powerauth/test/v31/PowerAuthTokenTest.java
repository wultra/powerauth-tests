/*
 * PowerAuth test and related software components
 * Copyright (C) 2019 Wultra s.r.o.
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
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthTokenTest {

    private PowerAuthTestConfiguration config;
    private NextStepClient nextStepClient;
    private PowerAuthClient powerAuthClient;
    private CreateTokenStepModel model;
    private ObjectStepLogger stepLogger;

    private static File dataFile;

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Autowired
    public void setNextStepClient(NextStepClient nextStepClient) {
        this.nextStepClient = nextStepClient;
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
    void setUp() {
        model = new CreateTokenStepModel();
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setHeaders(new HashMap<>());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setPassword(config.getPassword());
        model.setResultStatusObject(config.getResultStatusObjectV31());
        model.setStatusFileName(config.getStatusFileV31().getAbsolutePath());
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        model.setVersion("3.1");

        stepLogger = new ObjectStepLogger(System.out);
    }

    @Test
    void tokenCreateAndVerifyTest() throws Exception {
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

        if (isWebFlowRunning()) {
            Map<String, String> configNS = new HashMap<>();
            configNS.put("activationId", config.getActivationIdV31());
            ObjectResponse<GetAuthMethodsResponse> responseNS = nextStepClient.enableAuthMethodForUser(config.getUserV31(), AuthMethod.POWERAUTH_TOKEN, configNS);
            assertEquals("OK", responseNS.getStatus());
        }

        VerifyTokenStepModel modelVerify = new VerifyTokenStepModel();
        modelVerify.setTokenId(tokenId);
        modelVerify.setTokenSecret(tokenSecret);
        modelVerify.setHeaders(new HashMap<>());
        modelVerify.setResultStatusObject(config.getResultStatusObjectV31());
        modelVerify.setUriString(getTokenUri());
        modelVerify.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));
        modelVerify.setHttpMethod("POST");
        modelVerify.setVersion("3.1");

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifyTokenStep().execute(stepLogger2, modelVerify.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());

        final Map<String, Object> responseOK = (Map<String, Object>) stepLogger2.getResponse().responseObject();
        assertEquals("OK", responseOK.get("status"));
    }

    @Test
    void tokenCreateInvalidPasswordTest() throws Exception {
        model.setPassword("1235");

        new CreateTokenStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);
    }

    @Test
    void tokenVerifyInvalidTokenTest() throws Exception {
        VerifyTokenStepModel modelVerify = new VerifyTokenStepModel();
        modelVerify.setTokenId("test");
        modelVerify.setTokenSecret("test");
        modelVerify.setHeaders(new HashMap<>());
        modelVerify.setResultStatusObject(config.getResultStatusObjectV31());
        modelVerify.setUriString(getTokenUri());
        modelVerify.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));
        modelVerify.setHttpMethod("POST");
        modelVerify.setVersion("3.1");

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifyTokenStep().execute(stepLogger2, modelVerify.toMap());
        assertFalse(stepLogger2.getResult().success());
        assertEquals(401, stepLogger2.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger2.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);
    }

    @Test
    void tokenVerifyRemovedTokenTest() throws Exception {
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

        if (isWebFlowRunning()) {
            Map<String, String> configNS = new HashMap<>();
            configNS.put("activationId", config.getActivationIdV31());
            ObjectResponse<GetAuthMethodsResponse> responseNS = nextStepClient.enableAuthMethodForUser(config.getUserV31(), AuthMethod.POWERAUTH_TOKEN, configNS);
            assertEquals("OK", responseNS.getStatus());
        }

        powerAuthClient.removeToken(tokenId, config.getActivationIdV31());

        VerifyTokenStepModel modelVerify = new VerifyTokenStepModel();
        modelVerify.setTokenId(tokenId);
        modelVerify.setTokenSecret(tokenSecret);
        modelVerify.setHeaders(new HashMap<>());
        modelVerify.setResultStatusObject(config.getResultStatusObjectV31());
        modelVerify.setUriString(getTokenUri());
        modelVerify.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));
        modelVerify.setHttpMethod("POST");
        modelVerify.setVersion("3.1");

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifyTokenStep().execute(stepLogger2, modelVerify.toMap());
        assertFalse(stepLogger2.getResult().success());
        assertEquals(401, stepLogger2.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger2.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);
    }

    @Test
    void tokenCreateBlockedActivationTest() throws Exception {
        powerAuthClient.blockActivation(config.getActivationIdV31(), "test", "test");

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new CreateTokenStep().execute(stepLogger1, model.toMap());
        assertFalse(stepLogger1.getResult().success());
        assertEquals(401, stepLogger1.getResponse().statusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        final ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().responseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        checkSignatureError(errorResponse);

        powerAuthClient.unblockActivation(config.getActivationIdV31(), "test");

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new CreateTokenStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().success());
        assertEquals(200, stepLogger2.getResponse().statusCode());
    }

    @Test
    void tokenUnsupportedApplicationTest() throws Exception {
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

    @Test
    void tokenCounterIncrementTest() throws Exception {
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        new CreateTokenStep().execute(this.stepLogger, model.toMap());
        assertTrue(this.stepLogger.getResult().success());
        assertEquals(200, this.stepLogger.getResponse().statusCode());

        // Verify counter after createToken
        byte[] ctrDataExpected = new HashBasedCounter().next(ctrData);
        assertArrayEquals(ctrDataExpected, CounterUtil.getCtrData(model, this.stepLogger));
    }

    private void checkSignatureError(ErrorResponse errorResponse) {
        // Errors differ when Web Flow is used because of its Exception handler
        assertTrue("POWERAUTH_AUTH_FAIL".equals(errorResponse.getResponseObject().getCode()) || "ERR_AUTHENTICATION".equals(errorResponse.getResponseObject().getCode()));
    }

    private String getTokenUri() {
        return config.getPowerAuthIntegrationUrl() + "/api/auth/token/app/operation/list";
    }

    private boolean isWebFlowRunning() {
        return config.getPowerAuthIntegrationUrl().contains("powerauth-webflow");
    }
}
