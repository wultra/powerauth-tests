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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.core.rest.model.base.response.Response;
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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthTokenTest {

    private PowerAuthTestConfiguration config;
    private NextStepClient nextStepClient;
    private PowerAuthServiceClient powerAuthClient;
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
    public void setPowerAuthServiceClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @BeforeClass
    public static void setUpBeforeClass() throws IOException {
        dataFile = File.createTempFile("data", ".json");
        FileWriter fw = new FileWriter(dataFile);
        fw.write("All your base are belong to us!");
        fw.close();
    }

    @AfterClass
    public static void tearDownAfterClass() {
        assertTrue(dataFile.delete());
    }

    @Before
    public void setUp() {
        model = new CreateTokenStepModel();
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setHeaders(new HashMap<>());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setPassword(config.getPassword());
        model.setResultStatusObject(config.getResultStatusObjectV3());
        model.setStatusFileName(config.getStatusFileV3().getAbsolutePath());
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        model.setVersion("3.0");

        stepLogger = new ObjectStepLogger(System.out);
    }

    @Test
    public void tokenCreateAndVerifyTest() throws Exception {
        ObjectStepLogger stepLogger1 = new ObjectStepLogger();
        new CreateTokenStep().execute(stepLogger1, model.toMap());
        assertTrue(stepLogger1.getResult().isSuccess());
        assertEquals(200, stepLogger1.getResponse().getStatusCode());

        String tokenId = null;
        String tokenSecret = null;
        for (StepItem item: stepLogger1.getItems()) {
            if (item.getName().equals("Token successfully obtained")) {
                Map<String, Object> responseMap = (Map<String, Object>) item.getObject();
                tokenId = (String) responseMap.get("tokenId");
                tokenSecret = (String) responseMap.get("tokenSecret");
                break;
            }
        }

        assertNotNull(tokenId);
        assertNotNull(tokenSecret);

        Map<String, String> configNS = new HashMap<>();
        configNS.put("activationId", config.getActivationIdV3());
        ObjectResponse<GetAuthMethodsResponse> responseNS = nextStepClient.enableAuthMethodForUser("test_v3", AuthMethod.POWERAUTH_TOKEN, configNS);
        assertEquals("OK", responseNS.getStatus());

        VerifyTokenStepModel modelVerify = new VerifyTokenStepModel();
        modelVerify.setTokenId(tokenId);
        modelVerify.setTokenSecret(tokenSecret);
        modelVerify.setHeaders(new HashMap<>());
        modelVerify.setResultStatusObject(config.getResultStatusObjectV3());
        modelVerify.setUriString(config.getPowerAuthIntegrationUrl() + "/api/auth/token/app/operation/list");
        modelVerify.setDataFileName(dataFile.getAbsolutePath());
        modelVerify.setHttpMethod("POST");
        modelVerify.setVersion("3.0");

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifyTokenStep().execute(stepLogger2, modelVerify.toMap());
        assertTrue(stepLogger2.getResult().isSuccess());
        assertEquals(200, stepLogger2.getResponse().getStatusCode());

        Response responseOK = (Response) stepLogger2.getResponse().getResponseObject();
        assertEquals("OK", responseOK.getStatus());
    }

    @Test
    public void tokenCreateInvalidPasswordTest() throws Exception {
        model.setPassword("1235");

        new CreateTokenStep().execute(stepLogger, model.toMap());
        assertFalse(stepLogger.getResult().isSuccess());
        assertEquals(401, stepLogger.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("POWERAUTH_AUTH_FAIL", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_SIGNATURE_INVALID", errorResponse.getResponseObject().getMessage());
    }

    @Test
    public void tokenVerifyInvalidTokenTest() throws Exception {
        VerifyTokenStepModel modelVerify = new VerifyTokenStepModel();
        modelVerify.setTokenId("test");
        modelVerify.setTokenSecret("test");
        modelVerify.setHeaders(new HashMap<>());
        modelVerify.setResultStatusObject(config.getResultStatusObjectV3());
        modelVerify.setUriString(config.getPowerAuthIntegrationUrl() + "/api/auth/token/app/operation/list");
        modelVerify.setDataFileName(dataFile.getAbsolutePath());
        modelVerify.setHttpMethod("POST");
        modelVerify.setVersion("3.0");

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifyTokenStep().execute(stepLogger2, modelVerify.toMap());
        assertFalse(stepLogger2.getResult().isSuccess());
        assertEquals(401, stepLogger2.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger2.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("POWERAUTH_AUTH_FAIL", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_SIGNATURE_INVALID", errorResponse.getResponseObject().getMessage());
    }

    @Test
    public void tokenVerifyRemovedTokenTest() throws Exception {
        ObjectStepLogger stepLogger1 = new ObjectStepLogger();
        new CreateTokenStep().execute(stepLogger1, model.toMap());
        assertTrue(stepLogger1.getResult().isSuccess());
        assertEquals(200, stepLogger1.getResponse().getStatusCode());

        String tokenId = null;
        String tokenSecret = null;
        for (StepItem item: stepLogger1.getItems()) {
            if (item.getName().equals("Token successfully obtained")) {
                Map<String, Object> responseMap = (Map<String, Object>) item.getObject();
                tokenId = (String) responseMap.get("tokenId");
                tokenSecret = (String) responseMap.get("tokenSecret");
                break;
            }
        }

        assertNotNull(tokenId);
        assertNotNull(tokenSecret);

        Map<String, String> configNS = new HashMap<>();
        configNS.put("activationId", config.getActivationIdV3());
        ObjectResponse<GetAuthMethodsResponse> responseNS = nextStepClient.enableAuthMethodForUser("test", AuthMethod.POWERAUTH_TOKEN, configNS);
        assertEquals("OK", responseNS.getStatus());

        powerAuthClient.removeToken(tokenId, config.getActivationIdV3());

        VerifyTokenStepModel modelVerify = new VerifyTokenStepModel();
        modelVerify.setTokenId(tokenId);
        modelVerify.setTokenSecret(tokenSecret);
        modelVerify.setHeaders(new HashMap<>());
        modelVerify.setResultStatusObject(config.getResultStatusObjectV3());
        modelVerify.setUriString(config.getPowerAuthIntegrationUrl() + "/api/auth/token/app/operation/list");
        modelVerify.setDataFileName(dataFile.getAbsolutePath());
        modelVerify.setHttpMethod("POST");
        modelVerify.setVersion("3.0");

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new VerifyTokenStep().execute(stepLogger2, modelVerify.toMap());
        assertFalse(stepLogger2.getResult().isSuccess());
        assertEquals(401, stepLogger2.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger2.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("POWERAUTH_AUTH_FAIL", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_SIGNATURE_INVALID", errorResponse.getResponseObject().getMessage());
    }

    @Test
    public void tokenCreateBlockedActivationTest() throws Exception {
        powerAuthClient.blockActivation(config.getActivationIdV3(), "test");

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new CreateTokenStep().execute(stepLogger1, model.toMap());
        assertFalse(stepLogger1.getResult().isSuccess());
        assertEquals(401, stepLogger1.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("POWERAUTH_AUTH_FAIL", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_SIGNATURE_INVALID", errorResponse.getResponseObject().getMessage());

        powerAuthClient.unblockActivation(config.getActivationIdV3());

        ObjectStepLogger stepLogger2 = new ObjectStepLogger();
        new CreateTokenStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().isSuccess());
        assertEquals(200, stepLogger2.getResponse().getStatusCode());
    }

    @Test
    public void tokenUnsupportedApplicationTest() throws Exception {
        powerAuthClient.unsupportApplicationVersion(config.getApplicationVersionId());

        ObjectStepLogger stepLogger1 = new ObjectStepLogger(System.out);
        new CreateTokenStep().execute(stepLogger1, model.toMap());
        assertFalse(stepLogger1.getResult().isSuccess());
        assertEquals(401, stepLogger1.getResponse().getStatusCode());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(stepLogger1.getResponse().getResponseObject().toString(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("POWERAUTH_AUTH_FAIL", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_SIGNATURE_INVALID", errorResponse.getResponseObject().getMessage());

        powerAuthClient.supportApplicationVersion(config.getApplicationVersionId());

        ObjectStepLogger stepLogger2 = new ObjectStepLogger(System.out);
        new CreateTokenStep().execute(stepLogger2, model.toMap());
        assertTrue(stepLogger2.getResult().isSuccess());
        assertEquals(200, stepLogger2.getResponse().getStatusCode());

        EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger2.getResponse().getResponseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());
    }

    @Test
    public void tokenCounterIncrementTest() throws Exception {
        byte[] ctrData = CounterUtil.getCtrData(model, stepLogger);
        new CreateTokenStep().execute(this.stepLogger, model.toMap());
        assertTrue(this.stepLogger.getResult().isSuccess());
        assertEquals(200, this.stepLogger.getResponse().getStatusCode());

        // Verify counter after createToken
        byte[] ctrDataExpected = new HashBasedCounter().next(ctrData);
        assertArrayEquals(ctrDataExpected, CounterUtil.getCtrData(model, this.stepLogger));
    }

}
