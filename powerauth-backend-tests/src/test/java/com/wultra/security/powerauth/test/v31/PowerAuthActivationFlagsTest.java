/*
 * PowerAuth test and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.v3.*;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.CreateActivationStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer2Response;
import org.json.simple.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.test.context.junit4.SpringRunner;

import javax.xml.datatype.DatatypeFactory;
import java.io.File;
import java.io.IOException;
import java.util.*;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

/**
 * Activation flag tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnableConfigurationProperties
@ComponentScan(basePackages = {"com.wultra.security.powerauth", "io.getlime.security.powerauth"})
public class PowerAuthActivationFlagsTest {

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private PrepareActivationStepModel model;
    private File tempStatusFile;

    @LocalServerPort
    private int port;

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Before
    public void setUp() throws IOException {
        // Create temp status file
        tempStatusFile = File.createTempFile("pa_status_v31", ".json");

        // Model shared among tests
        model = new PrepareActivationStepModel();
        model.setActivationName("test v31 flags");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(new JSONObject());
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("3.1");
        model.setDeviceInfo("backend-tests");
    }

    @After
    public void tearDown() {
        assertTrue(tempStatusFile.delete());
    }

    @Test
    public void activationFlagCrudTest() throws Exception {
        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV31());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Test flags CRUD
        String activationId = initResponse.getActivationId();
        powerAuthClient.addActivationFlags(activationId, Arrays.asList("FLAG1", "FLAG2"));

        GetActivationStatusResponse status = powerAuthClient.getActivationStatus(activationId);
        assertEquals(Arrays.asList("FLAG1", "FLAG2"), status.getActivationFlags());

        ListActivationFlagsResponse listResponse = powerAuthClient.listActivationFlags(activationId);
        assertEquals(Arrays.asList("FLAG1", "FLAG2"), listResponse.getActivationFlags());

        powerAuthClient.updateActivationFlags(activationId, Arrays.asList("FLAG3", "FLAG4"));

        ListActivationFlagsResponse listResponse2 = powerAuthClient.listActivationFlags(activationId);
        assertEquals(Arrays.asList("FLAG3", "FLAG4"), listResponse2.getActivationFlags());

        powerAuthClient.removeActivationFlags(activationId, Collections.singletonList("FLAG4"));

        ListActivationFlagsResponse listResponse3 = powerAuthClient.listActivationFlags(activationId);
        assertEquals(Collections.singletonList("FLAG3"), listResponse3.getActivationFlags());

        powerAuthClient.addActivationFlags(activationId, Arrays.asList("FLAG3", "FLAG4"));

        ListActivationFlagsResponse listResponse4 = powerAuthClient.listActivationFlags(activationId);
        assertEquals(Arrays.asList("FLAG3", "FLAG4"), listResponse4.getActivationFlags());
    }

    @Test
    public void activationFlagLookupTest() throws Exception {
        GregorianCalendar beforeActivation = new GregorianCalendar();
        beforeActivation.setTimeInMillis(System.currentTimeMillis() - 1000);
        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV31());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Test flag lookup
        String activationId = initResponse.getActivationId();
        LookupActivationsRequest lookupRequest = new LookupActivationsRequest();
        lookupRequest.getUserIds().add(config.getUserV31());
        lookupRequest.setTimestampLastUsedAfter(DatatypeFactory.newInstance().newXMLGregorianCalendar(beforeActivation));
        lookupRequest.getActivationFlags().add("FLAG1");
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupRequest);
        assertTrue(response.getActivations().isEmpty());

        powerAuthClient.addActivationFlags(activationId, Arrays.asList("FLAG1", "FLAG2"));
        LookupActivationsResponse response2 = powerAuthClient.lookupActivations(lookupRequest);
        assertEquals(1, response2.getActivations().size());

        powerAuthClient.removeActivationFlags(activationId, Collections.singletonList("FLAG1"));
        LookupActivationsResponse response3 = powerAuthClient.lookupActivations(lookupRequest);
        assertTrue(response3.getActivations().isEmpty());

        powerAuthClient.addActivationFlags(activationId, Arrays.asList("FLAG3", "FLAG4"));
        lookupRequest.getActivationFlags().clear();
        lookupRequest.getActivationFlags().add("FLAG3");
        lookupRequest.getActivationFlags().add("FLAG4");
        LookupActivationsResponse response4 = powerAuthClient.lookupActivations(lookupRequest);
        assertEquals(1, response4.getActivations().size());

        powerAuthClient.addActivationFlags(activationId, Arrays.asList("FLAG3", "FLAG4"));
        lookupRequest.getActivationFlags().add("FLAG5");
        LookupActivationsResponse response5 = powerAuthClient.lookupActivations(lookupRequest);
        assertTrue(response5.getActivations().isEmpty());
    }

    @Test
    public void activationProviderFlagTest() throws Exception {
        // Create custom activation with test provider
        CreateActivationStepModel model = new CreateActivationStepModel();
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

        // Set unique user identity
        final String userIdSuffix = UUID.randomUUID().toString();
        final String userId = "TestUser_Flags_"+userIdSuffix;
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("test_id", "TEST_1_SIMPLE_LOOKUP_COMMIT_PROCESS");
        identityAttributes.put("username", userId);
        model.setIdentityAttributes(identityAttributes);
        ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        new CreateActivationStep().execute(stepLogger, model.toMap());

        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        String activationId = null;
        // Verify decrypted responses
        for (StepItem item: stepLogger.getItems()) {
            if (item.getName().equals("Decrypted Layer 2 Response")) {
                ActivationLayer2Response layer2Response = (ActivationLayer2Response) item.getObject();
                activationId = layer2Response.getActivationId();
                break;
            }
        }

        LookupActivationsRequest lookupRequest = new LookupActivationsRequest();
        lookupRequest.getUserIds().add(userId);
        lookupRequest.getActivationFlags().add("TEST-PROVIDER");
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupRequest);
        assertEquals(1, response.getActivations().size());
        assertEquals(activationId, response.getActivations().get(0).getActivationId());
    }
}
