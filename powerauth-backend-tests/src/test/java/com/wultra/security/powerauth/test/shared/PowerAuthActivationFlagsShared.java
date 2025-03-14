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

import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.LookupActivationsRequest;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.v3.CreateActivationStep;
import com.wultra.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import com.wultra.security.powerauth.rest.api.model.response.ActivationLayer2Response;

import java.io.File;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Activation flag test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthActivationFlagsShared {

    public static void activationFlagCrudTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PrepareActivationStepModel model, PowerAuthVersion version) throws Exception {
        // Init activation
        final InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        final InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());

        // Commit activation
        final CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Test flags CRUD
        String activationId = initResponse.getActivationId();
        powerAuthClient.addActivationFlags(activationId, Arrays.asList("FLAG1", "FLAG2"));

        final GetActivationStatusResponse status = powerAuthClient.getActivationStatus(activationId);
        assertEquals(Arrays.asList("FLAG1", "FLAG2"), status.getActivationFlags());

        final ListActivationFlagsResponse listResponse = powerAuthClient.listActivationFlags(activationId);
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

    public static void activationFlagLookupTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PrepareActivationStepModel model, PowerAuthVersion version) throws Exception {
        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        model.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, model.toMap());

        // Obtain timestamp created
        GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        final Date timestampCreated = statusResponse.getTimestampCreated();

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Test flag lookup
        String activationId = initResponse.getActivationId();
        final LookupActivationsRequest lookupRequest = new LookupActivationsRequest();
        lookupRequest.getUserIds().add(config.getUser(version));
        lookupRequest.setTimestampLastUsedAfter(timestampCreated);
        lookupRequest.getActivationFlags().add("FLAG1");
        final LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupRequest);
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

    public static void activationProviderFlagTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, File tempStatusFile, int port, PowerAuthVersion version) throws Exception {
        // Create custom activation with test provider
        CreateActivationStepModel model = new CreateActivationStepModel();
        model.setActivationName("test v" + version);
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(config.getResultStatusObject(version));
        model.setUriString("http://localhost:" + port);
        model.setVersion(version);
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

        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final String activationId = stepLogger.getItems().stream()
                .filter(item -> "Decrypted Layer 2 Response".equals(item.name()))
                .map(item -> (ActivationLayer2Response) item.object())
                .map(ActivationLayer2Response::getActivationId)
                .findAny()
                .orElse(null);

        LookupActivationsRequest lookupRequest = new LookupActivationsRequest();
        lookupRequest.getUserIds().add(userId);
        lookupRequest.getActivationFlags().add("TEST-PROVIDER");
        LookupActivationsResponse response = powerAuthClient.lookupActivations(lookupRequest);
        assertEquals(1, response.getActivations().size());
        assertEquals(activationId, response.getActivations().get(0).getActivationId());
    }
}
