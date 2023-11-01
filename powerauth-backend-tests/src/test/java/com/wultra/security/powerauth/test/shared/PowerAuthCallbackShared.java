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

import com.wultra.core.rest.client.base.RestClientException;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.entity.CallbackUrl;
import com.wultra.security.powerauth.client.model.enumeration.CallbackUrlType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.response.GetCallbackUrlListResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.security.powerauth.lib.cmd.util.RestClientFactory;
import org.springframework.core.ParameterizedTypeReference;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Callback test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthCallbackShared {

    public static void callbackCreateDeleteTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config) throws PowerAuthClientException {
        String callbackName = UUID.randomUUID().toString();
        String callbackUrl = "http://test.test";
        powerAuthClient.createCallbackUrl(config.getApplicationId(), callbackName, CallbackUrlType.ACTIVATION_STATUS_CHANGE, callbackUrl, Collections.singletonList("activationId"), null);
        final GetCallbackUrlListResponse callbacks = powerAuthClient.getCallbackUrlList(config.getApplicationId());
        boolean callbackFound = false;
        for (CallbackUrl callback: callbacks.getCallbackUrlList()) {
            if (callbackName.equals(callback.getName())) {
                callbackFound = true;
                assertEquals(callbackUrl, callback.getCallbackUrl());
                assertEquals(config.getApplicationId(), callback.getApplicationId());
                assertEquals(1, callback.getAttributes().size());
                assertEquals("activationId", callback.getAttributes().get(0));
                int callbackCountOrig = callbacks.getCallbackUrlList().size();
                powerAuthClient.removeCallbackUrl(callback.getId());
            }
        }
        assertTrue(callbackFound);
    }

    public static void callbackUpdateTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config) throws PowerAuthClientException {
        String callbackName = UUID.randomUUID().toString();
        String callbackUrl = "http://test.test";
        powerAuthClient.createCallbackUrl(config.getApplicationId(), callbackName, CallbackUrlType.ACTIVATION_STATUS_CHANGE, callbackUrl, Collections.singletonList("activationId"), null);
        final GetCallbackUrlListResponse callbacks = powerAuthClient.getCallbackUrlList(config.getApplicationId());
        boolean callbackFound = false;
        String callbackId = null;
        for (CallbackUrl callback: callbacks.getCallbackUrlList()) {
            if (callbackName.equals(callback.getName())) {
                callbackFound = true;
                callbackId = callback.getId();
                assertEquals(callbackUrl, callback.getCallbackUrl());
                assertEquals(config.getApplicationId(), callback.getApplicationId());
                assertEquals(1, callback.getAttributes().size());
                assertEquals("activationId", callback.getAttributes().get(0));
            }
        }
        assertTrue(callbackFound);
        assertNotNull(callbackId);
        String callbackName2 = UUID.randomUUID().toString();
        String callbackUrl2 = "http://test2.test2";
        powerAuthClient.updateCallbackUrl(callbackId, config.getApplicationId(), callbackName2, callbackUrl2, Arrays.asList("activationId", "userId", "deviceInfo", "platform"), null);
        final GetCallbackUrlListResponse callbacks2 = powerAuthClient.getCallbackUrlList(config.getApplicationId());
        boolean callbackFound2 = false;
        for (CallbackUrl callback: callbacks2.getCallbackUrlList()) {
            if (callbackName2.equals(callback.getName())) {
                callbackFound2 = true;
                callbackId = callback.getId();
                assertEquals(callbackUrl2, callback.getCallbackUrl());
                assertEquals(config.getApplicationId(), callback.getApplicationId());
                assertEquals(4, callback.getAttributes().size());
                assertEquals(Arrays.asList("activationId", "userId", "deviceInfo", "platform"), callback.getAttributes());
            }
        }
        assertTrue(callbackFound2);
        powerAuthClient.removeCallbackUrl(callbackId);
    }

    public static void callbackExecutionTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, Integer port, String version) throws PowerAuthClientException, RestClientException {
        // Skip test when the tested PA server is not running on localhost
        assumeTrue(config.getPowerAuthRestUrl().contains("localhost:8080"));
        String callbackName = UUID.randomUUID().toString();
        String callbackUrlPost = "http://localhost:" + port + "/callback/post";
        powerAuthClient.createCallbackUrl(config.getApplicationId(), callbackName, CallbackUrlType.ACTIVATION_STATUS_CHANGE, callbackUrlPost, Arrays.asList("activationId", "userId", "activationName", "deviceInfo", "platform", "activationFlags", "activationStatus", "blockedReason", "applicationId"), null);
        final GetCallbackUrlListResponse callbacks = powerAuthClient.getCallbackUrlList(config.getApplicationId());
        // Update activation status
        powerAuthClient.blockActivation(config.getActivationId(version), "TEST_CALLBACK", config.getUser(version));
        String callbackUrlVerify = "http://localhost:" + port + "/callback/verify";
        // When a HTTP error occurs, the test fails
        Map<String, Object> request = new HashMap<>();
        request.put("activationId", config.getActivationId(version));
        request.put("userId", config.getUser(version));
        request.put("activationName", "test v" + version);
        request.put("deviceInfo", "backend-tests");
        request.put("platform", "unknown");
        request.put("activationFlags", Collections.emptyList());
        request.put("activationStatus", "BLOCKED");
        request.put("blockedReason", "TEST_CALLBACK");
        request.put("applicationId", config.getApplicationId());
        RestClientFactory.getRestClient().post(callbackUrlVerify, request, new ParameterizedTypeReference<String>() {});
        powerAuthClient.unblockActivation(config.getActivationId(version), config.getUser(version));
        boolean callbackFound = false;
        for (CallbackUrl callback: callbacks.getCallbackUrlList()) {
            if (callbackName.equals(callback.getName())) {
                callbackFound = true;
                powerAuthClient.removeCallbackUrl(callback.getId());
            }
        }
        assertTrue(callbackFound);
    }
}
