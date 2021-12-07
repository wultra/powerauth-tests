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

import com.wultra.core.rest.client.base.RestClientException;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.CallbackUrlType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.v3.GetCallbackUrlListResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.security.powerauth.lib.cmd.util.RestClientFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Callback tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnableConfigurationProperties
@ComponentScan(basePackages = {"com.wultra.security.powerauth", "io.getlime.security.powerauth"})
public class PowerAuthCallbackTest {

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;

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

    @AfterEach
    public void tearDown() throws PowerAuthClientException {
        // Remove all callbacks on test application, they slow down tests
        List<GetCallbackUrlListResponse.CallbackUrlList> callbacks = powerAuthClient.getCallbackUrlList(config.getApplicationId());
        for (GetCallbackUrlListResponse.CallbackUrlList callback: callbacks) {
            powerAuthClient.removeCallbackUrl(callback.getId());
        }
    }

    @Test
    public void callbackCreateDeleteTest() throws PowerAuthClientException {
        String callbackName = UUID.randomUUID().toString();
        String callbackUrl = "http://test.test";
        powerAuthClient.createCallbackUrl(config.getApplicationId(), callbackName, CallbackUrlType.ACTIVATION_STATUS_CHANGE, callbackUrl, Collections.singletonList("activationId"));
        List<GetCallbackUrlListResponse.CallbackUrlList> callbacks = powerAuthClient.getCallbackUrlList(config.getApplicationId());
        boolean callbackFound = false;
        for (GetCallbackUrlListResponse.CallbackUrlList callback: callbacks) {
            if (callbackName.equals(callback.getName())) {
                callbackFound = true;
                assertEquals(callbackUrl, callback.getCallbackUrl());
                assertEquals(config.getApplicationId(), callback.getApplicationId());
                assertEquals(1, callback.getAttributes().size());
                assertEquals("activationId", callback.getAttributes().get(0));
                int callbackCountOrig = callbacks.size();
                powerAuthClient.removeCallbackUrl(callback.getId());
                assertEquals(callbackCountOrig - 1, powerAuthClient.getCallbackUrlList(config.getApplicationId()).size());
            }
        }
        assertTrue(callbackFound);
    }

    @Test
    public void callbackUpdateTest() throws PowerAuthClientException {
        String callbackName = UUID.randomUUID().toString();
        String callbackUrl = "http://test.test";
        powerAuthClient.createCallbackUrl(config.getApplicationId(), callbackName, CallbackUrlType.ACTIVATION_STATUS_CHANGE, callbackUrl, Collections.singletonList("activationId"));
        List<GetCallbackUrlListResponse.CallbackUrlList> callbacks = powerAuthClient.getCallbackUrlList(config.getApplicationId());
        boolean callbackFound = false;
        String callbackId = null;
        for (GetCallbackUrlListResponse.CallbackUrlList callback: callbacks) {
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
        powerAuthClient.updateCallbackUrl(callbackId, config.getApplicationId(), callbackName2, callbackUrl2, Arrays.asList("activationId", "userId", "deviceInfo", "platform"));
        List<GetCallbackUrlListResponse.CallbackUrlList> callbacks2 = powerAuthClient.getCallbackUrlList(config.getApplicationId());
        boolean callbackFound2 = false;
        for (GetCallbackUrlListResponse.CallbackUrlList callback: callbacks2) {
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
        int callbackCountOrig = callbacks.size();
        powerAuthClient.removeCallbackUrl(callbackId);
        assertEquals(callbackCountOrig - 1, powerAuthClient.getCallbackUrlList(config.getApplicationId()).size());
    }

    @Test
    public void callbackExecutionTest() throws PowerAuthClientException, RestClientException {
        // Skip test when the tested PA server is not running on localhost
        assumeTrue(config.getPowerAuthRestUrl().contains("localhost"));
        String callbackName = UUID.randomUUID().toString();
        String callbackUrlPost = "http://localhost:" + port + "/callback/post";
        powerAuthClient.createCallbackUrl(config.getApplicationId(), callbackName, CallbackUrlType.ACTIVATION_STATUS_CHANGE, callbackUrlPost, Arrays.asList("activationId", "userId", "activationName", "deviceInfo", "platform", "activationFlags", "activationStatus", "blockedReason", "applicationId"));
        List<GetCallbackUrlListResponse.CallbackUrlList> callbacks = powerAuthClient.getCallbackUrlList(config.getApplicationId());
        // Update activation status
        powerAuthClient.blockActivation(config.getActivationIdV31(), "TEST_CALLBACK", config.getUserV31());
        String callbackUrlVerify = "http://localhost:" + port + "/callback/verify";
        // When a HTTP error occurs, the test fails
        Map<String, Object> request = new HashMap<>();
        request.put("activationId", config.getActivationIdV31());
        request.put("userId", config.getUserV31());
        request.put("activationName", "test v31");
        request.put("deviceInfo", "backend-tests");
        request.put("platform", "unknown");
        request.put("activationFlags", Collections.emptyList());
        request.put("activationStatus", "BLOCKED");
        request.put("blockedReason", "TEST_CALLBACK");
        request.put("applicationId", config.getApplicationId());
        RestClientFactory.getRestClient().post(callbackUrlVerify, request, new ParameterizedTypeReference<String>() {});
        powerAuthClient.unblockActivation(config.getActivationIdV31(), config.getUserV31());
        boolean callbackFound = false;
        for (GetCallbackUrlListResponse.CallbackUrlList callback: callbacks) {
            if (callbackName.equals(callback.getName())) {
                callbackFound = true;
                int callbackCountOrig = callbacks.size();
                powerAuthClient.removeCallbackUrl(callback.getId());
                assertEquals(callbackCountOrig - 1, powerAuthClient.getCallbackUrlList(config.getApplicationId()).size());
            }
        }
        assertTrue(callbackFound);
    }
}
