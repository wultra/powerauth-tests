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
import com.wultra.security.powerauth.client.model.request.CreateCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.response.GetCallbackUrlListResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.util.RestClientFactory;
import org.springframework.core.ParameterizedTypeReference;

import java.util.*;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Callback test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthCallbackShared {

    public static void callbackExecutionTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, Integer port, PowerAuthVersion version) throws PowerAuthClientException, RestClientException {
        // Skip test when the tested PA server is not running on localhost
        assumeTrue(config.getPowerAuthRestUrl().contains("localhost:8080"));

        final CreateCallbackUrlRequest pasCreateCallbackUrlRequest = new CreateCallbackUrlRequest();
        pasCreateCallbackUrlRequest.setApplicationId(config.getApplicationId());
        pasCreateCallbackUrlRequest.setName(UUID.randomUUID().toString());
        pasCreateCallbackUrlRequest.setType(CallbackUrlType.ACTIVATION_STATUS_CHANGE);
        pasCreateCallbackUrlRequest.setCallbackUrl("http://localhost:" + port + "/callback/post");
        pasCreateCallbackUrlRequest.setAttributes(List.of("activationId", "userId", "activationName", "deviceInfo",
                "platform", "activationFlags", "activationStatus", "blockedReason", "applicationId"));
        powerAuthClient.createCallbackUrl(pasCreateCallbackUrlRequest);

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
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        powerAuthClient.unblockActivation(config.getActivationId(version), config.getUser(version));
        boolean callbackFound = false;
        for (CallbackUrl callback: callbacks.getCallbackUrlList()) {
            if (Objects.equals(pasCreateCallbackUrlRequest.getName(), callback.getName())) {
                callbackFound = true;
                powerAuthClient.removeCallbackUrl(callback.getId());
            }
        }
        assertTrue(callbackFound);
    }
}
