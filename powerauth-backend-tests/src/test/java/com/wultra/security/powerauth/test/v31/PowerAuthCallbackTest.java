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
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.v3.GetCallbackUrlListResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.hibernate.validator.internal.util.Contracts.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Callback tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthCallbackTest {

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Test
    public void callbackCreateDeleteTest() throws PowerAuthClientException {
        String callbackName = UUID.randomUUID().toString();
        String callbackUrl = "http://test.test";
        powerAuthClient.createCallbackUrl(config.getApplicationId(), callbackName, callbackUrl, Collections.singletonList("activationId"));
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
        powerAuthClient.createCallbackUrl(config.getApplicationId(), callbackName, callbackUrl, Collections.singletonList("activationId"));
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

}
