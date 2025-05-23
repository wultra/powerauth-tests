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
package com.wultra.security.powerauth.test.v3x;

import com.wultra.core.rest.client.base.RestClientException;
import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.client.model.entity.CallbackUrl;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.response.GetCallbackUrlListResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthCallbackShared;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.test.context.junit.jupiter.SpringExtension;

/**
 * Callback tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnableConfigurationProperties
@ComponentScan(basePackages = "com.wultra.security.powerauth")
class PowerAuthCallbackTest {

    // Test only in the latestPowerAuth protocol version
    private static final PowerAuthVersion VERSION = PowerAuthVersion.V3_3;

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
    void tearDown() throws PowerAuthClientException {
        // Remove all callbacks on test application, they slow down tests
        final GetCallbackUrlListResponse callbacks = powerAuthClient.getCallbackUrlList(config.getApplicationId());
        for (CallbackUrl callback: callbacks.getCallbackUrlList()) {
            powerAuthClient.removeCallbackUrl(callback.getId());
        }
    }

    @Test
    void callbackExecutionTest() throws PowerAuthClientException, RestClientException {
        PowerAuthCallbackShared.callbackExecutionTest(powerAuthClient, config, port, VERSION);
    }

}
