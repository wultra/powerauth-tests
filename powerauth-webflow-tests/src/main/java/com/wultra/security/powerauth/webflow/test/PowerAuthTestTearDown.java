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
package com.wultra.security.powerauth.webflow.test;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.webflow.configuration.WebFlowTestConfiguration;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Global test teardown.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthTestTearDown {

    private PowerAuthClient powerAuthClient;
    private WebFlowTestConfiguration config;

    @Autowired
    public void setPowerAuthServiceClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setWebFlowTestConfiguration(WebFlowTestConfiguration config) {
        this.config = config;
    }

    public void execute() throws PowerAuthClientException {
        powerAuthClient.removeActivation(config.getActivationId(), "test");
        assertTrue(config.getStatusFile().delete());
        try {
            config.getWebDriver().close();
            config.getWebDriver().quit();
        } catch (Exception ex) {
            // Ignore exceptions
        }
    }
}
