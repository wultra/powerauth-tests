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

import com.wultra.security.powerauth.webflow.configuration.WebFlowTestConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WebFlowTestConfiguration.class)
@EnableConfigurationProperties
public class WebFlowConfigurationTest {

    private WebFlowTestConfiguration config;

    @Autowired
    public void setWebFlowTestConfiguration(WebFlowTestConfiguration config) {
        this.config = config;
    }

    @Test
    public void applicationSetUpTest() {
        assertNotNull(config.getApplicationId());
        assertNotNull(config.getApplicationVersionId());
        assertNotNull(config.getMasterPublicKey());
        assertNotNull(config.getApplicationKey());
        assertNotEquals("", config.getApplicationKey());
        assertNotNull(config.getApplicationSecret());
        assertNotEquals("", config.getApplicationSecret());
        assertNotNull(config.getActivationId());
    }

    @Test
    public void activationSetUpTest() {
        assertNotNull(config.getStatusFile());
        assertNotNull(config.getResultStatusObject());
    }

}
