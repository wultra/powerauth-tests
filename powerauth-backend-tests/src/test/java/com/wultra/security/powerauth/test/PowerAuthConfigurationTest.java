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
package com.wultra.security.powerauth.test;

import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthConfigurationTest {

    private PowerAuthTestConfiguration config;

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Test
    public void applicationSetUpTest() {
        assertNotNull(config.getApplicationId());
        assertNotNull(config.getApplicationVersionId());
        assertNotNull(config.getMasterPublicKey());
        assertNotEquals("", config.getMasterPublicKey());
        assertNotNull(config.getApplicationKey());
        assertNotEquals("", config.getApplicationKey());
        assertNotNull(config.getApplicationSecret());
        assertNotEquals("", config.getApplicationSecret());
        assertNotNull(config.getActivationIdV2());
        assertNotNull(config.getActivationIdV3());
    }

    @Test
    public void activationSetUpTest() {
        assertNotNull(config.getStatusFileV2());
        assertNotNull(config.getResultStatusObjectV2());
        assertNotNull(config.getStatusFileV3());
        assertNotNull(config.getResultStatusObjectV3());

    }
}
