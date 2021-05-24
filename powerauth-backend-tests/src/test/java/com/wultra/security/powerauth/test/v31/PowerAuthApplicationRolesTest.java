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
import com.wultra.security.powerauth.client.v3.GetApplicationDetailResponse;
import com.wultra.security.powerauth.client.v3.ListApplicationRolesResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Application roles tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthApplicationRolesTest {

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
    public void applicationRolesCrudTest() throws Exception {
        // Test application roles CRUD
        long applicationId = config.getApplicationId();

        // Remove all existing roles
        ListApplicationRolesResponse initResponse = powerAuthClient.listApplicationRoles(applicationId);
        if (!initResponse.getApplicationRoles().isEmpty()) {
            powerAuthClient.removeApplicationRoles(applicationId, initResponse.getApplicationRoles());
        }

        powerAuthClient.addApplicationRoles(applicationId, Arrays.asList("ROLE1", "ROLE2"));

        GetApplicationDetailResponse response = powerAuthClient.getApplicationDetail(applicationId);
        assertEquals(Arrays.asList("ROLE1", "ROLE2"), response.getApplicationRoles());

        ListApplicationRolesResponse listResponse = powerAuthClient.listApplicationRoles(applicationId);
        assertEquals(Arrays.asList("ROLE1", "ROLE2"), listResponse.getApplicationRoles());

        powerAuthClient.updateApplicationRoles(applicationId, Arrays.asList("ROLE3", "ROLE4"));

        ListApplicationRolesResponse listResponse2 = powerAuthClient.listApplicationRoles(applicationId);
        assertEquals(Arrays.asList("ROLE3", "ROLE4"), listResponse2.getApplicationRoles());

        powerAuthClient.removeApplicationRoles(applicationId, Collections.singletonList("ROLE4"));

        ListApplicationRolesResponse listResponse3 = powerAuthClient.listApplicationRoles(applicationId);
        assertEquals(Collections.singletonList("ROLE3"), listResponse3.getApplicationRoles());

        powerAuthClient.addApplicationRoles(applicationId, Arrays.asList("ROLE3", "ROLE4"));

        ListApplicationRolesResponse listResponse4 = powerAuthClient.listApplicationRoles(applicationId);
        assertEquals(Arrays.asList("ROLE3", "ROLE4"), listResponse4.getApplicationRoles());
    }
}
