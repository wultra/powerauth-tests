/*
 * PowerAuth test and related software components
 * Copyright (C) 2022 Wultra s.r.o.
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

import com.wultra.app.enrollmentserver.api.model.enrollment.response.ConfigurationResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.client.RestTemplate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

/**
 * Test for enrollment configuration endpoint.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthEnrollmentConfigurationTest {

    @Autowired
    private PowerAuthTestConfiguration config;

    @Test
    void testConfiguration() {
        final String url = config.getEnrollmentServiceUrl() + "/api/configuration";
        final RestTemplate restTemplate = new RestTemplate();

        final ConfigurationResponse response = restTemplate.postForObject(url, null, Response.class).getResponseObject();

        assertThat(response.getMobileApplication().getAndroid().getMinimalVersion(), equalTo("1.4.0"));
        assertThat(response.getMobileApplication().getAndroid().getCurrentVersion(), equalTo("1.5.4"));
        assertThat(response.getMobileApplication().getIOs().getMinimalVersion(), equalTo("1.5.4"));
        assertThat(response.getMobileApplication().getIOs().getCurrentVersion(), equalTo("2.0.0"));
    }

    private static class Response extends ObjectResponse<ConfigurationResponse> {}
}
