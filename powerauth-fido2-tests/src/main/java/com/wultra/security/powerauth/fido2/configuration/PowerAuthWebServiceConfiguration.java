/*
 * PowerAuth test and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

package com.wultra.security.powerauth.fido2.configuration;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.fido2.client.PowerAuthFido2Client;
import com.wultra.security.powerauth.fido2.model.error.PowerAuthFido2Exception;
import com.wultra.security.powerauth.rest.client.PowerAuthFido2RestClient;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClient;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClientConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

/**
 * PowerAuth service configuration class.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Configuration
public class PowerAuthWebServiceConfiguration {

    @Bean
    public PowerAuthClient powerAuthClient(final PowerAuthConfigProperties properties) throws PowerAuthClientException {
        final String powerAuthServiceUrl = properties.getBaseUrl() + "/rest";
        if (StringUtils.hasText(properties.getSecurity().clientToken())) {
            final PowerAuthRestClientConfiguration config = new PowerAuthRestClientConfiguration();
            config.setPowerAuthClientToken(properties.getSecurity().clientToken());
            config.setPowerAuthClientSecret(properties.getSecurity().clientSecret());
            return new PowerAuthRestClient(powerAuthServiceUrl, config);
        }
        return new PowerAuthRestClient(powerAuthServiceUrl);
    }

    @Bean
    public PowerAuthFido2Client powerAuthFido2Client(final PowerAuthConfigProperties properties) throws PowerAuthFido2Exception {
        if (StringUtils.hasText(properties.getSecurity().clientToken())) {
            final PowerAuthRestClientConfiguration config = new PowerAuthRestClientConfiguration();
            config.setPowerAuthClientToken(properties.getSecurity().clientToken());
            config.setPowerAuthClientSecret(properties.getSecurity().clientSecret());
            return new PowerAuthFido2RestClient(properties.getBaseUrl(), config);
        }
        return new PowerAuthFido2RestClient(properties.getBaseUrl());
    }

}
