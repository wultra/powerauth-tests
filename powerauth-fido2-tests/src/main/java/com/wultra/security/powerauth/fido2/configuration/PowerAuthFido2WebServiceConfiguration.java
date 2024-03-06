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

import com.wultra.security.powerauth.client.PowerAuthFido2Client;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.rest.client.PowerAuthFido2RestClient;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClientConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * PowerAuth FIDO2 service configuration class.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Configuration
@Slf4j
public class PowerAuthFido2WebServiceConfiguration {

    @Value("${powerauth.service.baseUrl}")
    private String powerAuthServiceBaseUrl;

    @Value("${powerauth.service.security.clientToken}")
    private String clientToken;

    @Value("${powerauth.service.security.clientSecret}")
    private String clientSecret;

    @Bean
    public PowerAuthFido2Client powerAuthFido2Client() {
        try {
            // Endpoint security is on
            if (clientToken != null && !clientToken.isEmpty()) {
                final PowerAuthRestClientConfiguration config = new PowerAuthRestClientConfiguration();
                config.setPowerAuthClientToken(clientToken);
                config.setPowerAuthClientSecret(clientSecret);
                return new PowerAuthFido2RestClient(powerAuthServiceBaseUrl, config);
            } else {
                return new PowerAuthFido2RestClient(powerAuthServiceBaseUrl);
            }
        } catch (PowerAuthClientException ex) {
            // Log the error in case Rest client initialization failed
            logger.error(ex.getMessage(), ex);
            return null;
        }
    }

}