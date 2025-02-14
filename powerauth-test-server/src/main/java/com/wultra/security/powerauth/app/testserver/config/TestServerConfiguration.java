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

package com.wultra.security.powerauth.app.testserver.config;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * Test server configuration.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Configuration
@Data
@ComponentScan(basePackages = {"com.wultra.security", "com.wultra.security"})
public class TestServerConfiguration {

    @Value("${powerauth.enrollment.service.url:http://localhost:8080/enrollment-server}")
    private String enrollmentServiceUrl;

    @Value("${powerauth.version}")
    private String version;

}
