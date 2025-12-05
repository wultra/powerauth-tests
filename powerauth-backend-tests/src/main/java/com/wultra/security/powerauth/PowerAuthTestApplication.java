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
package com.wultra.security.powerauth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.EventListener;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;

/**
 * Spring boot test application.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootApplication
public class PowerAuthTestApplication {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthTestApplication.class);

    @Value("${powerauth.port:58080}")
    private int powerauthPort;

    @Value("${enrollment.port:58081}")
    private int enrollmentPort;

    @Value("${onboarding.port:58082}")
    private int onboardingPort;

    public static void main(String[] args) {
        SpringApplication.run(PowerAuthTestApplication.class, args);
    }

    @EventListener
    public void onReady(ApplicationReadyEvent event) {
        logger.info("PowerAuth Test Application started, application ports: {}, {}, {}", powerauthPort, enrollmentPort, onboardingPort);
    }

    @EventListener
    public void onShutdown(ContextClosedEvent event) {
        try {
            for (String url: List.of(
                    "http://localhost:" + powerauthPort + "/powerauth-java-server/actuator/shutdown",
                    "http://localhost:" + enrollmentPort + "/enrollment-server/actuator/shutdown",
                    "http://localhost:" + onboardingPort + "/enrollment-server-onboarding/actuator/shutdown")) {
                final HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
                conn.setRequestMethod("POST");
                conn.setDoOutput(true);
                conn.getResponseCode();
                conn.disconnect();
            }
        } catch (Exception e) {
            logger.error("Application shutdown failed", e);
        }
    }

}