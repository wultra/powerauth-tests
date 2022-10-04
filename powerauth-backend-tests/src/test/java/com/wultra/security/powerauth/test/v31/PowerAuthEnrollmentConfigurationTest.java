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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.wultra.app.enrollmentserver.api.model.enrollment.response.ConfigurationResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.EncryptStep;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.HashMap;
import java.util.Objects;
import java.util.function.Predicate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;

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

    private EncryptStepModel encryptModel;

    private final ObjectMapper objectMapper = new ObjectMapper().disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    @BeforeEach
    void setUp() throws Exception {
        encryptModel = new EncryptStepModel();
        encryptModel.setApplicationKey(config.getApplicationKey());
        encryptModel.setApplicationSecret(config.getApplicationSecret());
        encryptModel.setMasterPublicKey(config.getMasterPublicKey());
        encryptModel.setHeaders(new HashMap<>());
        encryptModel.setResultStatusObject(config.getResultStatusObjectV31());
        encryptModel.setVersion("3.1");
    }

    @Test
    void testConfiguration() throws Exception {
        encryptModel.setData(objectMapper.writeValueAsBytes("{}"));
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/configuration");
        encryptModel.setScope("application");

        final ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().isSuccess());
        assertEquals(200, stepLogger.getResponse().getStatusCode());

        final ConfigurationResponse response = stepLogger.getItems().stream()
                .filter(isStepItemDecryptedResponse())
                .map(StepItem::getObject)
                .map(Object::toString)
                .map(it -> safeReadValue(it, new TypeReference<ObjectResponse<ConfigurationResponse>>() { }))
                .filter(Objects::nonNull)
                .map(ObjectResponse::getResponseObject)
                .findFirst()
                .orElseThrow(() -> new AssertionError("error - no configuration found"));

        assertThat(response.getMobileApplication().getAndroid().getMinimalVersion(), equalTo("1.4.0"));
        assertThat(response.getMobileApplication().getAndroid().getCurrentVersion(), equalTo("1.5.4"));
        assertThat(response.getMobileApplication().getIOs().getMinimalVersion(), equalTo("1.5.4"));
        assertThat(response.getMobileApplication().getIOs().getCurrentVersion(), equalTo("2.0.0"));
    }

    private Predicate<StepItem> isStepItemDecryptedResponse() {
        return stepItem -> "Decrypted Response".equals(stepItem.getName());
    }

    private <T> T safeReadValue(final String value, final TypeReference<T> typeReference) {
        try {
            return objectMapper.readValue(value, typeReference);
        } catch (JsonProcessingException e) {
            fail("Unable to read json", e);
            return null;
        }
    }
}
