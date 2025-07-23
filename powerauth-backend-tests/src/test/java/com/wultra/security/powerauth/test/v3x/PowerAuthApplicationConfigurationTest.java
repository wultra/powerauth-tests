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
package com.wultra.security.powerauth.test.v3x;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.wultra.app.enrollmentserver.api.model.enrollment.request.OidcApplicationConfigurationRequest;
import com.wultra.app.enrollmentserver.api.model.enrollment.response.OidcApplicationConfigurationResponse;
import com.wultra.security.powerauth.configuration.PowerAuthOidcActivationConfigurationProperties;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.model.StepItem;
import com.wultra.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.EncryptStep;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.EnabledIf;

import java.util.HashMap;
import java.util.Objects;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@code /api/config/oidc}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@SpringBootTest(classes = {PowerAuthTestConfiguration.class, PowerAuthOidcActivationConfigurationProperties.class})
@EnableConfigurationProperties
@EnabledIf(expression = "#{T(org.springframework.util.StringUtils).hasText('${powerauth.test.activation.oidc.providerId}')}", loadContext = true)
class PowerAuthApplicationConfigurationTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V3_3;

    private static final ObjectMapper objectMapper = new ObjectMapper().disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    @Autowired
    private PowerAuthOidcActivationConfigurationProperties oidcConfigProperties;

    @Autowired
    private PowerAuthTestConfiguration config;

    private EncryptStepModel encryptModel;

    @BeforeEach
    void setUp() {
        encryptModel = new EncryptStepModel();
        encryptModel.setApplicationKey(config.getApplicationKey());
        encryptModel.setApplicationSecret(config.getApplicationSecret());
        encryptModel.setMasterPublicKeyP256(config.getMasterPublicKeyP256());
        encryptModel.setHeaders(new HashMap<>());
        encryptModel.setResultStatusObject(config.getResultStatusObject(VERSION));
        encryptModel.setBaseUriString(config.getPowerAuthIntegrationUrl());
        encryptModel.setVersion(VERSION);
    }

    @Test
    void testOidc() throws Exception {
        final OidcApplicationConfigurationRequest request = new OidcApplicationConfigurationRequest();
        request.setProviderId(oidcConfigProperties.getProviderId());

        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/api/config/oidc");
        encryptModel.setScope("application");
        encryptModel.setData(objectMapper.writeValueAsBytes(request));

        final ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final EciesEncryptedResponse response = (EciesEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(response.getEncryptedData());
        assertNotNull(response.getMac());

        final OidcApplicationConfigurationResponse decryptedData = stepLogger.getItems().stream()
                .filter(isStepItemDecryptedResponse())
                .map(StepItem::object)
                .map(Object::toString)
                .map(it -> safeReadValue(it, new TypeReference<ObjectResponse<OidcApplicationConfigurationResponse>>() {}))
                .filter(Objects::nonNull)
                .map(ObjectResponse::getResponseObject)
                .findFirst()
                .orElseThrow(() -> new AssertionFailedError("Decrypted data not found"));

        assertEquals(oidcConfigProperties.getProviderId(), decryptedData.getProviderId());
        assertNotNull(decryptedData.getClientId());
        assertNotNull(decryptedData.getScopes());
        assertNotNull(decryptedData.getRedirectUri());
        assertFalse(decryptedData.isPkceEnabled());
    }

    private static Predicate<StepItem> isStepItemDecryptedResponse() {
        return stepItem -> "Decrypted Response".equals(stepItem.name());
    }

    private static <T> T safeReadValue(final String value, final TypeReference<T> typeReference) {
        try {
            return objectMapper.readValue(value, typeReference);
        } catch (JsonProcessingException e) {
            fail("Unable to read json", e);
            return null;
        }
    }

}
