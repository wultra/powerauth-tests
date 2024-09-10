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
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.EncryptStep;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opentest4j.AssertionFailedError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@code /api/config/oidc}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthApplicationConfigurationTest {

    private static final String VERSION = "3.2";

    private static final ObjectMapper objectMapper = new ObjectMapper().disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    @Autowired
    private PowerAuthTestConfiguration config;

    @Autowired
    private PowerAuthClient powerAuthClient;

    private EncryptStepModel encryptModel;

    @BeforeEach
    void setUp() throws Exception {
        encryptModel = new EncryptStepModel();
        encryptModel.setApplicationKey(config.getApplicationKey());
        encryptModel.setApplicationSecret(config.getApplicationSecret());
        encryptModel.setMasterPublicKey(config.getMasterPublicKey());
        encryptModel.setHeaders(new HashMap<>());
        encryptModel.setResultStatusObject(config.getResultStatusObjectV32());
        encryptModel.setVersion(VERSION);

        final Object oidcConfiguration = Map.of(
                "providerId", "xyz999",
                "clientId", "jabberwocky",
                "clientSecret", "top secret",
                "scopes", "openid",
                "authorizeUri", "https://authorize.example.com",
                "redirectUri", "https://redirect.example.com",
                "tokenUri", "https://...",
                "userInfoUri", "https://..."
        );

        powerAuthClient.createApplicationConfig(config.getApplicationId(), "oauth2_providers", List.of(oidcConfiguration));
    }

    @Test
    void testOidc() throws Exception {
        final OidcApplicationConfigurationRequest request = new OidcApplicationConfigurationRequest();
        request.setProviderId("xyz999");

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

        assertEquals("xyz999", decryptedData.getProviderId());
        assertEquals("jabberwocky", decryptedData.getClientId());
        assertEquals("openid", decryptedData.getScopes());
        assertEquals("https://authorize.example.com", decryptedData.getAuthorizeUri());
        assertEquals("https://redirect.example.com", decryptedData.getRedirectUri());
        assertEquals("https://redirect.example.com", decryptedData.getRedirectUri());
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
