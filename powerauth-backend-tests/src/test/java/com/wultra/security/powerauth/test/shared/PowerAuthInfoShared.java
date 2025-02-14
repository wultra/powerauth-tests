/*
 * PowerAuth test and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.shared;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.wultra.core.rest.client.base.DefaultRestClient;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.model.StepItem;
import com.wultra.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.v3.EncryptStep;
import com.wultra.security.powerauth.rest.api.model.request.UserInfoRequest;
import com.wultra.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import com.wultra.security.powerauth.rest.api.model.response.ServerStatusResponse;
import org.opentest4j.AssertionFailedError;

import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth server info test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthInfoShared {

    private static final ObjectMapper objectMapper = new ObjectMapper().disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    // Tolerate 60 seconds time difference between client and server in tests
    private static final long SERVER_CLIENT_TIME_DIFF_TOLERANCE_MILLIS = 60000;

    public static void testUserInfo(final PowerAuthTestConfiguration config, final EncryptStepModel encryptModel, final PowerAuthVersion version) throws Exception {
        encryptModel.setUriString(config.getEnrollmentServiceUrl() + "/pa/v3/user/info");
        encryptModel.setScope("activation");
        encryptModel.setData(objectMapper.writeValueAsBytes(new UserInfoRequest()));

        final ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        new EncryptStep().execute(stepLogger, encryptModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final EciesEncryptedResponse response = (EciesEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(response.getEncryptedData());
        assertNotNull(response.getMac());

        final Map<String, Object> decryptedData = stepLogger.getItems().stream()
                .filter(isStepItemDecryptedResponse())
                .map(StepItem::object)
                .map(Object::toString)
                .map(it -> safeReadValue(it, new TypeReference<Map<String, Object>>() {}))
                .filter(Objects::nonNull)
                .findFirst()
                .orElseThrow(() -> new AssertionFailedError("Decrypted data not found"));

        assertNotNull(decryptedData.get("iat"));
        assertNotNull(decryptedData.get("jti"));
        assertEquals(config.getUser(version), decryptedData.get("sub"));
    }

    public static void testServerStatus(final PowerAuthTestConfiguration config) throws Exception {
        final RestClient restClient = new DefaultRestClient(config.getEnrollmentServiceUrl());
        final ObjectResponse<ServerStatusResponse> objectResponse = restClient.postObject("/pa/v3/status", new ObjectRequest<>(), ServerStatusResponse.class);
        assertTrue(Math.abs(objectResponse.getResponseObject().serverTime() - System.currentTimeMillis()) < SERVER_CLIENT_TIME_DIFF_TOLERANCE_MILLIS);
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
