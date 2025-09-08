/*
 * PowerAuth test and related software components
 * Copyright (C) 2025 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation either version 3 of the License or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not see <http://www.gnu.org/licenses/>.
 */
package com.wultra.security.powerauth.test.v4x;

import com.wultra.core.rest.client.base.RestClientException;
import com.wultra.core.rest.model.base.response.ErrorResponse;
import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.http.PowerAuthAuthorizationHttpHeader;
import com.wultra.security.powerauth.http.PowerAuthTokenHttpHeader;
import com.wultra.security.powerauth.lib.cmd.util.MapUtil;
import com.wultra.security.powerauth.lib.cmd.util.RestClientFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthHttpTest {

    private PowerAuthTestConfiguration config;

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Test
    void invalidSignatureHeaderTest() {
        final byte[] data = "test".getBytes(StandardCharsets.UTF_8);
        final String signatureHeaderInvalid = "PowerAuth pa_activation_id=\"79b910a6-b058-49bd-a56d-d54b5aada048\" pa_application_key=\"4rVingHqXITsWvGj1K+EBQ==\" pa_nonce=\"inZWJ5hCFBk+nnZ1sYTnjg==\" pa_auth_code_type=\"possession_knowledge\" pa_auth_code=\"lAKanQ2amnBBL7r48C2DEkyij14MBuODkzkaNEQm3PXVoFU2bGE+KZV8EWcMAIMgfBUlM81mxanVqJcr6k60Tg==\" pa_version=\"4.0\"";

        final Map<String, String> headers = Map.of(
                "Accept", "application/json",
                "Content-Type", "application/json",
                PowerAuthAuthorizationHttpHeader.HEADER_NAME, signatureHeaderInvalid);

        final RestClientException exception = assertThrows(RestClientException.class, () ->
                RestClientFactory.getRestClient().post(
                        config.getPowerAuthIntegrationUrl() + "/pa/v4/auth/validate",
                        data,
                        null,
                        MapUtil.toMultiValueMap(headers),
                        new ParameterizedTypeReference<Response>() {}
                ));

        assertEquals(401, exception.getStatusCode().value());
        assertNotNull(exception.getErrorResponse());
        final ErrorResponse errorResponse = exception.getErrorResponse();
        assertEquals("ERROR", errorResponse.getStatus());
        checkError(errorResponse);
    }

    @Test
    void invalidTokenHeaderTest() {
        byte[] data = "test".getBytes(StandardCharsets.UTF_8);
        String tokenHeaderInvalid = "PowerAuth token_id=\"2f126584-342c-4f9c-b687-dcf98d7c1ee4\", token_digest=\"53Qxy5Ast0xk+eJ1P9gs9DqlLTJGOnnQ7Y5tu3E42po=\", nonce=\"bqMyF7BnPxIos6E+RyDAig==\", timestamp=\"1757316828350\", version=\"4.0\"";

        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        headers.put(PowerAuthTokenHttpHeader.HEADER_NAME, tokenHeaderInvalid);
        String tokenUrl;
        tokenUrl = config.getPowerAuthIntegrationUrl() + "/api/auth/token/app/operation/list";

        try {
            RestClientFactory.getRestClient().post(
                    tokenUrl,
                    data,
                    null,
                    MapUtil.toMultiValueMap(headers),
                    new ParameterizedTypeReference<Response>() {}
            );
        } catch (RestClientException ex) {
            assertEquals(401, ex.getStatusCode().value());
            ErrorResponse errorResponse = Objects.requireNonNull(ex.getErrorResponse());
            assertEquals("ERROR", errorResponse.getStatus());
            checkError(errorResponse);
        }
    }

    @Test
    void invalidEncryptionHeaderTest() {
        byte[] data = "\"temporaryKeyId\":\"bdf6c492-2e54-485e-b71d-8f6adb26add3\",\"ephemeralPublicKey\":\"BEew43/VjKxV0dXPmejnbV745cUrIY1guojm6nsq554Mn/XCtn+sHz954VTWIyOYqnliGRrICaIr5cqWcpk1gUU=\",\"encryptedData\":\"LenJAtwgHUXPfRwHFuo6bjV+2x7fW7zyQQ6npOY+xNz8302KXgkm8OMYVEISaMSrOGPSdVKk7Pd/djna9HqeVEXLiLr9IZONid8BzaL9nSenk16G472d4OZyJKLgrZeFRlAOxSQCLCwn3nrVEuAOYGCVaTE+xMQZk9Lx7ze2uhE33n6fUIBfK+IgQWdqVG/+TYJcveRWRrkuf9/CS1zXiO0sVl3p2EuTXGSOxT3evdBMB8ctQBlZRpdRWGXNUnYthkmpE8G0mYcO3q+VoKRz8ikDWjibMZijtINL0wUA+b8DKkdtziZEjoJvxfvoDmZG0zxdut1zx3e9v8TAt/QGv21R0UT+4HkBFbZmrGxcctn0VKb1NzB8yRg9FhEofKMru5/4ZU4IIgOmaXton5tym+FFiQY+um2jfnl3Jq8JacpAS4eaRI3qSV44kU1uh+jj+v1P2IIHZG87HKxtAYImVClOBgXN5dyAGMXlcYk1IED9mXJt/uyP0jizHc9S6LTJhGVeyHm8r4SfqaqWVn2ZltkvHV4Obf4IcB6jquv8ssHmkvMvJ+c/UJ7P5NRt2ZFiRZ9h5h7j9tmWaoaLHsF6Xjq9i3PNggK79KKgcvlfBI8Dxxrwhxi17nMM+hOtw350UA3AufN4mJoyrrnpYdGIScCqFRtwaBWuZ1jG1KdnSAWKbl36O9sFZbTtU8ZTSOpi7u6NQb6NbBpqEftHjM2ijoGvsvKlWyDFfJol/F7s4ojB+ieKVZVOb9DP671r21wznrl2aGlVxisOAVi2UY27wYw7JJzynq2L7pQJMQMZAC+vmsovG+BB+JPzLoGOok08qdJUuxIz+UcxWI16nE1jcMjd8Wp4ojtrIleQ0VbzQHE=\",\"mac\":\"Lvtq2jumm7OC8+pu1nDTuING2VgIUhfXBWY+jEC818w=\",\"nonce\":\"qoy2Xti0oyzTVwvFbvZ7bQ==\",\"timestamp\":1757316677976".getBytes(StandardCharsets.UTF_8);
        String headerInvalid = "PowerAuth application_key=\"4rVingHqXITsWvGj1K+EBQ==\" version=\"4.0\"";

        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        headers.put(PowerAuthTokenHttpHeader.HEADER_NAME, headerInvalid);

        try {
            RestClientFactory.getRestClient().post(
                    config.getPowerAuthIntegrationUrl() + "/pa/v4/activation/create",
                    data,
                    null,
                    MapUtil.toMultiValueMap(headers),
                    new ParameterizedTypeReference<Response>() {}
            );
        } catch (RestClientException ex) {
            assertEquals(400, ex.getStatusCode().value());
            ErrorResponse errorResponse = Objects.requireNonNull(ex.getErrorResponse());
            assertEquals("ERROR", errorResponse.getStatus());
            assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
            assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
        }
    }

    private void checkError(ErrorResponse errorResponse) {
        assertTrue("POWERAUTH_AUTH_FAIL".equals(errorResponse.getResponseObject().getCode()) || "ERR_AUTHENTICATION".equals(errorResponse.getResponseObject().getCode()));
    }

}
