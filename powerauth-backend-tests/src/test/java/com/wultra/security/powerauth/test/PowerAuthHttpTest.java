/*
 * PowerAuth test and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package com.wultra.security.powerauth.test;

import com.wultra.core.rest.client.base.RestClientException;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader;
import io.getlime.security.powerauth.lib.cmd.util.MapUtil;
import io.getlime.security.powerauth.lib.cmd.util.RestClientFactory;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.test.context.junit4.SpringRunner;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthHttpTest {

    private PowerAuthTestConfiguration config;

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Test
    public void invalidSignatureHeaderTest() throws Exception {
        byte[] data = "test".getBytes(StandardCharsets.UTF_8);
        String signatureHeaderInvalid = "X-PowerAuth-Authorization: PowerAuth pa_activation_id=\"79b910a6-b058-49bd-a56d-d54b5aada048\" pa_application_key=\"4rVingHqXITsWvGj1K+EBQ==\" pa_nonce=\"inZWJ5hCFBk+nnZ1sYTnjg==\" pa_signature_type=\"possession_knowledge\" pa_signature=\"77419567-47712563\" pa_version=\"2.1\"";

        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        headers.put(PowerAuthSignatureHttpHeader.HEADER_NAME, signatureHeaderInvalid);

        try {
            RestClientFactory.getRestClient().post(
                    config.getPowerAuthIntegrationUrl() + "/pa/signature/validate",
                    data,
                    null,
                    MapUtil.toMultiValueMap(headers),
                    new ParameterizedTypeReference<Response>() {}
            );
        } catch (RestClientException ex) {
            assertEquals(401, ex.getStatusCode().value());
            ErrorResponse errorResponse = Objects.requireNonNull(ex.getErrorResponse());
            assertEquals("ERROR", errorResponse.getStatus());
            checkSignatureError(errorResponse);
        }
    }

    @Test
    public void invalidTokenHeaderTest() throws Exception {
        byte[] data = "test".getBytes(StandardCharsets.UTF_8);
        String tokenHeaderInvalid = "X-PowerAuth-Token: PowerAuth token_id=\"0f3da4d7-427d-4b54-8211-b1995214810b\" token_digest=\"rMYL7jvUhBqdGyNjiGJED+9cM0tAM9JhAhSdfbatPg4=\" nonce=\"jHaHL1mWWZoB/+QQbGTAwg==\" timestamp=\"1541000429960\" version=\"2.1\"";

        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        headers.put(PowerAuthTokenHttpHeader.HEADER_NAME, tokenHeaderInvalid);
        String tokenUrl;
        if (config.getPowerAuthIntegrationUrl().contains("powerauth-webflow")) {
            // Tests are running against Spring integration on Web Flow
            tokenUrl = config.getPowerAuthIntegrationUrl() + "/api/auth/token/app/operation/list";
        } else {
            // Tests are running against Java EE integration on demo server
            tokenUrl = config.getPowerAuthIntegrationUrl() + "/token/authorize";
        }

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
            checkSignatureError(errorResponse);
        }
    }

    @Test
    public void invalidEncryptionHeaderTest() throws Exception {
        byte[] data = "{\"ephemeralPublicKey\":\"BHBy8Apj7BFxjGaiKs8nFRkD4rjlSuo1rguWnjlSChLKhRGUdooT0Geh8rE6u2QOnY2rBaIj+Stzqj6A/cs3WUY=\",\"encryptedData\":\"rZKU++q2HE3uwZRMLSlYfuUvHrKt9CVGYUGB21CjdaNyflyTOei7dvRAVACQRyJmcyWePAl0BQHRaN1trJyw8Ue1YzYVx7fGEQ9l9WtCJYeYBPS4krR7ZFo4ydmeFm/rhklClUVJZ2OSSt2Z/O9HctA8W/BlwAMSVDj496wdZ3ozxDLhDwd+sBx03Y3812GD0s3HbxK4wHN/OCj+jAczowI0FzI1cT5DA+M7e7Hc0golN1SExVqw1aMVAwA32gwjbc0nuqecXPB0op4AhGTAOZFQDtmQH/U1chcykTXso4Y7FF1fKjyeyZN73imO3lImhKETBc+2hg3/KEVjP43OqtB5DgaCatoWXjAVHJY/mSLWJd7WtfCAq1+xNSbwuhAEt8y2+/2BzvaRQFs8WuqAuBlTx/c1u2hddCpfQFRb0a3x2l7FYrBtYYfmQZb38s+zsix6Ju4esZ9HibmX8XvdMZB9F4E+tUfLrRwJmFpRm5dC6ufZp8+Qur8c+SM5aOVqLRWf/by6rC/6P+Pm35UNwAYA5sbrZU+0za4TlT7hNR4bkxkHStz5moBRyrwIYtJVMKDg3pXMzLW/j35lN9mnlQHEKPbt7ZlRjeKotXGAjrztXDOT3bOHBayMHm/fjCk+cHUIEYvR3jd4PvgG6YuU9W6F/jCxG8XnFumuBVJzRVnHYlCC+eZ2XxwLxSxTpO3D\",\"mac\":\"RLhrZebxh03EssLgC265flJ06Wp67QdOhkAeXxAMxSk=\"}".getBytes(StandardCharsets.UTF_8);
        String tokenHeaderInvalid = "X-PowerAuth-Encryption: PowerAuth application_key=\"4rVingHqXITsWvGj1K+EBQ==\" version=\"3.0\"";

        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        headers.put(PowerAuthTokenHttpHeader.HEADER_NAME, tokenHeaderInvalid);

        try {
            RestClientFactory.getRestClient().post(
                    config.getPowerAuthIntegrationUrl() + "/pa/v3/activation/create",
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

    private void checkSignatureError(ErrorResponse errorResponse) {
        // Errors differ when Web Flow is used because of its Exception handler
        assertTrue("POWERAUTH_AUTH_FAIL".equals(errorResponse.getResponseObject().getCode()) || "ERR_AUTHENTICATION".equals(errorResponse.getResponseObject().getCode()));
    }

}
