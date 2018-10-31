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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.HashMap;
import java.util.Map;

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
        byte[] data = "test".getBytes();
        String signatureHeaderInvalid = "X-PowerAuth-Authorization: PowerAuth pa_activation_id=\"79b910a6-b058-49bd-a56d-d54b5aada048\" pa_application_key=\"4rVingHqXITsWvGj1K+EBQ==\" pa_nonce=\"inZWJ5hCFBk+nnZ1sYTnjg==\" pa_signature_type=\"possession_knowledge\" pa_signature=\"77419567-47712563\" pa_version=\"2.1\"";

        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        headers.put(PowerAuthSignatureHttpHeader.HEADER_NAME, signatureHeaderInvalid);

        HttpResponse response = Unirest.post(config.getPowerAuthIntegrationUrl() + "/pa/signature/validate")
                .headers(headers)
                .body(data)
                .asString();
        assertEquals(401, response.getStatus());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(response.getRawBody(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("POWERAUTH_AUTH_FAIL", errorResponse.getResponseObject().getCode());
        assertEquals("Signature validation failed", errorResponse.getResponseObject().getMessage());
    }

    @Test
    public void invalidTokenHeaderTest() throws Exception {
        byte[] data = "test".getBytes();
        String tokenHeaderInvalid = "X-PowerAuth-Token: PowerAuth token_id=\"0f3da4d7-427d-4b54-8211-b1995214810b\" token_digest=\"rMYL7jvUhBqdGyNjiGJED+9cM0tAM9JhAhSdfbatPg4=\" nonce=\"jHaHL1mWWZoB/+QQbGTAwg==\" timestamp=\"1541000429960\" version=\"2.1\"";

        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        headers.put(PowerAuthTokenHttpHeader.HEADER_NAME, tokenHeaderInvalid);

        HttpResponse response = Unirest.post(config.getPowerAuthIntegrationUrl() + "/api/auth/token/app/operation/list")
                .headers(headers)
                .body(data)
                .asString();
        assertEquals(401, response.getStatus());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(response.getRawBody(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("POWERAUTH_AUTH_FAIL", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_SIGNATURE_INVALID", errorResponse.getResponseObject().getMessage());
    }

    @Test
    public void invalidEncryptionHeaderTest() throws Exception {
        byte[] data = "test".getBytes();
        String tokenHeaderInvalid = "X-PowerAuth-Encryption: PowerAuth application_key=\"4rVingHqXITsWvGj1K+EBQ==\" version=\"3.0\"";

        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        headers.put(PowerAuthTokenHttpHeader.HEADER_NAME, tokenHeaderInvalid);

        HttpResponse response = Unirest.post(config.getPowerAuthIntegrationUrl() + "/pa/v3/activation/create")
                .headers(headers)
                .body(data)
                .asString();
        assertEquals(400, response.getStatus());

        ObjectMapper objectMapper = config.getObjectMapper();
        ErrorResponse errorResponse = objectMapper.readValue(response.getRawBody(), ErrorResponse.class);
        assertEquals("ERROR", errorResponse.getStatus());
        assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
        assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
    }

}
