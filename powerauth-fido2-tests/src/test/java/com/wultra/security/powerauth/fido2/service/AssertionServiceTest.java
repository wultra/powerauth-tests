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

package com.wultra.security.powerauth.fido2.service;

import com.wultra.security.powerauth.client.PowerAuthFido2Client;
import com.wultra.security.powerauth.client.model.response.fido2.AssertionChallengeResponse;
import com.wultra.security.powerauth.fido2.configuration.WebAuthnConfiguration;
import com.wultra.security.powerauth.fido2.controller.request.AssertionOptionsRequest;
import com.wultra.security.powerauth.fido2.controller.response.AssertionOptionsResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Test of {@link AssertionService}
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class AssertionServiceTest {

    @Mock
    private PowerAuthFido2Client fido2Client;

    @Mock
    private Fido2SharedService fido2SharedService;

    @Mock
    private WebAuthnConfiguration webAuthNConfig;

    @InjectMocks
    private AssertionService tested;

    @Test
    void testAssertionOptions_paymentData() throws Exception {
        final String username = null;
        final String applicationId = "app";
        final String templateName = "payment";
        final Map<String, String> operationParameters = Map.of(
                "iban", "CZ5508000000001234567899",
                "amount", "11499.99",
                "currency", "CZK",
                "note", "It's a gift!"
        );

        final AssertionOptionsRequest request = new AssertionOptionsRequest(username, applicationId, templateName, operationParameters);

        final AssertionChallengeResponse challengeResponse = new AssertionChallengeResponse();
        challengeResponse.setChallenge("operationId&" + buildPaymentData(operationParameters));
        when(fido2Client.requestAssertionChallenge(any()))
                .thenReturn(challengeResponse);

        final AssertionOptionsResponse response = tested.assertionOptions(request);
        final String rebuildPaymentData = convertHmacSecret((AssertionService.HMACGetSecretInput) response.extensions().get("hmacGetSecret"));
        assertEquals("A1*ICZ5508000000001234567899*A11499.99CZK*NIt's a gift!", rebuildPaymentData);
    }

    @Test
    void testAssertionOptions_longPaymentData() throws Exception {
        final String username = null;
        final String applicationId = "app";
        final String templateName = "payment";
        final Map<String, String> operationParameters = Map.of(
                "iban", "CZ5508000000001234567899",
                "amount", "11499.99",
                "currency", "CZK",
                "note", "This is a long story to tell..."
        );

        final AssertionOptionsRequest request = new AssertionOptionsRequest(username, applicationId, templateName, operationParameters);

        final AssertionChallengeResponse challengeResponse = new AssertionChallengeResponse();
        challengeResponse.setChallenge("operationId&" + buildPaymentData(operationParameters));
        when(fido2Client.requestAssertionChallenge(any()))
                .thenReturn(challengeResponse);

        final AssertionOptionsResponse response = tested.assertionOptions(request);
        final String rebuildPaymentData = convertHmacSecret((AssertionService.HMACGetSecretInput) response.extensions().get("hmacGetSecret"));
        assertEquals("A1*ICZ5508000000001234567899*A11499.99CZK", rebuildPaymentData);
    }

    private static String convertHmacSecret(final AssertionService.HMACGetSecretInput hmacSecret) {
        final byte[] seed1Bytes = Base64.getDecoder().decode(hmacSecret.seed1());
        final byte[] seed2Bytes = Base64.getDecoder().decode(hmacSecret.seed2());

        final byte[] operationDataBytes = new byte[64];
        System.arraycopy(seed1Bytes, 0, operationDataBytes, 0, seed1Bytes.length);
        System.arraycopy(seed2Bytes, 0, operationDataBytes, 32, seed2Bytes.length);

        final String paddedOperationData = new String(operationDataBytes);
        return String.join("*", paddedOperationData.split("\\*"));
    }

    private static String buildPaymentData(final Map<String, String> operationParameters) {
        String paymentData = "A1";

        if (operationParameters.containsKey("iban")) {
            paymentData += "*I" + operationParameters.get("iban");
        }

        if (operationParameters.containsKey("amount")) {
            paymentData += "*A" + operationParameters.get("amount");
            if (operationParameters.containsKey("currency")) {
                paymentData += operationParameters.get("currency");
            }
        }

        if (operationParameters.containsKey("note")) {
            paymentData += "*N" + operationParameters.get("note");
        }

        return paymentData;
    }

}
