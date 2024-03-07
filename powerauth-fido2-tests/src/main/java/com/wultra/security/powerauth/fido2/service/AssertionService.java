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

import com.webauthn4j.data.UserVerificationRequirement;
import com.wultra.security.powerauth.client.PowerAuthFido2Client;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.fido2.AssertionChallengeRequest;
import com.wultra.security.powerauth.client.model.request.fido2.AssertionVerificationRequest;
import com.wultra.security.powerauth.client.model.response.fido2.AssertionChallengeResponse;
import com.wultra.security.powerauth.client.model.response.fido2.AssertionVerificationResponse;
import com.wultra.security.powerauth.fido2.configuration.WebAuthnConfiguration;
import com.wultra.security.powerauth.fido2.controller.request.AssertionOptionsRequest;
import com.wultra.security.powerauth.fido2.controller.request.VerifyAssertionRequest;
import com.wultra.security.powerauth.fido2.controller.response.AssertionOptionsResponse;
import com.wultra.security.powerauth.fido2.controller.response.CredentialDescriptor;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;

/**
 * Service for WebAuthn authentication tasks.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Service
@AllArgsConstructor
@Slf4j
public class AssertionService {

    private static final String OPERATION_DATA_EXTENSION_KEY = "txAuthSimple";

    private final PowerAuthFido2Client fido2Client;
    private final SharedService sharedService;
    private final WebAuthnConfiguration webAuthNConfig;

    /**
     * Build public key assertion options.
     * @param request Request form with user input.
     * @return Public key assertion options.
     * @throws PowerAuthClientException in case of PowerAuth server communication error.
     */
    public AssertionOptionsResponse assertionOptions(final AssertionOptionsRequest request) throws PowerAuthClientException {
        final String userId = request.username();
        final String applicationId = request.applicationId();

        logger.info("Building assertion options for userId={}, applicationId={}", userId, applicationId);

        final List<CredentialDescriptor> existingCredentials = sharedService.fetchExistingCredentials(userId, applicationId);
        if (existingCredentials.isEmpty() && StringUtils.hasText(userId))  {
            throw new IllegalStateException("Not registered yet.");
        }

        final AssertionChallengeResponse challengeResponse = fetchChallenge(applicationId, request.templateName());
        final String challenge = challengeResponse.getChallenge();
        final String operationData = extractOperationData(challenge);

        return AssertionOptionsResponse.builder()
                .challenge(challenge)
                .rpId(webAuthNConfig.getRpId())
                .timeout(webAuthNConfig.getTimeout().toMillis())
                .allowCredentials(existingCredentials)
                .userVerification(UserVerificationRequirement.PREFERRED)
                .extensions(Map.of(OPERATION_DATA_EXTENSION_KEY, operationData))
                .build();
    }

    /**
     * Verify credential at PowerAuth server.
     * @param credential Received public key credential.
     * @return PowerAuth authentication response.
     * @throws PowerAuthClientException in case of PowerAuth server communication error.
     */
    public AssertionVerificationResponse authenticate(final VerifyAssertionRequest credential) throws PowerAuthClientException {
        final AssertionVerificationRequest request = new AssertionVerificationRequest();
        request.setId(credential.id());
        request.setType(credential.type().getValue());
        request.setAuthenticatorAttachment(credential.authenticatorAttachment().getValue());
        request.setResponse(credential.response());
        request.setApplicationId(credential.applicationId());
        request.setExpectedChallenge(credential.expectedChallenge());
        request.setRelyingPartyId(webAuthNConfig.getRpId());
        request.setAllowedOrigins(webAuthNConfig.getAllowedOrigins());
        request.setRequiresUserVerification(credential.userVerificationRequired());
        return fido2Client.authenticate(request);
    }

    private AssertionChallengeResponse fetchChallenge(final String applicationId, final String templateName) throws PowerAuthClientException {
        final AssertionChallengeRequest request = new AssertionChallengeRequest();
        request.setApplicationIds(List.of(applicationId));
        request.setTemplateName(templateName);
        return fido2Client.requestAssertionChallenge(request);
    }

    private static String extractOperationData(final String challenge) {
        final String[] split = challenge.split("&", 2);
        if (split.length != 2) {
            throw new IllegalStateException("Invalid challenge.");
        }
        return split[1];
    }

}
