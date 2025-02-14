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

import com.wultra.security.powerauth.fido2.client.PowerAuthFido2Client;
import com.wultra.security.powerauth.fido2.configuration.WebAuthnConfiguration;
import com.wultra.security.powerauth.fido2.controller.request.AssertionOptionsRequest;
import com.wultra.security.powerauth.fido2.controller.request.VerifyAssertionRequest;
import com.wultra.security.powerauth.fido2.controller.response.AssertionOptionsResponse;
import com.wultra.security.powerauth.fido2.controller.response.CredentialDescriptor;
import com.wultra.security.powerauth.fido2.model.error.PowerAuthFido2Exception;
import com.wultra.security.powerauth.fido2.model.request.AssertionChallengeRequest;
import com.wultra.security.powerauth.fido2.model.request.AssertionVerificationRequest;
import com.wultra.security.powerauth.fido2.model.response.AssertionChallengeResponse;
import com.wultra.security.powerauth.fido2.model.response.AssertionVerificationResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.*;

/**
 * Service for WebAuthn authentication tasks.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Service
@AllArgsConstructor
@Slf4j
public class AssertionService {

    private final PowerAuthFido2Client fido2Client;
    private final WebAuthnConfiguration webAuthNConfig;

    /**
     * Build public key assertion options.
     * @param request Request form with user input.
     * @return Public key assertion options.
     * @throws PowerAuthFido2Exception in case of PowerAuth server communication error.
     */
    public AssertionOptionsResponse assertionOptions(final AssertionOptionsRequest request) throws PowerAuthFido2Exception {
        final String userId = request.userId();
        final String applicationId = request.applicationId();

        logger.info("Building assertion options for userId={}, applicationId={}", userId, applicationId);

        final AssertionChallengeResponse challengeResponse = fetchChallenge(userId, applicationId, request.templateName(), request.operationParameters());
        final var credentialList = Optional.ofNullable(challengeResponse.getAllowCredentials());
        if (credentialList.isEmpty() && StringUtils.hasText(userId))  {
            logger.info("User ID {} is not yet registered.", userId);
            throw new IllegalStateException("Not registered yet.");
        }

        final List<CredentialDescriptor> allowCredentials = credentialList
                .orElse(Collections.emptyList())
                .stream()
                .map(Fido2SharedService::toCredentialDescriptor)
                .toList();

        return AssertionOptionsResponse.builder()
                .challenge(challengeResponse.getChallenge())
                .rpId(webAuthNConfig.getRpId())
                .timeout(webAuthNConfig.getTimeout().toMillis())
                .allowCredentials(allowCredentials)
                .extensions(Collections.emptyMap()).build();
    }

    /**
     * Verify credential at PowerAuth server.
     * @param credential Received public key credential.
     * @return PowerAuth authentication response.
     * @throws PowerAuthFido2Exception in case of PowerAuth server communication error.
     */
    public AssertionVerificationResponse authenticate(final VerifyAssertionRequest credential) throws PowerAuthFido2Exception {
        final byte[] credentialId = Base64.getUrlDecoder().decode(credential.id());

        final AssertionVerificationRequest request = new AssertionVerificationRequest();
        request.setCredentialId(Base64.getEncoder().encodeToString(credentialId));
        request.setType(credential.type().getValue());
        if (credential.authenticatorAttachment() != null) {
            request.setAuthenticatorAttachment(credential.authenticatorAttachment().getValue());
        }
        request.setResponse(credential.response());
        request.setApplicationId(credential.applicationId());
        request.setExpectedChallenge(credential.expectedChallenge());
        request.setRelyingPartyId(webAuthNConfig.getRpId());
        request.setAllowedOrigins(webAuthNConfig.getAllowedOrigins());
        request.setAllowedTopOrigins(webAuthNConfig.getAllowedTopOrigins());
        request.setRequiresUserVerification(credential.userVerificationRequired());

        final AssertionVerificationResponse response = fido2Client.authenticate(request);
        logger.debug("Credential assertion response of userId={}: {}", response.getUserId(), response);
        logger.info("Activation ID {} of userId={}: valid={}", response.getActivationId(), response.getUserId(), response.isAssertionValid());

        return response;
    }

    private AssertionChallengeResponse fetchChallenge(final String userId, final String applicationId, final String templateName, final Map<String, String> operationParameters) throws PowerAuthFido2Exception {
        logger.info("Getting assertion challenge for userId={}, applicationId={}, template={}, parameters={}", userId, applicationId, templateName, operationParameters);
        final AssertionChallengeRequest request = new AssertionChallengeRequest();
        if (StringUtils.hasText(userId)) {
            request.setUserId(userId);
        }
        request.setApplicationIds(List.of(applicationId));
        request.setTemplateName(templateName);
        if (operationParameters != null) {
            request.setParameters(operationParameters);
        }
        final AssertionChallengeResponse response = fido2Client.requestAssertionChallenge(request);
        logger.debug("Assertion challenge response for userId={}: {}", userId, response);
        return response;
    }

}
