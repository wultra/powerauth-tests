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

import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.wultra.security.powerauth.client.PowerAuthFido2Client;
import com.wultra.security.powerauth.client.model.entity.fido2.AllowCredentials;
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

import java.util.*;
import java.util.stream.Collectors;

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

        final AssertionChallengeResponse challengeResponse = fetchChallenge(userId, applicationId, request.templateName(), request.operationParameters());
        final var credentialList = Optional.ofNullable(challengeResponse.getAllowCredentials());
        if (credentialList.isEmpty() && StringUtils.hasText(userId))  {
            logger.info("User {} is not yet registered.", userId);
            throw new IllegalStateException("Not registered yet.");
        }

        final List<CredentialDescriptor> existingCredentials = credentialList
                .orElse(Collections.emptyList())
                .stream()
                .map(AssertionService::toCredentialDescriptor)
                .collect(Collectors.toCollection(ArrayList::new));

        final String challenge = challengeResponse.getChallenge();
        final String operationData = extractOperationData(challenge);

        // Relevant to Wultra Authenticator 1 only. If there is a credential with usb transport,
        // append a virtual credential holding operation data with usb transport.
        final boolean containsUsbTransport = existingCredentials.stream()
                .map(CredentialDescriptor::transports)
                .flatMap(Collection::stream)
                .anyMatch(AuthenticatorTransport.USB::equals);

        if (containsUsbTransport) {
            logger.debug("Appending operation data as a virtual credential.");
            existingCredentials.add(
                    new CredentialDescriptor(
                            PublicKeyCredentialType.PUBLIC_KEY,
                            Base64.getEncoder().encodeToString(operationData.getBytes()),
                            List.of(AuthenticatorTransport.USB))
            );
        }

        return AssertionOptionsResponse.builder()
                .challenge(challenge)
                .rpId(webAuthNConfig.getRpId())
                .timeout(webAuthNConfig.getTimeout().toMillis())
                .allowCredentials(existingCredentials)
                .extensions(Map.of(
                        OPERATION_DATA_EXTENSION_KEY, operationData)
                ).build();
    }

    /**
     * Verify credential at PowerAuth server.
     * @param credential Received public key credential.
     * @return PowerAuth authentication response.
     * @throws PowerAuthClientException in case of PowerAuth server communication error.
     */
    public AssertionVerificationResponse authenticate(final VerifyAssertionRequest credential) throws PowerAuthClientException {
        final AssertionVerificationRequest request = new AssertionVerificationRequest();
        request.setCredentialId(Base64.getEncoder().encodeToString(credential.id().getBytes()));
        request.setType(credential.type().getValue());
        request.setAuthenticatorAttachment(credential.authenticatorAttachment().getValue());
        request.setResponse(credential.response());
        request.setApplicationId(credential.applicationId());
        request.setExpectedChallenge(credential.expectedChallenge());
        request.setRelyingPartyId(webAuthNConfig.getRpId());
        request.setAllowedOrigins(webAuthNConfig.getAllowedOrigins());
        request.setRequiresUserVerification(credential.userVerificationRequired());

        final AssertionVerificationResponse response = fido2Client.authenticate(request);
        logger.debug("Credential assertion response of userId={}: {}", response.getUserId(), response);
        logger.info("Activation ID {} of userId={}: valid={}", response.getActivationId(), response.getUserId(), response.isAssertionValid());

        return response;
    }

    private AssertionChallengeResponse fetchChallenge(final String userId, final String applicationId, final String templateName, final Map<String, String> operationParameters) throws PowerAuthClientException {
        logger.info("Getting registration challenge for userId={}, applicationId={}, template={}, parameters={}", userId, applicationId, templateName, operationParameters);
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

    private static String extractOperationData(final String challenge) {
        final String[] split = challenge.split("&", 2);
        if (split.length != 2) {
            throw new IllegalStateException("Invalid challenge format.");
        }
        return split[1];
    }

    public static CredentialDescriptor toCredentialDescriptor(final AllowCredentials allowCredentials) {
        final String credentialId = new String(allowCredentials.getCredentialId());
        final List<AuthenticatorTransport> transports = allowCredentials.getTransports().stream()
                .map(AuthenticatorTransport::create)
                .toList();
        return new CredentialDescriptor(PublicKeyCredentialType.create(allowCredentials.getType()), credentialId, transports);
    }

}
