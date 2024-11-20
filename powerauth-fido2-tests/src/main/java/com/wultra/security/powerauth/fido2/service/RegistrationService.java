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

import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.wultra.security.powerauth.fido2.client.PowerAuthFido2Client;
import com.wultra.security.powerauth.fido2.configuration.WebAuthnConfiguration;
import com.wultra.security.powerauth.fido2.controller.request.RegisterCredentialRequest;
import com.wultra.security.powerauth.fido2.controller.request.RegistrationOptionsRequest;
import com.wultra.security.powerauth.fido2.controller.response.CredentialDescriptor;
import com.wultra.security.powerauth.fido2.controller.response.RegistrationOptionsResponse;
import com.wultra.security.powerauth.fido2.model.entity.AuthenticatorParameters;
import com.wultra.security.powerauth.fido2.model.error.PowerAuthFido2Exception;
import com.wultra.security.powerauth.fido2.model.request.RegistrationRequest;
import com.wultra.security.powerauth.fido2.model.response.RegistrationChallengeResponse;
import com.wultra.security.powerauth.fido2.model.response.RegistrationResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Base64;
import java.util.List;

/**
 * Service for WebAuthn registration tasks.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Service
@AllArgsConstructor
@Slf4j
public class RegistrationService {

    private final PowerAuthFido2Client fido2Client;
    private final WebAuthnConfiguration webAuthNConfig;

    /**
     * Build public key registration options.
     * @param request Request form with user input.
     * @return Public key registration options.
     * @throws PowerAuthFido2Exception in case of PowerAuth server communication error.
     */
    public RegistrationOptionsResponse registerOptions(final RegistrationOptionsRequest request) throws PowerAuthFido2Exception {
        final String applicationId = request.applicationId();
        final String userId = request.userId();
        final String username = StringUtils.hasText(request.username()) ? request.username() : userId;
        final String userDisplayName = StringUtils.hasText(request.userDisplayName()) ? request.userDisplayName() : userId;

        final RegistrationChallengeResponse challengeResponse = fetchChallenge(userId, applicationId);

        final List<CredentialDescriptor> excludeCredentials = challengeResponse.getExcludeCredentials().stream()
                .map(Fido2SharedService::toCredentialDescriptor)
                .toList();

        logger.info("Building registration options for userId={}, applicationId={}", userId, applicationId);
        return RegistrationOptionsResponse.builder()
                .rp(new PublicKeyCredentialRpEntity(webAuthNConfig.getRpId(), webAuthNConfig.getRpName()))
                .user(new PublicKeyCredentialUserEntity(userId.getBytes(), username, userDisplayName))
                .challenge(challengeResponse.getChallenge())
                .pubKeyCredParams(List.of(
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
                ))
                .timeout(webAuthNConfig.getTimeout().toMillis())
                .excludeCredentials(excludeCredentials)
                .build();
    }

    /**
     * Register credential at PowerAuth server.
     * @param credential Newly created public key credential
     * @return PowerAuth registration response.
     * @throws PowerAuthFido2Exception in case of PowerAuth server communication error.
     */
    public RegistrationResponse register(final RegisterCredentialRequest credential) throws PowerAuthFido2Exception {
        final String applicationId = credential.applicationId();
        final String userId = credential.userId();
        logger.info("Registering created credential of userId={}, applicationId={}", userId, applicationId);

        final RegistrationRequest request = new RegistrationRequest();
        request.setActivationName(userId);
        request.setApplicationId(applicationId);
        request.setAuthenticatorParameters(buildAuthenticatorParameters(credential));

        final RegistrationResponse response = fido2Client.register(request);
        logger.debug("Credential registration response of userId={}: {}", userId, response);
        logger.info("Activation ID {} of userId={}: status={}", response.getActivationId(), response.getUserId(), response.getActivationStatus());
        return response;
    }

    private RegistrationChallengeResponse fetchChallenge(final String userId, final String applicationId) throws PowerAuthFido2Exception {
        logger.info("Getting registration challenge for userId={}, applicationId={}", userId, applicationId);
        final RegistrationChallengeResponse response = fido2Client.requestRegistrationChallenge(userId, applicationId);
        logger.debug("Registration challenge response for userId={}: {}", userId, response);
        return response;
    }

    private AuthenticatorParameters buildAuthenticatorParameters(final RegisterCredentialRequest credential) {
        final byte[] credentialId = Base64.getUrlDecoder().decode(credential.id());

        final AuthenticatorParameters parameters = new AuthenticatorParameters();
        parameters.setCredentialId(Base64.getEncoder().encodeToString(credentialId));
        if (credential.authenticatorAttachment() != null) {
            parameters.setAuthenticatorAttachment(credential.authenticatorAttachment().getValue());
        }
        parameters.setType(credential.type().getValue());
        parameters.setResponse(credential.response());
        parameters.setAllowedOrigins(webAuthNConfig.getAllowedOrigins());
        parameters.setAllowedTopOrigins(webAuthNConfig.getAllowedTopOrigins());
        parameters.setRelyingPartyId(webAuthNConfig.getRpId());
        parameters.setRequiresUserVerification(credential.userVerificationRequired());
        return parameters;
    }

}
