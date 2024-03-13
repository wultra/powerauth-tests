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
import com.wultra.security.powerauth.client.PowerAuthFido2Client;
import com.wultra.security.powerauth.client.model.entity.fido2.AuthenticatorParameters;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.fido2.RegistrationRequest;
import com.wultra.security.powerauth.client.model.response.fido2.RegistrationChallengeResponse;
import com.wultra.security.powerauth.client.model.response.fido2.RegistrationResponse;
import com.wultra.security.powerauth.fido2.configuration.WebAuthnConfiguration;
import com.wultra.security.powerauth.fido2.controller.request.RegisterCredentialRequest;
import com.wultra.security.powerauth.fido2.controller.request.RegistrationOptionsRequest;
import com.wultra.security.powerauth.fido2.controller.response.RegistrationOptionsResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

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
    private final Fido2SharedService fido2SharedService;
    private final WebAuthnConfiguration webAuthNConfig;

    /**
     * Build public key registration options.
     * @param request Request form with user input.
     * @return Public key registration options.
     * @throws PowerAuthClientException in case of PowerAuth server communication error.
     */
    public RegistrationOptionsResponse registerOptions(final RegistrationOptionsRequest request) throws PowerAuthClientException {
        final String userId = request.username();
        final String applicationId = request.applicationId();

        final RegistrationChallengeResponse challengeResponse = fetchChallenge(userId, applicationId);

        logger.info("Building registration options for userId={}, applicationId={}", userId, applicationId);
        return RegistrationOptionsResponse.builder()
                .rp(new PublicKeyCredentialRpEntity(webAuthNConfig.getRpId(), webAuthNConfig.getRpName()))
                .user(new PublicKeyCredentialUserEntity(userId.getBytes(), userId, userId))
                .challenge(challengeResponse.getChallenge())
                .pubKeyCredParams(List.of(
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
                ))
                .timeout(webAuthNConfig.getTimeout().toMillis())
                .excludeCredentials(fido2SharedService.fetchExistingCredentials(userId, applicationId))
                .build();
    }

    /**
     * Register credential at PowerAuth server.
     * @param credential Newly created public key credential
     * @return PowerAuth registration response.
     * @throws PowerAuthClientException in case of PowerAuth server communication error.
     */
    public RegistrationResponse register(final RegisterCredentialRequest credential) throws PowerAuthClientException {
        logger.info("Registering created credential of userId={}, applicationId={}", credential.username(), credential.applicationId());

        final RegistrationRequest request = new RegistrationRequest();
        request.setActivationName(credential.username());
        request.setApplicationId(credential.applicationId());
        request.setAuthenticatorParameters(buildAuthenticatorParameters(credential));

        final RegistrationResponse response = fido2Client.register(request);
        logger.debug("Credential registration response of userId={}: {}", credential.username(), response);
        logger.info("Activation ID {} of userId={}: status={}", response.getActivationId(), response.getUserId(), response.getActivationStatus());
        return response;
    }

    private RegistrationChallengeResponse fetchChallenge(final String userId, final String applicationId) throws PowerAuthClientException {
        logger.info("Getting registration challenge for userId={}, applicationId={}", userId, applicationId);
        final RegistrationChallengeResponse response = fido2Client.requestRegistrationChallenge(userId, applicationId);
        logger.debug("Registration challenge response for userId={}: {}", userId, response);
        return response;
    }

    private AuthenticatorParameters buildAuthenticatorParameters(final RegisterCredentialRequest credential) {
        final AuthenticatorParameters parameters = new AuthenticatorParameters();
        parameters.setId(credential.id());
        parameters.setAuthenticatorAttachment(credential.authenticatorAttachment().getValue());
        parameters.setType(credential.type().getValue());
        parameters.setResponse(credential.response());
        parameters.setAllowedOrigins(webAuthNConfig.getAllowedOrigins());
        parameters.setRelyingPartyId(webAuthNConfig.getRpId());
        parameters.setRequiresUserVerification(credential.userVerificationRequired());
        return parameters;
    }

}
