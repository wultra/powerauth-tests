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
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.PowerAuthFido2Client;
import com.wultra.security.powerauth.client.model.entity.Application;
import com.wultra.security.powerauth.client.model.entity.fido2.AuthenticatorDetail;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.response.OperationTemplateDetailResponse;
import com.wultra.security.powerauth.fido2.controller.response.CredentialDescriptor;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.List;

/**
 * Service shared for registration and authentication.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Service
@AllArgsConstructor
@Slf4j
public class Fido2SharedService {

    private static final String EXTRAS_TRANSPORT_KEY = "transports";
    private static final PublicKeyCredentialType CREDENTIAL_TYPE = PublicKeyCredentialType.PUBLIC_KEY;

    private final PowerAuthFido2Client fido2Client;
    private final PowerAuthClient powerAuthClient;

    /**
     * Fetch all registered credentials.
     * @param userId User to whom the credentials belong.
     * @param applicationId Of the used application.
     * @return List of credentials.
     * @throws PowerAuthClientException if there is an error in PowerAuth communication.
     */
    public List<CredentialDescriptor> fetchExistingCredentials(final String userId, final String applicationId) throws PowerAuthClientException {
        if (!StringUtils.hasText(userId) || !StringUtils.hasText(applicationId)) {
            return Collections.emptyList();
        }

        return listAuthenticators(userId, applicationId).stream()
                .map(Fido2SharedService::toCredentialDescriptor)
                .toList();
    }

    /**
     * Fetch list of all existing applications.
     * @return List of application ids.
     * @throws PowerAuthClientException if there is an error in PowerAuth communication.
     */
    public List<String> fetchApplicationNameList() throws PowerAuthClientException {
        return powerAuthClient.getApplicationList().getApplications()
                .stream()
                .map(Application::getApplicationId)
                .sorted().toList();
    }

    /**
     * Fetch all existing operation templates.
     * @return List of operation template names.
     * @throws PowerAuthClientException if there is an error in PowerAuth communication.
     */
    public List<String> fetchTemplateNameList() throws PowerAuthClientException {
        return powerAuthClient.operationTemplateList()
                .stream()
                .map(OperationTemplateDetailResponse::getTemplateName)
                .sorted().toList();
    }

    private List<AuthenticatorDetail> listAuthenticators(final String userId, final String applicationId) throws PowerAuthClientException {
        return fido2Client.getRegisteredAuthenticatorList(userId, applicationId).getAuthenticators();
    }

    @SuppressWarnings("unchecked")
    private static CredentialDescriptor toCredentialDescriptor(final AuthenticatorDetail authenticatorDetail) {
        final String credentialId = authenticatorDetail.getCredentialId();
        final List<AuthenticatorTransport> transports = (List<AuthenticatorTransport>) authenticatorDetail.getExtras().getOrDefault(EXTRAS_TRANSPORT_KEY, Collections.emptyList());
        return new CredentialDescriptor(CREDENTIAL_TYPE, credentialId, transports);
    }

}
