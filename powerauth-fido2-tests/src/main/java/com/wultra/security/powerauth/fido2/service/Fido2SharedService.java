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
import com.wultra.security.powerauth.client.model.entity.Application;
import com.wultra.security.powerauth.client.model.entity.fido2.Credential;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.response.OperationTemplateDetailResponse;
import com.wultra.security.powerauth.fido2.controller.response.CredentialDescriptor;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

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

    private final PowerAuthClient powerAuthClient;

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

    /**
     * Map Credential from PowerAuth Server to WebAuthN Credential Descriptor.
     * @param credential To be mapped to Credential Descriptor.
     * @return Credential Descriptor.
     */
    public static CredentialDescriptor toCredentialDescriptor(final Credential credential) {
        final List<AuthenticatorTransport> transports = credential.getTransports().stream()
                .map(AuthenticatorTransport::create)
                .toList();
        return new CredentialDescriptor(PublicKeyCredentialType.create(credential.getType()), credential.getCredentialId(), transports);
    }

}
