/*
 * PowerAuth test and related software components
 * Copyright (C) 2022 Wultra s.r.o.
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
package com.wultra.security.powerauth.app.testserver.controller;

import com.wultra.security.powerauth.app.testserver.errorhandling.ActivationFailedException;
import com.wultra.security.powerauth.app.testserver.errorhandling.AppConfigNotFoundException;
import com.wultra.security.powerauth.app.testserver.errorhandling.GenericCryptographyException;
import com.wultra.security.powerauth.app.testserver.errorhandling.RemoteExecutionException;
import com.wultra.security.powerauth.app.testserver.model.request.CreateTokenRequest;
import com.wultra.security.powerauth.app.testserver.model.response.CreateTokenResponse;
import com.wultra.security.powerauth.app.testserver.service.CreateTokenService;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for token related services.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController
@RequestMapping("token")
public class CreateTokenController {

    private final CreateTokenService tokenService;

    /**
     * Constructor with token service.
     * @param tokenService Token service.
     */
    @Autowired
    public CreateTokenController(CreateTokenService tokenService) {
        this.tokenService = tokenService;
    }

    /**
     * Call to create a new token.
     * @param request Request for creating a new token.
     * @return Response with token ID and secret.
     * @throws GenericCryptographyException In case a crypto provider is not initialized properly.
     * @throws RemoteExecutionException In case remote communication fails.
     * @throws AppConfigNotFoundException In case app configuration is incorrect.
     * @throws ActivationFailedException In case activation is not found.
     */
    @RequestMapping(value = "token/create", method = RequestMethod.POST)
    public ObjectResponse<CreateTokenResponse> createToken(@RequestBody ObjectRequest<CreateTokenRequest> request) throws GenericCryptographyException, RemoteExecutionException, AppConfigNotFoundException, ActivationFailedException {
        final CreateTokenResponse response = tokenService.createToken(request.getRequestObject());
        return new ObjectResponse<>(response);
    }

}
